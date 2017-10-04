import re
import uuid
import time
import logging

import requests
import mongoengine as me

import mist.api.config as config
import mist.api.monitoring.tasks

from mist.api.helpers import trigger_session_update

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import MethodNotAllowedError

from mist.api.users.models import Metric
from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.machines.models import InstallationStatus

from mist.api.monitoring.helpers import show_fields
from mist.api.monitoring.helpers import show_measurements

from mist.api.monitoring.handlers import HANDLERS
from mist.api.monitoring.handlers import MainStatsHandler
from mist.api.monitoring.handlers import MultiLoadHandler
from mist.api.monitoring import traefik


log = logging.getLogger(__name__)


def get_stats(machine, start='', stop='', step='',
              metrics=None, callback=None, tornado_async=False):
    """Get all monitoring data for the specified machine.

    If a list of `metrics` is provided, each metric needs to comply with the
    following template:

        <measurement>.<tags>.<column>

    where <tags> (optional) must be in "key=value" format and delimited by ".".

    Regular expressions may also be specified, but they need to be inside `/`,
    as defined by InfluxQL. The usage of "." should be avoided when using
    regular expressions, since dots are also used to delimit the metrics' path.

    Arguments:
        - machine: Machine model instance to get stats for
        - start: the time since when to query for stats, eg. 10s, 2m, etc
        - stop: the time until which to query for stats
        - step: the step at which to return stats
        - metrics: the metrics to query for, if explicitly specified
        - callback: the method to be invoked in order to return data
        - tornado_async: denotes whether to issue a Tornado-safe HTTP request

    """
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError('Machine does not have monitoring enabled')
    if metrics is None:
        metrics = []
    elif not isinstance(metrics, list):
        metrics = [metrics]

    if machine.monitoring.system == 'collectd-graphite':
        if not config.HAS_CORE:
            raise Exception()
        from mist.core.methods import _graphite_get_stats
        return _graphite_get_stats(
            machine, start=start, stop=stop, step=step, metrics=metrics,
            callback=callback, tornado_async=tornado_async,
        )
    elif machine.monitoring.system == 'telegraf-influxdb':
        if not metrics:
            metrics = (config.INFLUXDB_BUILTIN_METRICS.keys() +
                       machine.monitoring.metrics)

        # NOTE: For backwards compatibility.
        # Transform "min" and "sec" to "m" and "s", respectively.
        start, stop, step = map(
            lambda x: re.sub('in|ec', repl='', string=x),
            (start.strip('-'), stop.strip('-'), step)
        )

        # Fetch series.
        results = {}
        for metric in metrics:
            path = metric.split('.')
            measurement = path[0]
            if len(path) is 1:
                metric += '.*'
            if not measurement or measurement == '*':
                raise BadRequestError('No measurement specified')
            handler = HANDLERS.get(measurement, MainStatsHandler)(machine)
            data = handler.get_stats(metric=metric, start=start, stop=stop,
                                     step=step, callback=callback,
                                     tornado_async=tornado_async)
            if data:
                results.update(data)
        return results
    else:
        raise Exception("Invalid monitoring system")


def get_load(owner, start='', stop='', step='', uuids=None,
             tornado_callback=None, tornado_async=True):
    """Get shortterm load for all monitored machines."""
    if not uuids:
        clouds = Cloud.objects(owner=owner, deleted=None).only('id')
        uuids = [m.id for m in
                 Machine.objects(cloud__in=clouds,
                                 monitoring__hasmonitoring=True).only('id')]
    if not uuids:
        raise NotFoundError('No machine has monitoring enabled')

    # Transform "min" and "sec" to "m" and "s", respectively.
    start, stop, step = map(
        lambda x: re.sub('in|ec', repl='', string=x),
        (start.strip('-'), stop.strip('-'), step)
    )

    # Get load stats.
    return MultiLoadHandler(uuids).get_stats(metric='system.load1',
                                             start=start, stop=stop, step=step,
                                             callback=tornado_callback,
                                             tornado_async=tornado_async)


def check_monitoring(owner):
    """Return the monitored machines, enabled metrics, and user details."""

    custom_metrics = owner.get_metrics_dict()
    for metric in custom_metrics.values():
        metric['machines'] = []

    monitored_machines = []
    monitored_machines_2 = {}

    clouds = Cloud.objects(owner=owner, deleted=None)
    machines = Machine.objects(cloud__in=clouds,
                               monitoring__hasmonitoring=True)

    for machine in machines:
        monitored_machines.append([machine.cloud.id, machine.machine_id])
        try:
            commands = machine.monitoring.get_commands()
        except Exception as exc:
            log.error(exc)
            commands = {}
        monitored_machines_2[machine.id] = {
            'cloud_id': machine.cloud.id,
            'machine_id': machine.machine_id,
            'installation_status':
                machine.monitoring.installation_status.as_dict(),
            'commands': commands,
        }
        for metric_id in machine.monitoring.metrics:
            if metric_id in custom_metrics:
                machines = custom_metrics[metric_id]['machines']
                machines.append((machine.cloud.id, machine.machine_id))

    if config.HAS_CORE:
        from mist.core.helpers import curr_plan_as_dict
    else:
        def curr_plan_as_dict(owner):
            return {}

    ret = {
        'current_plan': curr_plan_as_dict(owner),
        'machines': monitored_machines,
        'monitored_machines': monitored_machines_2,
        'rules': owner.get_rules_dict(),
        'alerts_email': owner.alerts_email,
        'custom_metrics': custom_metrics,
        # TODO
        # FIXME
        'builtin_metrics': config.INFLUXDB_BUILTIN_METRICS,
    }
    for key in ('rules', 'builtin_metrics', 'custom_metrics'):
        for id in ret[key]:
            ret[key][id]['id'] = id
    return ret


# FIXME: Method arguments are left unchanged for backwards compatibility.
def enable_monitoring(owner, cloud_id, machine_id,
                      no_ssh=False,
                      dry=False, job_id='', deploy_async=True, plugins=None):
    """Enable monitoring for a machine.

    If `no_ssh` is False, then the monitoring agent will be deployed over SSH.
    Otherwise, the installation command will be returned to the User in order
    to be ran manually.

    """
    log.info("%s: Enabling monitoring for machine '%s' in cloud '%s'.",
             owner.id, machine_id, cloud_id)

    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')
    try:
        machine = Machine.objects.get(cloud=cloud, machine_id=machine_id)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)
    if machine.monitoring.hasmonitoring:
        log.warning("%s: Monitoring is already enabled for "
                    "machine '%s' in cloud '%s'.",
                    owner.id, machine_id, cloud_id)

    # Extra vars
    machine.monitoring.system = config.DEFAULT_MONITORING_METHOD
    if config.DEFAULT_MONITORING_METHOD == 'collectd-graphite':
        if not config.HAS_CORE:
            raise Exception()
        from mist.core.methods import _enable_monitoring_prepare
        extra_vars = _enable_monitoring_prepare(machine)
    elif config.DEFAULT_MONITORING_METHOD == 'telegraf-influxdb':
        extra_vars = {'uuid': machine.id, 'monitor': config.INFLUX['host']}
    else:
        raise Exception("Invalid DEFAULT_MONITORING_METHOD")

    # Ret dict
    ret_dict = {'extra_vars': extra_vars}
    for os_type, cmd in machine.monitoring.get_commands().items():
        ret_dict['%s_command' % os_type] = cmd
    # for backwards compatibility
    ret_dict['command'] = ret_dict['unix_command']

    # Dry run, so return!
    if dry:
        return ret_dict

    # Reset Machines's InstallationStatus field.
    machine.monitoring.installation_status = InstallationStatus()
    machine.monitoring.installation_status.started_at = time.time()
    machine.monitoring.installation_status.state = 'preparing'
    machine.monitoring.installation_status.manual = no_ssh
    machine.monitoring.hasmonitoring = True
    machine.monitoring.system = config.DEFAULT_MONITORING_METHOD

    machine.save()
    trigger_session_update(owner, ['monitoring'])

    # Attempt to contact monitor server and enable monitoring for the machine
    try:
        if config.DEFAULT_MONITORING_METHOD == 'collectd-graphite':
            if not config.HAS_CORE:
                raise Exception()
            from mist.core.methods import _enable_monitoring_monitor
            _enable_monitoring_monitor(owner, cloud_id, machine_id)
        elif config.DEFAULT_MONITORING_METHOD == 'telegraf-influxdb':
            traefik.reset_config()
    except Exception as exc:
        machine.monitoring.installation_status.state = 'failed'
        machine.monitoring.installation_status.error_msg = repr(exc)
        machine.monitoring.installation_status.finished_at = time.time()
        machine.monitoring.hasmonitoring = False
        machine.save()
        trigger_session_update(owner, ['monitoring'])
        raise

    # Update installation status
    if no_ssh:
        machine.monitoring.installation_status.state = 'installing'
    else:
        machine.monitoring.installation_status.state = 'pending'
    machine.save()
    trigger_session_update(owner, ['monitoring'])

    if not no_ssh:
        if job_id:
            job = None
        else:
            job_id = uuid.uuid4().hex
            job = 'enable_monitoring'
        ret_dict['job'] = job
        if config.DEFAULT_MONITORING_METHOD == 'collectd-graphite':
            # Install collectd to the machine
            func = mist.api.tasks.deploy_collectd
            if deploy_async:
                func = func.delay
            func(
                owner.id, machine.cloud.id, machine.machine_id, extra_vars,
                job_id=job_id, job=job, plugins=plugins,
            )
        elif config.DEFAULT_MONITORING_METHOD == 'telegraf-influxdb':
            # Install Telegraf
            func = mist.api.monitoring.tasks.install_telegraf
            if deploy_async:
                func = func.delay
            func(owner.id, machine.cloud.id, machine.machine_id, job, job_id)

    if job_id:
        ret_dict['job_id'] = job_id

    return ret_dict


# TODO: Switch to mongo's UUID.
def disable_monitoring(owner, cloud_id, machine_id, no_ssh=False, job_id=''):
    """Disable monitoring for a machine.

    If `no_ssh` is False, we will attempt to SSH to the Machine and uninstall
    the monitoring agent.

    """
    log.info("%s: Disabling monitoring for machine '%s' in cloud '%s'.",
             owner.id, machine_id, cloud_id)

    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')
    try:
        machine = Machine.objects.get(cloud=cloud, machine_id=machine_id)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)
    if machine.monitoring.hasmonitoring:
        raise BadRequestError('Machine does not have monitoring enabled')

    # Uninstall monitoring agent.
    ret_dict = {}
    if not no_ssh:
        if job_id:
            job = None
        else:
            job = 'disable_monitoring'
            job_id = uuid.uuid4().hex
        ret_dict['job'] = job

        if machine.monitoring.system == 'collectd-graphite':
            if not config.HAS_CORE:
                raise Exception
            from mist.core.tasks import undeploy_collectd
            undeploy_collectd.delay(owner.id, cloud_id, machine_id,
                                    job_id=job_id, job=job)
        elif machine.monitoring.system == 'telegraf-influxdb':
            # Schedule undeployment of Telegraf.
            mist.api.monitoring.tasks.uninstall_telegraf.delay(
                owner.id, machine.cloud.id, machine.machine_id, job, job_id)

    if job_id:
        ret_dict['job_id'] = job_id

    # tell monitor server to no longer monitor this uuid
    try:
        if machine.monitoring.system == 'collectd-graphite':
            if not config.HAS_CORE:
                raise Exception
            url = "%s/machines/%s" % (config.MONITOR_URI, machine.id)
            ret = requests.delete(url)
            if ret.status_code == 404:
                log.warning("Monitor server couldn't find uuid, continuing..")
            elif ret.status_code != 200:
                log.error("disable_monitoring: "
                          "Monitor server bad response %d:%s",
                          ret.status_code, ret.text)
            else:
                log.debug("Monitor server good response in disable_monitoring")
        elif machine.monitoring.system == 'telegraf-influxdb':
            traefik.reset_config()
    except Exception as exc:
        log.error("Exception %s while asking monitor server in "
                  "disable_monitoring", exc)

    # Update monitoring information.
    # since we successfully disabled in monitor server, update local database
    # delete rules
    for rule_id, rule in owner.rules.items():
        if rule.cloud == cloud_id and rule.machine == machine_id:
            owner.rules[rule_id].delete()
            del owner.rules[rule_id]
    owner.save()
    machine.monitoring.hasmonitoring = False
    machine.save()

    trigger_session_update(owner, ['monitoring'])
    return ret_dict


def disable_monitoring_cloud(owner, cloud_id, no_ssh=False):
    """Disable monitoring for all machines of the specified Cloud."""
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        machines = Machine.objects(
            cloud=cloud, monitoring__hasmonitoring=True).only('machine_id')
    except me.DoesNotExist:
        raise NotFoundError("Cloud doesn't exist")
    for machine in machines:
        try:
            disable_monitoring(owner, cloud_id, machine.machine_id,
                               no_ssh=no_ssh)
        except Exception as exc:
            log.error("Error while disabling monitoring for all machines of "
                      "Cloud %s (%s): %s", cloud.id, owner.id, exc)


def find_metrics(owner, machine_uuid):
    """Return the metrics associated with the specified machine."""
    try:
        machine = Machine.objects.get(id=machine_uuid)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine doesn't exist")
    if machine.owner != owner:
        raise NotFoundError("Machine doesn't exist")
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")
    metrics = {}
    for metric in show_fields(show_measurements(machine_uuid)):
        metrics[metric['id']] = metric
    return metrics


def associate_metric(owner, machine_uuid, metric_id, name='', unit=''):
    """Associate a new metric to a machine."""
    try:
        machine = Machine.objects.get(id=machine_uuid)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine doesn't exist")
    if machine.owner != owner:
        raise NotFoundError("Machine doesn't exist")
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")
    metric = update_metric(owner, metric_id, name, unit)
    if metric_id not in machine.monitoring.metrics:
        machine.monitoring.metrics.append(metric_id)
        machine.save()
    return metric


def disassociate_metric(owner, machine_uuid, metric_id):
    """Disassociate a metric from a machine."""
    try:
        machine = Machine.objects.get(id=machine_uuid)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine doesn't exist")
    if machine.owner != owner:
        raise NotFoundError("Machine doesn't exist")
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")
    try:
        Metric.objects.get(owner=owner, metric_id=metric_id)
    except Metric.DoesNotExist:
        raise NotFoundError("Invalid metric_id")
    if metric_id not in machine.monitoring.metrics:
        raise NotFoundError("Metric isn't associated with this Machine")
    machine.monitoring.metrics.remove(metric_id)
    machine.save()
    trigger_session_update(owner, ['monitoring'])


def update_metric(owner, metric_id, name='', unit=''):
    """Update an existing metric."""
    try:
        metric = Metric.objects.get(owner=owner, metric_id=metric_id)
    except Metric.DoesNotExist:
        metric = Metric(owner=owner, metric_id=metric_id)
    if name:
        metric.name = name
    if unit:
        metric.unit = unit
    metric.save()
    trigger_session_update(owner, ['monitoring'])
    return metric
