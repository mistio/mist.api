import os
import re
import uuid
import time
import datetime
import logging

import mongoengine as me

import mist.api.shell
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

from mist.api.monitoring.influxdb.helpers import show_fields
from mist.api.monitoring.influxdb.helpers import show_measurements
from mist.api.monitoring.influxdb.handlers import HANDLERS as INFLUXDB_HANDLERS
from mist.api.monitoring.influxdb.handlers \
    import MainStatsHandler as InfluxMainStatsHandler
from mist.api.monitoring.influxdb.handlers \
    import MultiLoadHandler as InfluxMultiLoadHandler

from mist.api.monitoring.graphite.methods \
    import get_stats as graphite_get_stats
from mist.api.monitoring.graphite.methods \
    import get_load as graphite_get_load

from mist.api.monitoring import traefik

from mist.api.rules.models import Rule

log = logging.getLogger(__name__)


def get_stats(machine, start='', stop='', step='', metrics=None):
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

    """
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError('Machine does not have monitoring enabled')
    if metrics is None:
        metrics = []
    elif not isinstance(metrics, list):
        metrics = [metrics]

    if machine.monitoring.method in ('telegraf-graphite'):
        if not config.HAS_CORE:
            raise Exception()
        return graphite_get_stats(
            machine, start=start, stop=stop, step=step, metrics=metrics,
        )
    elif machine.monitoring.method == 'telegraf-influxdb':
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
            regex = r'^(?:\w+)\((.+)\)$'
            match = re.match(regex, metric)
            if not match:
                groups = (metric, )
            while match:
                groups = match.groups()
                match = re.match(regex, groups[0])
            measurement, _ = groups[0].split('.', 1)
            handler = INFLUXDB_HANDLERS.get(
                measurement, InfluxMainStatsHandler
            )(machine)
            data = handler.get_stats(metric=metric, start=start, stop=stop,
                                     step=step)
            if data:
                results.update(data)
        return results
    else:
        raise Exception("Invalid monitoring method")


def get_load(owner, start='', stop='', step='', uuids=None):
    """Get shortterm load for all monitored machines."""
    clouds = Cloud.objects(owner=owner, deleted=None).only('id')
    machines = Machine.objects(cloud__in=clouds,
                               monitoring__hasmonitoring=True)
    if uuids:
        machines.filter(id__in=uuids)

    graphite_uuids = [machine.id for machine in machines
                      if machine.monitoring.method.endswith('-graphite')]
    influx_uuids = [machine.id for machine in machines
                    if machine.monitoring.method.endswith('-influxdb')]

    graphite_data = {}
    influx_data = {}
    if graphite_uuids:
        graphite_data = graphite_get_load(owner, start=start, stop=stop,
                                          step=step, uuids=graphite_uuids)
    if influx_uuids:
        # Transform "min" and "sec" to "m" and "s", respectively.
        _start, _stop, _step = map(
            lambda x: re.sub('in|ec', repl='', string=x),
            (start.strip('-'), stop.strip('-'), step)
        )
        influx_data = InfluxMultiLoadHandler(influx_uuids).get_stats(
            metric='system.load1',
            start=_start, stop=_stop, step=_step,
        )

    if graphite_data or influx_data:
        return dict(graphite_data.items() + influx_data.items())
    else:
        raise NotFoundError('No machine has monitoring enabled')


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

    if config.HAS_BILLING:
        from mist.billing.methods import curr_plan_as_dict
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
    }
    if config.HAS_CORE:
        ret.update({
            # Keep for backwards compatibility
            'builtin_metrics': config.GRAPHITE_BUILTIN_METRICS,
            'builtin_metrics_graphite': config.GRAPHITE_BUILTIN_METRICS,
            'builtin_metrics_influxdb': config.INFLUXDB_BUILTIN_METRICS,
        })
    else:
        ret.update({
            # Keep for backwards compatibility
            'builtin_metrics': config.INFLUXDB_BUILTIN_METRICS,
            'builtin_metrics_influxdb': config.INFLUXDB_BUILTIN_METRICS,
        })
    for key in ('rules', 'builtin_metrics', 'custom_metrics'):
        for id in ret[key]:
            ret[key][id]['id'] = id
    return ret


def update_monitoring_options(owner, emails):
    """Set `emails` as global e-mail alert's recipients."""
    from mist.api.helpers import is_email_valid
    # FIXME Send e-mails as a list, instead of string?
    emails = emails.replace(' ', '')
    emails = emails.replace('\n', ',')
    emails = emails.replace('\r', ',')
    owner.alerts_email = [
        email for email in emails.split(',') if is_email_valid(email)
    ]
    owner.save()
    trigger_session_update(owner, ['monitoring'])
    return {'alerts_email': owner.alerts_email}


def enable_monitoring(owner, cloud_id, machine_id, no_ssh=False, dry=False,
                      job_id='', deploy_async=True, plugins=None):
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

    old_monitoring_method = machine.monitoring.method
    # Decide on monitoring method
    machine.monitoring.method = (
        machine.cloud.default_monitoring_method or
        machine.cloud.owner.default_monitoring_method or
        config.DEFAULT_MONITORING_METHOD
    )
    assert machine.monitoring.method in config.MONITORING_METHODS
    assert machine.monitoring.method != 'collectd-graphite' or config.HAS_CORE

    if old_monitoring_method != machine.monitoring.method:
        machine.monitoring.method_since = datetime.datetime.now()
    # Extra vars
    if machine.monitoring.method in ('telegraf-influxdb',
                                     'telegraf-graphite'):
        extra_vars = {'uuid': machine.id, 'monitor': config.INFLUX['host']}
    else:
        raise Exception("Invalid monitoring method")

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

    machine.save()
    trigger_session_update(owner, ['monitoring'])

    # Attempt to contact monitor server and enable monitoring for the machine
    try:
        if machine.monitoring.method in ('telegraf-influxdb',
                                         'telegraf-graphite'):
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
        if machine.monitoring.method in ('telegraf-influxdb',
                                         'telegraf-graphite'):
            # Install Telegraf
            func = mist.api.monitoring.tasks.install_telegraf
            if deploy_async:
                func = func.delay
            func(machine.id, job, job_id, plugins)
        else:
            raise Exception("Invalid monitoring method")

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
    if not machine.monitoring.hasmonitoring:
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

        if machine.monitoring.method in ('telegraf-influxdb',
                                         'telegraf-graphite'):
            # Schedule undeployment of Telegraf.
            mist.api.monitoring.tasks.uninstall_telegraf.delay(machine.id,
                                                               job, job_id)
    if job_id:
        ret_dict['job_id'] = job_id

    # Update monitoring information in db: set monitoring to off, remove rules.
    # If the machine we are trying to disable monitoring for is the only one
    # included in a rule, then delete the rule. Otherwise, attempt to remove
    # the machine from the list of resources the rule is referring to.
    for rule in Rule.objects(owner_id=machine.owner.id):
        if rule.ctl.includes_only(machine):
            rule.delete()
        else:
            rule.ctl.maybe_remove(machine)

    machine.monitoring.hasmonitoring = False
    machine.monitoring.activated_at = 0
    machine.save()

    # tell monitor server to no longer monitor this uuid
    try:
        if machine.monitoring.method in ('telegraf-influxdb',
                                         'telegraf-graphite'):
            traefik.reset_config()
    except Exception as exc:
        log.error("Exception %s while asking monitor server in "
                  "disable_monitoring", exc)

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


def find_metrics(machine):
    """Return the metrics associated with the specified machine."""
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")

    if machine.monitoring.method in ('telegraf-graphite'):
        if not config.HAS_CORE:
            raise Exception()
        from mist.core.methods import _graphite_find_metrics
        return _graphite_find_metrics(machine)
    elif machine.monitoring.method == 'telegraf-influxdb':
        metrics = {}
        for metric in show_fields(show_measurements(machine.id)):
            metrics[metric['id']] = metric
        return metrics
    else:
        raise Exception("Invalid monitoring method")


def associate_metric(machine, metric_id, name='', unit=''):
    """Associate a new metric to a machine."""
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")
    metric = update_metric(machine.owner, metric_id, name, unit)
    if metric_id not in machine.monitoring.metrics:
        machine.monitoring.metrics.append(metric_id)
        machine.save()
    trigger_session_update(machine.owner, ['monitoring'])
    return metric


def disassociate_metric(machine, metric_id):
    """Disassociate a metric from a machine."""
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")
    try:
        Metric.objects.get(owner=machine.owner, metric_id=metric_id)
    except Metric.DoesNotExist:
        raise NotFoundError("Invalid metric_id")
    if metric_id not in machine.monitoring.metrics:
        raise NotFoundError("Metric isn't associated with this Machine")
    machine.monitoring.metrics.remove(metric_id)
    machine.save()
    trigger_session_update(machine.owner, ['monitoring'])


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


# FIXME The `plugin_id` is the name of the plugin/script as it exists in the
# monitoring agent's configuration, and not an ID stored in our database to
# which we can easily refer.
def undeploy_python_plugin(machine, plugin_id):
    """Undeploy a custom plugin from a machine."""
    # Just remove the executable.
    plugin = os.path.join('/opt/mistio/mist-telegraf/custom', plugin_id)
    script = '$(command -v sudo) rm %s' % plugin

    # Run the command over SSH.
    shell = mist.api.shell.Shell(machine.ctl.get_host())
    key_id, ssh_user = shell.autoconfigure(machine.owner, machine.cloud.id,
                                           machine.machine_id)
    retval, stdout = shell.command(script)
    shell.disconnect()

    if retval:
        log.error('Error undeploying custom plugin: %s', stdout)

    # TODO Shouldn't we also `disassociate_metric` and remove relevant Rules?

    return {'metric_id': None, 'stdout': stdout}
