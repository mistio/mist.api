import re
import uuid
import time
import logging
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


def get_stats(owner, cloud_id, machine_id, start='', stop='', step='',
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
        - owner: either an Organization mongoengine object or a UUID
        - cloud_id: the id of the Cloud, whose machines' stats will be fetched
        - machine_id: the id of the Machine to fetch stats for
        - start: the time since when to query for stats, eg. 10s, 2m, etc
        - stop: the time until which to query for stats
        - step: the step at which to return stats
        - metrics: the metrics to query for, if explicitly specified
        - callback: the method to be invoked in order to return data
        - tornado_async: denotes whether to issue a Tornado-safe HTTP request

    """
    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=owner, deleted=None)
        machine = Machine.objects.get(id=machine_id, cloud=cloud)
    except me.DoesNotExist:
        raise NotFoundError('Machine does not exist')
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError('Machine does not have monitoring enabled')
    if not metrics:
        metrics = config.BUILTIN_METRICS.keys() + machine.monitoring.metrics
    if not isinstance(metrics, list):
        metrics = [metrics]

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

    def _get_metrics_as_dict(owner):
        return {
            metric.metric_id: {
                'name': metric.name, 'unit': metric.unit
            } for metric in Metric.objects(owner=owner)
        }

    custom_metrics = _get_metrics_as_dict(owner)
    for metric in custom_metrics.values():
        metric['machines'] = []

    monitored_machines = []
    monitored_machines_2 = {}

    clouds = Cloud.objects(owner=owner, deleted=None)
    machines = Machine.objects(cloud__in=clouds,
                               monitoring__hasmonitoring=True)

    for machine in machines:
        monitored_machines.append([machine.cloud.id, machine.machine_id])
        monitored_machines_2[machine.id] = {
            'cloud_id': machine.cloud.id,
            'machine_id': machine.machine_id,
            'installation_status':
                machine.monitoring.installation_status.as_dict(),
            'commands': machine.monitoring.get_commands(),
        }
        for metric_id in machine.monitoring.metrics:
            if metric_id in custom_metrics:
                machines = custom_metrics[metric_id]['machines']
                machines.append((machine.cloud.id, machine.machine_id))

    ret = {
        'current_plan': {},
        'machines': monitored_machines,
        'monitored_machines': monitored_machines_2,
        'rules': {},
        'alerts_email': owner.alerts_email,
        'custom_metrics': custom_metrics,
        'builtin_metrics': config.BUILTIN_METRICS,
    }
    for key in ('builtin_metrics', 'custom_metrics'):
        for id in ret[key]:
            ret[key][id]['id'] = id
    return ret


# FIXME: Method arguments are left unchanged for backwards compatibility.
def enable_monitoring(owner, cloud_id, machine_id, name='', dns_name='',
                      public_ips=None, private_ips=None, no_ssh=False,
                      dry=False, job_id='', plugins=None, deploy_async=True):
    """Enable monitoring for a machine.

    If `no_ssh` is False, then the monitoring agent will be deployed over SSH.
    Otherwise, the installation command will be returned to the User in order
    to be ran manually.

    """
    try:
        machine = Machine.objects.get(machine_id=machine_id, cloud=cloud_id)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)
    if machine.owner != owner:  # Cloud's Owner.
        raise NotFoundError("Machine %s doesn't exist" % machine_id)
    if machine.monitoring.hasmonitoring:
        msg = 'Monitoring is already enabled for Machine %s of Cloud %s'
    else:
        msg = 'Enabling monitoring for Machine %s of Cloud %s'
    log.warning(msg, machine.id, cloud_id)

    ret = {
        'extra_vars': {
            'uuid': machine.id,
            'monitor': config.INFLUX['host'],
        },
    }
    commands = machine.monitoring.get_commands()
    ret['command'] = commands['unix']
    ret['unix_command'] = commands['unix']  # FIXME For backwards compatibility

    if not dry:
        # Reset Machines's InstallationStatus field.
        machine.monitoring.installation_status = InstallationStatus()
        machine.monitoring.installation_status.started_at = time.time()
        machine.monitoring.installation_status.state = 'preparing'
        machine.monitoring.installation_status.manual = no_ssh
        machine.monitoring.hasmonitoring = True
        if no_ssh:
            machine.monitoring.installation_status.state = 'installing'
        else:
            machine.monitoring.installation_status.state = 'pending'
        machine.save()

        trigger_session_update(owner, ['monitoring'])

        traefik.reset_config()

        # Install Telegraf.
        if not no_ssh:
            if job_id:
                job = None
            else:
                job_id = uuid.uuid4().hex
                job = 'enable_monitoring'
            ret['job'] = job

            func = mist.api.monitoring.tasks.install_telegraf
            if deploy_async:
                func = func.delay
            func(owner.id, machine.cloud.id, machine.machine_id, job, job_id)

        if job_id:
            ret['job_id'] = job_id

    return ret


# TODO: Switch to mongo's UUID.
def disable_monitoring(owner, cloud_id, machine_id, no_ssh=False, job_id=''):
    """Disable monitoring for a machine.

    If `no_ssh` is False, we will attempt to SSH to the Machine and uninstall
    the monitoring agent.

    """
    try:
        machine = Machine.objects.get(machine_id=machine_id, cloud=cloud_id)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)
    if machine.owner != owner:  # Cloud's Owner.
        raise NotFoundError("Machine %s doesn't exist" % machine_id)
    if not machine.monitoring.hasmonitoring:
        raise BadRequestError('Machine does not have monitoring enabled')

    log.info('Disabling monitoring for Owner %s, Machine %s of Cloud %s',
             owner.id, machine_id, cloud_id)

    # Schedule undeployment of Telegraf.
    ret = {}
    if not no_ssh:
        if job_id:
            job = None
        else:
            job = 'disable_monitoring'
            job_id = uuid.uuid4().hex
        ret['job'] = job

        mist.api.monitoring.tasks.uninstall_telegraf.delay(
            owner.id, machine.cloud.id, machine.machine_id, job, job_id)

    if job_id:
        ret['job_id'] = job_id

    # Update monitoring information.
    machine.monitoring.hasmonitoring = False
    machine.save()

    traefik.reset_config()

    trigger_session_update(owner, ['monitoring'])
    return ret


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
