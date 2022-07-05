import os
import re
import uuid
import time
import datetime
import logging
import asyncio

import mongoengine as me

import mist.api.shell
import mist.api.config as config
import mist.api.monitoring.tasks

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import MethodNotAllowedError

from mist.api.users.models import Metric
from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.machines.models import InstallationStatus

from mist.api.methods import list_resources

from mist.api.monitoring.influxdb.helpers import show_fields
from mist.api.monitoring.influxdb.helpers import show_measurements
from mist.api.monitoring.influxdb.handlers import HANDLERS as INFLUXDB_HANDLERS
from mist.api.monitoring.influxdb.handlers \
    import MainStatsHandler as InfluxMainStatsHandler
from mist.api.monitoring.influxdb.handlers \
    import MultiLoadHandler as InfluxMultiLoadHandler
from mist.api.monitoring.influxdb.handlers \
    import MultiCoresHandler as InfluxMultiCoresHandler

from mist.api.monitoring.graphite.methods \
    import get_stats as graphite_get_stats
from mist.api.monitoring.graphite.methods \
    import find_metrics as graphite_find_metrics
from mist.api.monitoring.graphite.methods \
    import get_load as graphite_get_load
from mist.api.monitoring.graphite.methods \
    import get_cores as graphite_get_cores

from mist.api.monitoring.foundationdb.methods import get_stats as fdb_get_stats
from mist.api.monitoring.foundationdb.methods import get_load as fdb_get_load
from mist.api.monitoring.foundationdb.methods import get_cores as fdb_get_cores
from mist.api.monitoring.foundationdb.methods \
    import find_metrics as fdb_find_metrics

from mist.api.monitoring.victoriametrics.methods \
    import get_stats as victoria_get_stats
from mist.api.monitoring.victoriametrics.methods \
    import get_load as victoria_get_load
from mist.api.monitoring.victoriametrics.methods \
    import get_cores as victoria_get_cores
from mist.api.monitoring.victoriametrics.methods \
    import find_metrics as victoria_find_metrics

from mist.api.monitoring import traefik

from mist.api.notifications.models import NoDataRuleTracker

from mist.api.rules.models import MachineMetricRule
from mist.api.rules.models import NoDataRule

from mist.api.helpers import trigger_session_update, amqp_publish_user


log = logging.getLogger(__name__)


def get_stats(
    machine, start="", stop="", step="",
        metrics=None, monitoring_method=None, metering=True):
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
        - monitoring_method: override default monitoring method

    """
    if not monitoring_method:
        monitoring_method = machine.monitoring.method

    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine does not have monitoring enabled")
    if metrics is None:
        metrics = []
    elif not isinstance(metrics, list):
        metrics = [metrics]

    if monitoring_method in ("telegraf-graphite"):
        return graphite_get_stats(
            machine, start=start, stop=stop, step=step, metrics=metrics,
        )
    elif monitoring_method == "telegraf-influxdb":
        if not metrics:
            metrics = (
                list(config.INFLUXDB_BUILTIN_METRICS.keys()) +
                machine.monitoring.metrics
            )

        # NOTE: For backwards compatibility.
        # Transform "min" and "sec" to "m" and "s", respectively.
        start, stop, step = [
            re.sub("in|ec", repl="", string=x)
            for x in (start.strip("-"), stop.strip("-"), step)
        ]

        # Fetch series.
        results = {}
        for metric in metrics:
            regex = r"^(?:\w+)\((.+)\)$"
            match = re.match(regex, metric)
            if not match:
                groups = (metric,)
            while match:
                groups = match.groups()
                match = re.match(regex, groups[0])
            measurement, _ = groups[0].split(".", 1)
            handler = INFLUXDB_HANDLERS.get(
                measurement, InfluxMainStatsHandler
            )(machine)
            data = handler.get_stats(
                metric=metric, start=start, stop=stop, step=step
            )
            if data:
                results.update(data)
        return results

    # return time-series data from foundationdb
    elif monitoring_method == "telegraf-tsfdb":
        return fdb_get_stats(
            machine,
            start,
            stop,
            step,
            metrics
        )

    elif monitoring_method == "telegraf-victoriametrics":
        return victoria_get_stats(
            machine,
            start,
            stop,
            step,
            metrics,
            metering
        )

    else:
        raise Exception("Invalid monitoring method")


def get_load(owner, start="", stop="", step="", uuids=None):
    """Get shortterm load for all monitored machines."""
    clouds = Cloud.objects(owner=owner, deleted=None).only("id")
    if uuids:
        machines = Machine.objects(
            owner=owner, cloud__in=clouds, id__in=uuids,
            monitoring__hasmonitoring=True
        )
    else:
        machines = Machine.objects(
            owner=owner, cloud__in=clouds, monitoring__hasmonitoring=True
        )

    graphite_uuids = [
        machine.id
        for machine in machines
        if machine.monitoring.method.endswith("-graphite")
    ]
    influx_uuids = [
        machine.id
        for machine in machines
        if machine.monitoring.method.endswith("-influxdb")
    ]
    fdb_uuids = [
        machine.id
        for machine in machines
        if machine.monitoring.method.endswith("-tsfdb")
    ]
    victoria_uuids = [
        machine.id
        for machine in machines
        if machine.monitoring.method.endswith("-victoriametrics")
    ]

    graphite_data = {}
    influx_data = {}
    fdb_data = {}
    victoria_data = {}

    if graphite_uuids:
        graphite_data = graphite_get_load(
            owner, start=start, stop=stop, step=step, uuids=graphite_uuids
        )
    if influx_uuids:

        # Transform "min" and "sec" to "m" and "s", respectively.
        _start, _stop, _step = [
            re.sub("in|ec", repl="", string=x)
            for x in (start.strip("-"), stop.strip("-"), step)
        ]
        metric = "system.load1"
        if step:
            metric = "MEAN(%s)" % metric
        influx_data = InfluxMultiLoadHandler(influx_uuids).get_stats(
            metric=metric, start=_start, stop=_stop, step=_step,
        )

    if fdb_uuids:
        fdb_data = fdb_get_load(owner, fdb_uuids, start, stop, step)

    if victoria_uuids:
        victoria_data = victoria_get_load(
            owner, victoria_uuids, start, stop, step)

    if graphite_data or influx_data or fdb_data or victoria_data:
        return dict(
            list(graphite_data.items()) +
            list(influx_data.items()) +
            list(fdb_data.items()) +
            list(victoria_data.items())
        )
    else:
        raise NotFoundError("No machine has monitoring enabled")


def get_cores(owner, start="", stop="", step="", uuids=None):
    """Get cores for all monitored machines."""
    clouds = Cloud.objects(owner=owner, deleted=None).only("id")
    if uuids:
        machines = Machine.objects(
            owner=owner, cloud__in=clouds, id__in=uuids,
            monitoring__hasmonitoring=True
        )
    else:
        machines = Machine.objects(
            owner=owner, cloud__in=clouds, monitoring__hasmonitoring=True
        )

    graphite_uuids = [
        machine.id
        for machine in machines
        if machine.monitoring.method.endswith("-graphite")
    ]
    influx_uuids = [
        machine.id
        for machine in machines
        if machine.monitoring.method.endswith("-influxdb")
    ]
    fdb_uuids = [
        machine.id
        for machine in machines
        if machine.monitoring.method.endswith("-tsfdb")
    ]
    victoria_uuids = [
        machine.id
        for machine in machines
        if machine.monitoring.method.endswith("-victoriametrics")
    ]

    graphite_data = {}
    influx_data = {}
    fdb_data = {}
    victoria_data = {}

    if graphite_uuids:
        graphite_data = graphite_get_cores(
            owner, start=start, stop=stop, step=step, uuids=graphite_uuids
        )
    if influx_uuids:
        # Transform "min" and "sec" to "m" and "s", respectively.
        _start, _stop, _step = [
            re.sub("in|ec", repl="", string=x)
            for x in (start.strip("-"), stop.strip("-"), step)
        ]
        metric = "cpu.cpu=/cpu\d/.usage_idle"
        if step:
            metric = "MEAN(%s)" % metric
        influx_data = InfluxMultiCoresHandler(influx_uuids).get_stats(
            metric=metric, start=_start, stop=_stop,
            step=_step)

    if fdb_uuids:
        fdb_data = fdb_get_cores(owner, fdb_uuids, start, stop, step)

    if victoria_uuids:
        victoria_data = victoria_get_cores(
            owner, victoria_uuids, start, stop, step)

    if graphite_data or influx_data or fdb_data or victoria_data:
        return dict(
            list(graphite_data.items()) +
            list(influx_data.items()) +
            list(fdb_data.items()) +
            list(victoria_data.items())
        )
    else:
        raise NotFoundError("No machine has monitoring enabled")


def check_monitoring(owner):
    """Return the monitored machines, enabled metrics, and user details."""

    custom_metrics = owner.get_metrics_dict()
    for metric in list(custom_metrics.values()):
        metric["machines"] = []

    monitored_machines = []
    monitored_machines_2 = {}

    clouds = Cloud.objects(owner=owner, deleted=None)
    machines = Machine.objects(
        cloud__in=clouds, monitoring__hasmonitoring=True
    )

    for machine in machines:
        monitored_machines.append([machine.cloud.id, machine.external_id])
        try:
            commands = machine.monitoring.get_commands()
        except Exception as exc:
            log.error(exc)
            commands = {}
        monitored_machines_2[machine.id] = {
            "cloud_id": machine.cloud.id,
            "machine_id": machine.external_id,
            "installation_status": (
                machine.monitoring.installation_status.as_dict()
            ),
            "commands": commands,
        }
        for metric_id in machine.monitoring.metrics:
            if metric_id in custom_metrics:
                machines = custom_metrics[metric_id]["machines"]
                machines.append((machine.cloud.id, machine.external_id))

    ret = {
        "machines": monitored_machines,
        "monitored_machines": monitored_machines_2,
        "rules": owner.get_rules_dict(),
        "alerts_email": owner.alerts_email,
        "custom_metrics": custom_metrics,
    }
    if config.DEFAULT_MONITORING_METHOD.endswith("graphite"):
        ret.update(
            {
                # Keep for backwards compatibility
                "builtin_metrics": config.GRAPHITE_BUILTIN_METRICS,
                "builtin_metrics_graphite": config.GRAPHITE_BUILTIN_METRICS,
                "builtin_metrics_influxdb": config.INFLUXDB_BUILTIN_METRICS,
            }
        )
    elif config.DEFAULT_MONITORING_METHOD.endswith("influxdb"):
        ret.update(
            {
                # Keep for backwards compatibility
                "builtin_metrics": config.INFLUXDB_BUILTIN_METRICS,
                "builtin_metrics_influxdb": config.INFLUXDB_BUILTIN_METRICS,
            }
        )
    elif config.DEFAULT_MONITORING_METHOD.endswith("tsfdb"):
        ret.update(
            {
                # Keep for backwards compatibility
                "builtin_metrics": {},
                # "builtin_metrics_tsfdb": config.FDB_BUILTIN_METRICS,
            }
        )
    elif config.DEFAULT_MONITORING_METHOD.endswith("victoriametrics"):
        ret.update(
            {
                # Keep for backwards compatibility
                "builtin_metrics": {},
                # "builtin_metrics_tsfdb": config.FDB_BUILTIN_METRICS,
            }
        )
    for key in ("rules", "builtin_metrics", "custom_metrics"):
        for id in ret[key]:
            ret[key][id]["id"] = id
    return ret


def update_monitoring_options(org, emails):
    """Set `emails` as global e-mail alert's recipients."""
    from mist.api.helpers import is_email_valid

    # FIXME Send e-mails as a list, instead of string?
    emails = emails.replace(" ", "")
    emails = emails.replace("\n", ",")
    emails = emails.replace("\r", ",")
    org.alerts_email = [
        email for email in emails.split(",") if is_email_valid(email)
    ]
    org.save()
    trigger_session_update(org, ["org"])
    return {"alerts_email": org.alerts_email}


def enable_monitoring(
    owner,
    cloud_id,
    machine_id,
    no_ssh=False,
    dry=False,
    job_id="",
    deploy_async=True,
    plugins=None,
):
    """Enable monitoring for a machine.

    If `no_ssh` is False, then the monitoring agent will be deployed over SSH.
    Otherwise, the installation command will be returned to the User in order
    to be ran manually.

    """
    log.info(
        "%s: Enabling monitoring for machine '%s' in cloud '%s'.",
        owner.id,
        machine_id,
        cloud_id,
    )

    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError("Cloud does not exist")
    try:
        machine = Machine.objects.get(cloud=cloud, id=machine_id)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)
    if machine.monitoring.hasmonitoring:
        log.warning(
            "%s: Monitoring is already enabled for "
            "machine '%s' in cloud '%s'.",
            owner.id,
            machine_id,
            cloud_id,
        )

    old_monitoring_method = machine.monitoring.method
    # Decide on monitoring method
    machine.monitoring.method = (
        machine.cloud.default_monitoring_method or
        machine.cloud.owner.default_monitoring_method or
        config.DEFAULT_MONITORING_METHOD
    )
    assert machine.monitoring.method in config.MONITORING_METHODS

    if old_monitoring_method != machine.monitoring.method:
        machine.monitoring.method_since = datetime.datetime.now()
    # Extra vars
    if machine.monitoring.method in (
        "telegraf-influxdb",
        "telegraf-graphite",
        "telegraf-tsfdb",
        "telegraf-victoriametrics"
    ):
        extra_vars = {"uuid": machine.id, "monitor": config.INFLUX["host"]}
    else:
        raise Exception("Invalid monitoring method")

    # Ret dict
    ret_dict = {"extra_vars": extra_vars}
    for os_type, cmd in list(machine.monitoring.get_commands().items()):
        ret_dict["%s_command" % os_type] = cmd
    # for backwards compatibility
    ret_dict["command"] = ret_dict["unix_command"]

    # Dry run, so return!
    if dry:
        return ret_dict

    # Reset Machines's InstallationStatus field.
    machine.monitoring.installation_status = InstallationStatus()
    machine.monitoring.installation_status.started_at = time.time()
    machine.monitoring.installation_status.state = "preparing"
    machine.monitoring.installation_status.manual = no_ssh
    machine.monitoring.hasmonitoring = True

    machine.save()
    notify_machine_monitoring(machine)

    # Attempt to contact monitor server and enable monitoring for the machine
    try:
        if machine.monitoring.method in (
            "telegraf-influxdb",
            "telegraf-graphite",
            "telegraf-tsfdb",
            "telegraf-victoriametrics"
        ):
            traefik.reset_config()
    except Exception as exc:
        machine.monitoring.installation_status.state = "failed"
        machine.monitoring.installation_status.error_msg = repr(exc)
        machine.monitoring.installation_status.finished_at = time.time()
        machine.monitoring.hasmonitoring = False
        machine.save()
        notify_machine_monitoring(machine)
        raise

    # Update installation status
    if no_ssh:
        machine.monitoring.installation_status.state = "installing"
    else:
        machine.monitoring.installation_status.state = "pending"
    machine.save()
    notify_machine_monitoring(machine)

    if not no_ssh:
        if job_id:
            job = None
        else:
            job_id = uuid.uuid4().hex
            job = "enable_monitoring"
        ret_dict["job"] = job
        if machine.monitoring.method in (
            "telegraf-influxdb",
            "telegraf-graphite",
            "telegraf-tsfdb",
            "telegraf-victoriametrics"
        ):
            # Install Telegraf
            func = mist.api.monitoring.tasks.install_telegraf
            if deploy_async:
                func = func.send
            func(machine.id, job, job_id, plugins)
        else:
            raise Exception("Invalid monitoring method")

    if job_id:
        ret_dict["job_id"] = job_id

    return ret_dict


def disable_monitoring(owner, cloud_id, machine_id, no_ssh=False, job_id=""):
    """Disable monitoring for a machine.

    If `no_ssh` is False, we will attempt to SSH to the Machine and uninstall
    the monitoring agent.

    """
    log.info(
        "%s: Disabling monitoring for machine '%s' in cloud '%s'.",
        owner.id,
        machine_id,
        cloud_id,
    )

    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError("Cloud does not exist")
    try:
        machine = Machine.objects.get(cloud=cloud, id=machine_id)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_id)
    if not machine.monitoring.hasmonitoring:
        raise BadRequestError("Machine does not have monitoring enabled")

    # Uninstall monitoring agent.
    ret_dict = {}
    if not no_ssh:
        if job_id:
            job = None
        else:
            job = "disable_monitoring"
            job_id = uuid.uuid4().hex
        ret_dict["job"] = job

        if machine.monitoring.method in (
            "telegraf-influxdb",
            "telegraf-graphite",
            "telegraf-tsfdb",
            "telegraf-victoriametrics"
        ):
            # Schedule undeployment of Telegraf.
            mist.api.monitoring.tasks.uninstall_telegraf.send(
                machine.id, job, job_id
            )
    if job_id:
        ret_dict["job_id"] = job_id

    # Update monitoring information in db: set monitoring to off, remove rules.
    # If the machine we are trying to disable monitoring for is the only one
    # included in a rule, then delete the rule. Otherwise, attempt to remove
    # the machine from the list of resources the rule is referring to.
    for rule in MachineMetricRule.objects(org_id=machine.owner.id):
        if isinstance(rule, NoDataRule):
            NoDataRuleTracker.remove(rule.id, machine.id)
        elif rule.ctl.includes_only(machine):
            rule.delete()
        else:
            rule.ctl.maybe_remove(machine)

    machine.monitoring.hasmonitoring = False
    machine.monitoring.activated_at = 0
    machine.save()
    notify_machine_monitoring(machine)

    # tell monitor server to no longer monitor this uuid
    try:
        if machine.monitoring.method in (
            "telegraf-influxdb",
            "telegraf-graphite",
            "telegraf-tsfdb",
            "telegraf-victoriametrics"
        ):
            traefik.reset_config()
    except Exception as exc:
        log.error(
            "Exception %s while asking monitor server in "
            "disable_monitoring",
            exc,
        )

    notify_machine_monitoring(machine)

    return ret_dict


def disable_monitoring_cloud(owner, cloud_id, no_ssh=False):
    """Disable monitoring for all machines of the specified Cloud."""
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        machines = Machine.objects(
            cloud=cloud, monitoring__hasmonitoring=True
        ).only("machine_id")
    except me.DoesNotExist:
        raise NotFoundError("Cloud doesn't exist")
    for machine in machines:
        try:
            disable_monitoring(
                owner, cloud_id, machine.id, no_ssh=no_ssh
            )
        except Exception as exc:
            log.error(
                "Error while disabling monitoring for all machines of "
                "Cloud %s (%s): %s",
                cloud.id,
                owner.id,
                exc,
            )


async def async_find_metrics(resources):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError('loop is closed')
    except RuntimeError:
        loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    metrics_all = [
        loop.run_in_executor(None, find_metrics, resource)
        for resource in resources
    ]
    metrics_all = await asyncio.gather(*metrics_all, return_exceptions=True)
    metrics_dict = {}
    for resource, metrics in zip(resources, metrics_all):
        if isinstance(metrics, Exception):
            log.error("Failed to get metrics for resource %s: %r" %
                      (resource, metrics))
        else:
            metrics_dict.update(metrics)
    return metrics_dict


def find_metrics(resource):
    """Return the metrics associated with the specified resource."""
    if not hasattr(resource, "monitoring") or \
            not resource.monitoring.hasmonitoring:
        return {}

    if resource.monitoring.method in ('telegraf-graphite'):
        return graphite_find_metrics(resource)
    elif resource.monitoring.method == 'telegraf-influxdb':
        metrics = {}
        for metric in show_fields(show_measurements(resource.id)):
            metrics[metric['id']] = metric
        return metrics
    elif resource.monitoring.method == "telegraf-tsfdb":
        return fdb_find_metrics(resource)
    elif resource.monitoring.method == "telegraf-victoriametrics":
        return victoria_find_metrics(resource)
    else:
        raise Exception("Invalid monitoring method")


def associate_metric(machine, metric_id, name="", unit=""):
    """Associate a new metric to a machine."""
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")
    metric = update_metric(machine.owner, metric_id, name, unit)
    if metric_id not in machine.monitoring.metrics:
        machine.monitoring.metrics.append(metric_id)
        machine.save()
    notify_machine_monitoring(machine)
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
    notify_machine_monitoring(machine)


def update_metric(owner, metric_id, name="", unit=""):
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
    return metric


# FIXME The `plugin_id` is the name of the plugin/script as it exists in the
# monitoring agent's configuration, and not an ID stored in our database to
# which we can easily refer.
def undeploy_python_plugin(machine, plugin_id):
    """Undeploy a custom plugin from a machine."""
    # Just remove the executable.
    plugin = os.path.join("/opt/mistio/mist-telegraf/custom", plugin_id)
    script = "$(command -v sudo) rm %s" % plugin

    # Run the command over SSH.
    shell = mist.api.shell.Shell(machine.ctl.get_host())
    key_id, ssh_user = shell.autoconfigure(
        machine.owner, machine.cloud.id, machine.external_id
    )
    retval, stdout = shell.command(script)
    shell.disconnect()

    if retval:
        log.error("Error undeploying custom plugin: %s", stdout)

    # TODO Shouldn't we also `disassociate_metric` and remove relevant Rules?

    return {'metric_id': None, 'stdout': stdout}


def find_all_metrics(resources):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    metrics = loop.run_until_complete(async_find_metrics(resources))
    loop.close()
    return metrics


def find_metrics_by_attributes(auth_context, resource_id, resource_type, tags):
    resource_types = ["machine", "cloud"]
    if resource_id:
        if not resource_type:
            cloud, _ = list_resources(
                auth_context, "cloud", search=resource_id)
            # If we have an id which corresponds to a cloud but no resource
            # type we return all the metrics of all resources of that cloud
            if cloud:
                resources, _ = list_resources(
                    auth_context, "machine", cloud=cloud[0].id)
                return find_all_metrics(resources)
        if resource_type:
            resource_types = [resource_type]
        for resource_type in resource_types:
            resources, _ = list_resources(
                auth_context, resource_type=resource_type, search=resource_id)
            if resources:
                return find_all_metrics(resources)
        return {}
    if resource_type:
        resources, _ = list_resources(
            auth_context, resource_type=resource_type, tags=tags)
        return find_all_metrics(resources)
    if tags:
        resources = []
        for resource_type in resource_types:
            resources += (list_resources(auth_context,
                                         resource_type=resource_type,
                                         tags=tags))[0]
        return find_all_metrics(resources)
    return {}


def notify_machine_monitoring(machine):
    patches = []
    patches.append({
        "path": "/%s-%s/monitoring" % (
            machine.id, machine.external_id),
        "value": machine.monitoring.as_dict(),
        "op": "replace"
    })

    amqp_publish_user(machine.owner.id,
                      routing_key='patch_machines',
                      data={'cloud_id': machine.cloud.id,
                            'patch': patches})
