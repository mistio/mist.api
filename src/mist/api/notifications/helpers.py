import re
import time
import datetime

from mist.api import config

from mist.api.helpers import rename_kwargs

from mist.api.exceptions import BadRequestError

from mist.api.users.models import Metric
from mist.api.rules.models import Rule
from mist.api.rules.models import NoDataRule
from mist.api.rules.models import MachineMetricRule
from mist.api.rules.models import ArbitraryLogsRule
from mist.api.rules.models import ResourceLogsRule

from mist.api.logs.methods import log_event

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine


def _get_alert_details(resource, rule, incident_id,
                       value, triggered, timestamp, action=''):
    """Return a dict with the alert/incident details. For resource-bound
    rules, this method must return a dict that is resource-agnostic, yet
    contains all the necessary information in terms of the corresponding
    resource, such as its type and UUID, as well as any other resource-
    specific information."""
    assert isinstance(rule, Rule)
    assert resource or rule.is_arbitrary()

    # Use the old way for monitoring data for now..
    if isinstance(rule, MachineMetricRule):
        return _alert_pretty_machine_details(
            rule.owner, rule.title, value, triggered, timestamp,
            resource.cloud.id, resource.machine_id, action
        )

    # A human-readable string of the query conditions.
    cond = ' & '.join([str(q) for q in rule.queries])
    cond += ' within %d %s' % (rule.window.start - rule.window.stop,
                               rule.window.period)

    # A quick description of the metric.
    label = '%s of matching %s' % (rule.queries[-1].aggregation,
                                   rule._data_type_str)

    # The basic dict of details for describing every alert. All common
    # alert details among rules should be added here.
    d = {
        'rule_id': rule.id,
        'rule_title': rule.title,
        'rule_data_type': rule._data_type_str,
        'rule_arbitrary': rule.is_arbitrary(),
        'metric_name': label,
        'curr_value': value,
        'condition': cond,
        'action': 'alert',
        'state': 'WARNING' if triggered else 'OK',
        'since': _get_time_diff_to_now(timestamp),
        'time': _get_current_local_time(),
        'uri': config.CORE_URI,
    }

    # FIXME For backwards compatibility. Note that `name` cannot be
    # defined for arbitrary rules. The `host` and `machine_link` entries
    # are machine-specific.
    d.update({'name': '', 'host': '', 'machine_link': ''})

    if isinstance(rule, ArbitraryLogsRule):
        return d

    if isinstance(rule, ResourceLogsRule):
        resource_type = resource._get_collection_name().rstrip('s')
        d.update({
            'resource_id': resource.id,
            'resource_type': resource_type,
            'resource_name': _get_resource_name(resource),
            'resource_repr': _get_resource_repr(resource),
            'resource_link': '%s/%ss/%s' % (config.CORE_URI,
                                            resource_type, resource.id)
        })
        return d

    raise Exception()


# TODO Deprecate.
def _alert_pretty_machine_details(owner, rule_id, value, triggered, timestamp,
                                  cloud_id='', machine_id='', action=''):
    # Always pass (cloud_id, machine_id) explicitly instead of getting them
    # from  the `Rule` instance, as before, since instances of `NoDataRule`
    # will most likely return multiple resources, which is not supported by
    # the current implementation.
    assert cloud_id and machine_id
    rule = Rule.objects.get(owner_id=owner.id, title=rule_id)

    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    machine = Machine.objects.get(cloud=cloud, machine_id=machine_id)

    if machine.monitoring.method.endswith('graphite'):
        metrics = config.GRAPHITE_BUILTIN_METRICS
    if machine.monitoring.method.endswith('influxdb'):
        metrics = config.INFLUXDB_BUILTIN_METRICS

    if isinstance(rule, NoDataRule):
        # no data alert
        condition = "Monitoring data unavailable"
        label = "Monitoring data"
        fval = "unavailable"
    else:
        # regular alert
        if not action:
            action = rule.action
        if rule.metric in metrics:
            mdict = metrics[rule.metric]
            metric = Metric(metric_id=rule.metric, name=mdict['name'],
                            unit=mdict['unit'])
        else:
            try:
                metric = Metric.objects.get(owner=owner, metric_id=rule.metric)
            except Metric.DoesNotExist:
                raise BadRequestError(
                    "Metric '%s' is not a builtin rule metric, "
                    "nor defined in .metrics." % rule.metric
                )
        label = metric.name or rule.metric.replace(".", " ")
        if rule.operator == 'lt':
            operator = '<'
        elif rule.operator == 'gt':
            operator = '>'
        else:
            operator = rule.operator
        fthresh = metric.format_value(rule.value)
        condition = '%s %s %s' % (label, operator, fthresh)
        if rule.aggregate in ('any', 'avg'):
            condition += ' for %s value' % rule.aggregate
        if rule.reminder_offset:
            period = int(1 + rule.reminder_offset / 60)
            condition += ' within %s mins' % period
        fval = metric.format_value(value)

    state = "WARNING" if triggered else "OK"

    return {
        'rule_id': rule.id,
        'rule_title': rule.title,
        'cloud_id': cloud_id,
        'machine_id': machine_id,
        'name': machine.name,
        'resource_name': machine.name,
        'resource_repr': _get_resource_repr(machine),
        'host': _get_nice_machine_host_label(machine),  # dns name or ip
        'condition': condition,  # all of load greater than 5 for 2 mins
        'state': state,  # WARNING or OK
        'action': action,  # reboot
        'time': _get_current_local_time(),  # time
        'metric_name': label,  # cpu or my_metric or Mon Data
        'curr_value': fval,  # current metric value
        'since': _get_time_diff_to_now(timestamp),  # relative time of trigger
        'machine_link': '%s/machines/%s' % (config.CORE_URI, machine.id),
        'resource_link': '%s/machines/%s' % (config.CORE_URI, machine.id),
        'uri': config.CORE_URI,
        'resource_type': 'machine',
        'rule_data_type': 'metrics',
        'rule_arbitrary': False,
    }


def _log_alert(resource, rule, value, triggered, timestamp, incident_id,
               action='', **kwargs):
    """Create a log entry for the triggered rule. Any special pre-processing
    of the log entry, such as renaming dict keys, should be taken care of at
    this point."""
    # Get dict with alert details.
    info = _get_alert_details(resource, rule, incident_id, value,
                              triggered, timestamp, action)

    # Get the resource's type. This will be set to None for arbitrary rules.
    resource_type = info.pop('resource_type', None)

    # Set of keys to remove.
    for key in ('uri', 'name', 'time', 'since', 'action',
                'incident_id', 'resource_repr', 'machine_link', ):
        if key in info:
            info.pop(key)

    # Rename resource-agnostic keys, if applicable.
    if resource_type is not None:
        for key in info.keys():
            if key.startswith('resource_'):
                rename_kwargs(info,
                              key, key.replace('resource', resource_type))

    # Rename arbitrary keys.
    rename_kwargs(info, 'curr_value', 'value')
    rename_kwargs(info, 'action', 'rule_action')

    # FIXME For backwards compability.
    if isinstance(resource, Machine):
        info['cloud_id'] = resource.cloud.id
        info['machine_id'] = resource.machine_id

    # Update info with additional kwargs.
    info.update(kwargs)

    # Log the alert.
    log_event(
        owner_id=rule.owner_id, event_type='incident', incident_id=incident_id,
        action='rule_triggered' if triggered else 'rule_untriggered', **info
    )


def _get_current_local_time():
    """Calculate current time in human readable format"""
    now = datetime.datetime.now()
    return '%s PDT (UTC-7)' % now.strftime('%a, %d %b %Y %H:%M:%S')


def _get_time_diff_to_now(ts):
    """Calculate time difference from `ts` to now in human readable format"""
    secs = abs(int(time.time() - ts))
    mins, secs = divmod(secs, 60)
    hours, mins = divmod(mins, 60)
    time_ago = ""
    if hours:
        time_ago += "%dh" % hours
    if mins:
        time_ago += "%dm" % mins
    if secs:
        time_ago += "%ds" % secs
    if time_ago:
        time_ago += " ago"
    else:
        time_ago = "just now"
    return time_ago


def _get_resource_name(resource):
    """Return the name identifier of the `resource` as stored in the db"""
    return (getattr(resource, 'name', '') or
            getattr(resource, 'title', '') or
            getattr(resource, 'domain', '') or '')


def _get_resource_repr(resource):
    """Return a nice name for the `resource` based on its str representation"""
    name = str(resource)
    name = re.sub(r'<class.*?> ', '', name).strip()  # Remove type()
    name = re.sub(r'of Org.*\)$', '', name).strip()  # Remove Org
    name = re.sub(r'\s\([a-z0-9]{32}?\)', '', name)  # Remove UUID
    return name.capitalize()


def _get_nice_machine_host_label(machine):
    """Calculate nice host label for `machine`"""
    ips = (', '.join(machine.public_ips) if machine.public_ips else
           ', '.join(machine.private_ips))
    hostname = machine.hostname if (machine.hostname and
                                    machine.hostname != 'n/a') else ''
    return '%s (%s)' % (hostname, ips) if hostname else ips
