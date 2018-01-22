import time
import datetime

from mist.api import config

from mist.api.exceptions import BadRequestError

from mist.api.users.models import Metric
from mist.api.rules.models import Rule
from mist.api.rules.models.main import NoDataRule

from mist.api.logs.methods import log_event

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine


# TODO Deprecate.
def _alert_pretty_details(owner, rule_id, value, triggered, timestamp,
                          cloud_id='', machine_id='', action=''):
    # Always pass (cloud_id, machine_id) explicitly instead of getting them
    # from  the `Rule` instance, as before, since instances of `NoDataRule`
    # will most likely return multiple resources, which is not supported by
    # the current implementation.
    assert cloud_id and machine_id
    rule = Rule.objects.get(owner_id=owner.id, title=rule_id)

    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    machine = Machine.objects.get(cloud=cloud, machine_id=machine_id)

    if isinstance(rule, NoDataRule):
        # no data alert
        condition = "Monitoring data unavailable"
        label = "Monitoring data"
        fval = "unavailable"
    else:
        # regular alert
        if not action:
            action = rule.action
        if rule.metric in config.GRAPHITE_BUILTIN_METRICS:
            mdict = config.GRAPHITE_BUILTIN_METRICS[rule.metric]
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
            # rules are always checked for the last minute and the first
            # notification is sent reminder_offset secs after the rule is
            # triggered. This creates the false impression that the rule is
            # being checked for the last 1 + reminder_offset / 60 minutes
            period = int(1 + rule.reminder_offset / 60)
            condition += ' within %s mins' % period
        fval = metric.format_value(value)

    state = "WARNING" if triggered else "OK"
    # calculate nice host label
    ips = ", ".join(machine.public_ips) if machine.public_ips \
                                        else ", ".join(machine.private_ips)
    hostname = machine.hostname if (
        machine.hostname and machine.hostname != 'n/a') else ''
    if not hostname:
        host = ips
    else:
        host = "%s (%s)" % (hostname, ips)

    # calculate current time in human readable format
    local_time = datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S')
    local_time = "%s PDT (UTC-7)" % local_time

    # calculate time ago in human readable format
    secs = abs(int(time.time() - timestamp))
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
    return {
        'cloud_id': cloud_id,
        'machine_id': machine_id,
        'name': machine.name,
        'host': host,  # dns name or ip
        'condition': condition,  # all of load greater than 5 for 2 mins
        'state': state,  # WARNING or OK
        'action': action,  # reboot
        'time': local_time,  # time
        'metric_name': label,  # cpu or my_metric or Mon Data
        'curr_value': fval,  # current metric value
        'since': time_ago,  # relative time of trigger
        'machine_link': '%s/machines/%s' % (config.CORE_URI, machine.id),
        'uri': config.CORE_URI,
    }


# TODO Deprecate.
def _log_alert(owner, rule_id, value, triggered, timestamp, incident_id,
               cloud_id='', machine_id='', action='', **kwargs):
    info = _alert_pretty_details(
        owner, rule_id, value, triggered, timestamp,
        cloud_id, machine_id, action
    )
    event_kwargs = {
        'owner_id': owner.id,
        'event_type': 'incident',
        'action': 'rule_triggered' if triggered else 'rule_untriggered',
        'cloud_id': info['cloud_id'],
        'machine_id': info['machine_id'],
        'condition': info['condition'],
        'state': info['state'],
        'value': info['curr_value'],
        'machine_name': info['name'],
        'host': info['host'],
        'rule_action': info['action'],
        'incident_id': incident_id,
        'rule_id': rule_id,
    }
    event_kwargs.update(kwargs)
    log_event(**event_kwargs)
