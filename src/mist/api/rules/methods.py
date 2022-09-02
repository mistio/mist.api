import logging

from mist.api import config

from mist.api.exceptions import RuleNotFoundError

from mist.api.helpers import get_resource_model

from mist.api.notifications.helpers import _log_alert

from mist.api.rules.models import Rule
from mist.api.rules.models import NoDataAction
from mist.api.rules.models import NotificationAction
from mist.api.rules.tasks import run_action_by_id


log = logging.getLogger(__name__)


def run_chained_actions(rule_id, incident_id, resource_id, resource_type,
                        value, triggered, triggered_now, timestamp):
    """Run a Rule's actions.

    Runs actions based on the rule's state. This method will initially check
    whether a NoData alert has been raised in order to call a special NoData
    action. In case a rule is re-triggered or its state transitions from the
    untriggered to triggered state and vice versa, relevant events will also
    be logged.

    When a monitoring rule is triggered, this method will asynchronously apply
    a celery chain of the rule's actions that have been specified by user. The
    chain's tasks are executed sequentially, meaning that the next task in the
    chain is executed once the one that preceded it has completed successfully.

    It is IMPORTANT to create a chain of immutable tasks (using the `.si`
    callable, instead of the more regularly used `.s`), since by default a
    chained task provides its output as the following task's input, which may
    yield unexpected behavior.

    """
    try:
        rule = Rule.objects.get(id=rule_id)
    except Rule.DoesNotExist:
        raise RuleNotFoundError()
    # Log (un)triggered alert.
    skip_log = False if triggered_now or not triggered else True
    if skip_log is False:
        if not rule.is_arbitrary():
            Model = get_resource_model(resource_type)
            resource = Model.objects.get(id=resource_id, owner=rule.org)
        else:
            resource = rule.org
        _log_alert(resource, rule, value, triggered, timestamp, incident_id,
                   rule.actions[0])
    # If the rule got un-triggered or re-triggered, just send a notification
    # if a NotificationAction has been specified.
    if not (triggered and triggered_now):
        action = rule.actions[0]
        if isinstance(action, NotificationAction):
            run_action_by_id.send(
                rule_id, incident_id, action.id, resource_id,
                resource_type, value, triggered, timestamp,
            )
        return

    # Get a list of task signatures for every task, excluding the first one.
    tasks = []
    for action in rule.actions:
        task = run_action_by_id.message(
            rule_id, incident_id, action.id, resource_id,
            resource_type, value, triggered, timestamp,
        )
        tasks.append(task)

    delay = 0
    # Buffer no-data alerts so that we can decide on false-positives.
    if isinstance(rule.actions[0], NoDataAction):
        delay = config.NO_DATA_ALERT_BUFFER_PERIOD * 1000
    from mist.api.dramatiq_app import dramatiq
    # Apply all tasks in parallel
    dramatiq.group(tasks).run(delay=delay)
