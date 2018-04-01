import operator
import logging

from mist.api.exceptions import NotFoundError
from mist.api.rules.tasks import run_action_by_id
from mist.api.rules.models import Rule
from mist.api.rules.models import NotificationAction


log = logging.getLogger(__name__)


def run_chained_actions(rule_id, machine, value, triggered, timestamp,
                        notification_level, incident_id):
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
        rule = Rule.objects.get(owner_id=machine.owner.id, title=rule_id)
    except Rule.DoesNotExist:
        raise NotFoundError()

    # If the rule got un-triggered or re-triggered, just send a notification
    # if a NotificationAction has been specified.
    if not triggered or notification_level > 0:
        action = rule.actions[0]
        if isinstance(action, NotificationAction):
            run_action_by_id.delay(
                machine.owner.id, rule_id, action.id, machine.id, value,
                triggered, timestamp, notification_level, incident_id
            )
        return

    # Get a list of task signatures for every task, excluding the first one.
    chain = []
    for action in rule.actions[1:]:
        task = run_action_by_id.si(
            machine.owner.id, rule_id, action.id, machine.id, value,
            triggered, timestamp, notification_level, incident_id
        )
        chain.append(task)

    # If there are multiple actions, build a celery chain.
    if chain:
        chain = reduce(operator.or_, chain)

    # Get the task signature of the first action, which was omitted above.
    action = rule.actions[0]
    task = run_action_by_id.si(
        machine.owner.id, rule_id, action.id, machine.id, value,
        triggered, timestamp, notification_level, incident_id
    )

    # Apply all tasks asynchronously. There are 3 scenarios here:
    # a. If there's only a single task, and not a celery chain, just apply
    #    it
    # b. If there's a celery chain, group it with the first task, if it's
    #    a NotificationAction, in order for the NotificationAction to not
    #    block the rest of the chain by running them in parallel
    # c. If there's a celery chain, pipe it to the first task, if that is
    #    not a NotificationAction
    # TODO Allow multiple NotificationAction's. Permit users to specify
    # more than a single notification that will notify them of the outcome
    # of the previously executed task in the chain, whether it succeeded
    # or not.
    if not chain:
        task.apply_async()
    elif isinstance(action, NotificationAction):
        from celery import group
        group(task, chain)()
    else:
        chain = operator.or_(task, chain)
        chain.apply_async()
