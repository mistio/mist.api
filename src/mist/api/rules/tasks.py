import logging

from mist.api.dramatiq_app import dramatiq

from mist.api.helpers import get_resource_model
from mist.api.helpers import rtype_to_classpath

from mist.api.rules.models import Rule
from mist.api.rules.models import NoDataRule

from mist.api.exceptions import MistError
from mist.api.exceptions import CloudUnavailableError
from mist.api.exceptions import ServiceUnavailableError
from mist.api.exceptions import MachineUnauthorizedError

from mist.api.notifications.helpers import _log_alert


log = logging.getLogger(__name__)

__all__ = [
    'evaluate',
    'add_nodata_rule',
    'run_action_by_id',
]


@dramatiq.actor(max_retries=3, max_age=60_000, queue_name='dramatiq_rules')
def evaluate(rule_id):
    """Perform a full rule evaluation."""
    try:
        rule = Rule.objects.get(id=rule_id)
    except Rule.DoesNotExist:
        log.warning('Cannot evaluate rule %s, not found', rule_id)
        return
    rule.ctl.evaluate(update_state=True, trigger_actions=True)


@dramatiq.actor
def add_nodata_rule(org_id, backend='graphite'):
    """Idempotently setup a NoDataRule for the given Organization."""
    try:
        log.info('Adding %s no-data rule for Org %s', backend, org_id)
        NoDataRule.objects.get(org_id=org_id, title='NoData')
    except NoDataRule.DoesNotExist:
        NoDataRule(org_id=org_id).ctl.auto_setup(backend=backend)


@dramatiq.actor(max_retries=3, max_age=60_000, queue_name='dramatiq_rules')
def run_action_by_id(rule_id, incident_id, action_id,
                     resource_id, resource_type, value, triggered, timestamp):
    """Run a Rule's action asynchronously.

    Attempts to run an action, which is identified by its action_id. Such
    tasks are usually called as part of a celery chain, meaning that every
    subsequent task is registered as a callback to the task that preceded
    it. If a task fails and raises an exception, the chain will transition
    to the failure state and the rest of the chain's tasks will not run.

    This task will be retried in case it's failed up to `self.max_retries`
    times with an interval based on `self.default_retry_delay`. Note that
    celery will not move on to the next task in the chain, while a task is
    being retried.

    Extra CAUTION must be taken when raising/suppressing exceptions in order
    to avoid unexpected behavior.

    """
    rule = Rule.objects.get(id=rule_id)
    action = rule.actions.get(id=action_id)

    if rule.is_arbitrary():
        resource = None
    else:
        assert resource_type in rtype_to_classpath, resource_type
        Model = get_resource_model(resource_type)
        resource = Model.objects.get(id=resource_id, owner=rule.org_id)

    try:
        action.run(resource, value, triggered, timestamp, incident_id)
    except (ServiceUnavailableError, CloudUnavailableError) as err:
        # Catch errors due to SSH connectivity issues and the cloud provider's
        # API being unresponsive. Log the failure even if it will be retried
        _log_alert(resource, rule, value, triggered,
                   timestamp, incident_id, error=str(err))
        raise
    except MachineUnauthorizedError as err:
        # Catch exception, log it, and re-raise to improve auditing. Re-raising
        # the exception is important in order to stop the chain's execution.
        _log_alert(resource, rule, value, triggered, timestamp, incident_id,
                   error=str(err))
        raise
    except MistError as err:
        log.error("Error running %s: %r", action, err)
        _log_alert(resource, rule, value, triggered, timestamp, incident_id,
                   error=str(err))
        raise
    except Exception as err:
        log.error("Error running %s: %r", action, err)
        raise
