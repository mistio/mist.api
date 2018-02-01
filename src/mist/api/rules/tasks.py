import logging

from mist.api import config

from mist.api.celery_app import app

from mist.api.rules.models import Rule
from mist.api.rules.models import NoDataRule
from mist.api.machines.models import Machine

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import CloudUnavailableError
from mist.api.exceptions import ServiceUnavailableError
from mist.api.exceptions import MachineUnauthorizedError

from mist.api.notifications.helpers import _log_alert


log = logging.getLogger(__name__)


@app.task
def evaluate(rule_id):
    """Perform a full rule evaluation."""
    rule = Rule.objects.get(id=rule_id)
    rule.ctl.evaluate(update_state=True, trigger_actions=True)


@app.task
def add_nodata_rule(owner_id, backend='graphite'):
    """Idempotently setup a NoDataRule for the given Organization."""
    try:
        log.info('Adding %s no-data rule for Org %s', backend, owner_id)
        # NOTE Allow a second NoDataRule in case of a mist.core installation
        # that has `config.CILIA_MULTI=True`. This is necessary if the old
        # graphite-based monitoring system works in parallel with the newer,
        # influxdb-based.
        title = 'NoData'
        if config.HAS_CORE and config.CILIA_MULTI and backend == 'influxdb':
            title = backend.capitalize() + title
        NoDataRule.objects.get(owner_id=owner_id, title=title)
    except NoDataRule.DoesNotExist:
        NoDataRule(owner_id=owner_id).ctl.auto_setup(backend=backend)


@app.task(bind=True, default_retry_delay=5, max_retries=3)
def run_action_by_id(self, owner_id, rule_id, action_id, machine_id, value,
                     triggered, timestamp, notification_level, incident_id):
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
    rule = Rule.objects.get(owner_id=owner_id, title=rule_id)
    action = rule.get_action(action_id)
    machine = Machine.objects.get(id=machine_id)

    if machine.owner.id != owner_id:
        raise NotFoundError()
    if not machine.monitoring.hasmonitoring:
        raise BadRequestError()

    try:
        action.run(machine, value, triggered, timestamp, incident_id)
    except (ServiceUnavailableError, CloudUnavailableError) as err:
        # Catch errors due to SSH connectivity issues and the cloud provider's
        # API being unresponsive.
        log.error('Error running %s: %r', action, err)
        # Log the failure, if there are no more retries.
        if self.request.retries >= self.max_retries:
            _log_alert(machine.owner, rule_id, value, triggered,
                       timestamp, incident_id, error=str(err),
                       cloud_id=machine.cloud.id,
                       machine_id=machine.machine_id)
        # Retry task with a linear back-off to minimize the chances of hitting
        # the same error again.
        countdown = (self.default_retry_delay * (self.request.retries + 1))
        # After max_retries have been exceeded, this will re-raise the original
        # exception.
        self.retry(exc=err, countdown=countdown)
    except MachineUnauthorizedError as err:
        # Catch exception, log it, and re-raise to improve auditing.
        log.error("Error running %s: %r", action, err)
        _log_alert(machine.owner, rule_id, value, triggered,
                   timestamp, incident_id, error=str(err),
                   cloud_id=machine.cloud.id, machine_id=machine.machine_id)
        # Re-raising the exception is important in order to stop the chain's
        # execution.
        raise
    except Exception as exc:
        log.error("Error running %s: %r", action, exc)
        _log_alert(machine.owner, rule_id, value, triggered,
                   timestamp, incident_id, error='%s failed' % action,
                   cloud_id=machine.cloud.id, machine_id=machine.machine_id)
        raise
