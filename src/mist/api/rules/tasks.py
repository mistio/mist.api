from mist.api.tasks import app
from mist.api.rules.models import Rule
from mist.api.rules.models import NoDataRule


@app.task
def evaluate(rule_id):
    """Perform a full rule evaluation."""
    rule = Rule.objects.get(id=rule_id)
    rule.ctl.evaluate(update_state=True, trigger_actions=True)


@app.task
def add_nodata_rule(owner_id):
    """Idempotently setup a NoDataRule for the given Organization."""
    try:
        NoDataRule.objects.get(owner_id=owner_id, title='NoData')
    except NoDataRule.DoesNotExist:
        NoDataRule(owner_id=owner_id).ctl.auto_setup()
