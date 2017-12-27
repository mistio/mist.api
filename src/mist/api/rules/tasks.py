from mist.api.tasks import app
from mist.api.rules.models import Rule


@app.task
def evaluate(rule_id):
    """Perform a full rule evaluation."""
    rule = Rule.objects.get(id=rule_id)
    rule.ctl.evaluate(update_state=True, trigger_actions=True)
