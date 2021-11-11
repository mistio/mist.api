
import logging

from mist.api.dramatiq_app import dramatiq

from mist.api.notifications.models import NoDataRuleTracker
from mist.api.rules.models import NoDataRule
from mist.api.machines.models import Machine


log = logging.getLogger(__name__)

__all__ = [
    'gc_nodataruletracker'
]


@dramatiq.actor
def gc_nodataruletracker():
    """Deletes outdated tracking information of triggered NoData rules
    """
    NoDataRuleTracker.objects(
        rule_id__nin=[rule.id for rule in NoDataRule.objects()]).delete()
    NoDataRuleTracker.objects(
        machine_id__nin=[
            machine.id for machine in Machine.objects(
                missing_since=None,
                monitoring__hasmonitoring=True)]).delete()
