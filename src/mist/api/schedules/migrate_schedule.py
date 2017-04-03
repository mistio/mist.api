import mongoengine as me
from mist.api.schedules.models import Schedule


class MSchedule(me.Document):
    """Temporary Document to hold migration status for users"""
    schedule = me.ReferenceField(Schedule, required=True)
    migrated = me.BooleanField(default=False)
