import datetime
import mongoengine as me


class RuleState(me.EmbeddedDocument):
    """This class denotes the per resource state for a given Rule.

    A Rule's `states` field stores the current state of incidents that have
    been triggered. The majority of these incidents are meant to be active.

    The state of a given incident may be described by 3 timestamps:

        1. firing_since: denotes when the rule got triggered for a resource
        2. pending_since: denotes when the rule got in pending state
        3. resolved_since: denotes when the rule got untriggered

    A pending state describes an incident that has been triggered, because its
    query conditions evaluated to True, but the corresponding action/alert has
    been temporarily suppressed.

    A Rule's `states` field is supposed to keep state of unresolved incidents.
    However, untriggered/resolved incidents are also kept around for a small
    retention period in order to be propagated to the end user as "resolved".
    The retention period is specified by the `EXPIRE_PERIOD` class attribute.
    Resolved states older than `EXPIRE_PERIOD` seconds are removed.

    """

    value = me.DynamicField()

    resource = me.StringField()

    firing_since = me.DateTimeField()
    pending_since = me.DateTimeField()
    resolved_since = me.DateTimeField()

    EXPIRE_PERIOD = 60 * 60 * 6  # 6 hours.

    def is_firing(self):
        return self.firing_since is not None and not self.is_resolved()

    def is_pending(self):
        if not self.pending_since:
            return False
        return not (self.is_resolved() or self.is_firing())

    def is_resolved(self):
        return self.resolved_since is not None

    def expired(self):
        if not self.is_resolved():
            return False
        return (datetime.datetime.utcnow() -
                self.resolved_since).total_seconds() > self.EXPIRE_PERIOD

    def as_dict(self):
        return {
            'value': self.value,
            'resource': self.resource or '',
            'firing_since': str(self.firing_since or ''),
            'pending_since': str(self.pending_since or ''),
            'resolved_since': str(self.resolved_since or ''),
        }

    def __str__(self):
        if self.is_firing():
            return 'FIRING since %s' % self.firing_since.ctime()
        if self.is_pending():
            return 'PENDING since %s' % self.pending_since.ctime()
        if self.is_resolved():
            return 'RESOLVED since %s' % self.resolved_since.ctime()
