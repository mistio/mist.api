import re

import mongoengine as me

# NotificationPolicy -> NotificationRule(List)   -> NotificationOperator(List)
#                    -> NotificationChannel(List) <-'

class NotificationChannel(me.EmbeddedDocument):
    """
    Represents a single Notifications channel, such as
    email, desktop, in-app etc.
    """
    ctype = me.StringField(max_length=20, default="")
    cid = me.StringField(max_length=64, default="")


class NotificationOperator(me.EmbeddedDocument):
    """
    Represents a single Notifications operator, which
    essentially corresponds to an allow/block action
    """
    channel = me.EmbeddedDocumentField(NotificationChannel)
    cid = me.StringField(max_length=64, default="")
    value = me.StringField(max_length=5, required=True,
                           choices=('ALLOW', 'INHERIT', 'BLOCK'))


class NotificationRule(me.EmbeddedDocument):
    """
    Represents a single Notifications rule, which includes
    a filter expression and a list of rules of length equal
    to the number of channels defined in the parent policy
    """
    type = me.StringField(max_length=200, required=True, default="")
    action = me.StringField(max_length=200, required=True, default="")
    tags = me.StringField(max_length=200, required=True, default="")
    operators = me.EmbeddedDocumentListField(NotificationOperator)

    def channels_for_notification(self, notification, inherited_channels=[]):
        """
        Accepts a notification and checks its validity against
        the rule, returning the list of channels which are allowed.
        
        The method also accepts an optional list of channels inherited (e.g.
        from another, higher-level policy). In this case, it performs a difference
        with those inherited channels with the blocked channels of the current
        policy, and performs a union with the result with the allowed channels
        of the current policy.
        """
        if self.notification_matches_rule(notification):
            allowed_ch = Set([op.channel for op in self.operators if op.value == 'ALLOW'])
            blocked_ch = Set([op.channel for op in self.operators if op.value == 'BLOCK'])
            inherited_ch = Set(inherited_channels)
            return list(allowed_ch + (inherited_ch - blocked_ch))

    def notification_matches_rule(notification):
        """
        Accepts a notification and returns whether
        the notification type, action and tags match the corresponding
        rule entries
        """
        return (notification.type == self.type 
                and notification.action == self.action 
                and notification.tags == self.tags)


class NotificationPolicy(me.EmbeddedDocument):
    """
    Represents a policy for pushing notifications
    through different channels, according to one or more
    rules.
    """
    rules = me.EmbeddedDocumentListField(NotificationRule)
    channels = me.EmbeddedDocumentListField(NotificationChannel)

    def channels_for_notification(self, notification, inherited_channels=None):
        """
        Accepts a notification instance and returns a list of channel
        instances through which the notification should be pushed, 
        by checking against the policy's rules.
        """
        channels = Set()
        for rule in self.rules:
            new_channels = Set(rule.channels_for_notification(notification, inherited_channels))
            channels = channels.union(new_channels)
        return channels

    def get_channels(self, rtype = None):
        """
        Returns policy channels that any of the policy's, rules
        refer to, optionally filtering by one or more rule types.
        """
        pass

    def get_rules(self, ctype = None):
        """
        Returns policy rules, optionally filtering by one
        or more channel ids.
        """
        pass


class Notification():
    # todo: allow custom fields
    def __init__(self, message, type, action=None):
        self.message = message
        self.type = type
        self.action = action
