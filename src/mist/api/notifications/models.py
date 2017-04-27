import re

import mongoengine as me

# NotificationPolicy -> NotificationRule(List)   -> NotificationOperator(List)
#                    -> NotificationChannel(List) <-'


class NotificationPolicy(me.EmbeddedDocument):
    """
    Represents a policy for pushing notifications
    through different channels, according to one or more
    rules.
    """
    rules = me.EmbeddedDocumentListField(NotificationRule)
    channels = me.EmbeddedDocumentListField(NotificationChannel)

    def channels_for_notification(self, notification):
        """
        Accepts a notification instance and returns a list of channel
        instances through which the notification should be pushed, 
        by checking against the policy's rules.
        """
        channels = Set()
        for rule in self.rules:
            new_channels = Set(rule.channels_for_notification(notification))
            channels = channels.union(new_channels)
        return channels

    def get_channels(self, rtype = None):
        """
        Returns policy channels that any of the policy's, rules
        refer to, optionally filtering by one or more rule ids.
        """
        pass

    def get_rules(self, ctype = None):
        """
        Returns policy rules, optionally filtering by one
        or more channel ids.
        """
        pass


class NotificationRule(me.EmbeddedDocument):
    """
    Represents a single Notifications rule, which includes
    a filter expression and a list of rules of length equal
    to the number of channels defined in the parent policy
    """
    rule = me.StringField(max_length=200, required=True, default="")
    operators = me.EmbeddedDocumentListField(NotificationOperator)

    def channels_for_notification(self, notification):
        """
        Accepts a notification and checks its validity against
        the rule, returning the list of channels which are allowed.
        """
        if self.notification_passes_rule(notification, self.rule):
            return [op.channel for op in self.operators if op.value == 'ALLOW']

    def notification_passes_rule(notification, rule):
        pass


class NotificationOperator(me.EmbeddedDocument):
    """
    Represents a single Notifications operator, which
    essentially corresponds to an allow/block action
    """
    channel = me.EmbeddedDocumentField(NotificationChannel)
    rule = me.EmbeddedDocumentField(NotificationRule)
    cid = me.StringField(max_length=64, default="")
    value = me.StringField(max_length=5, required=True,
                           choices=('ALLOW', 'BLOCK'))


class NotificationChannel(me.EmbeddedDocument):
    """
    Represents a single Notifications channel, such as
    email, desktop, in-app etc.
    """
    ctype = me.StringField(max_length=20, default="")
    cid = me.StringField(max_length=64, default="")


class Notification():

    def __init__(self, message, type, action=None):
        self.message = message
        self.type = type
        self.action = action
