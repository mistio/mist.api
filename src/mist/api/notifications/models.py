import mongoengine as me

from mist.api.users.models import User, Organization, Owner


class NotificationRule(me.EmbeddedDocument):
    '''
    Represents a single notification rule, with a notification source
    and optional channel.
    '''
    source = me.StringField(max_length=64, required=True, default="")
    channel = me.StringField(max_length=64, required=False, default="")
    value = me.StringField(max_length=7, required=True,
                           choices=('ALLOW', 'BLOCK'), default='BLOCK')


class UserNotificationPolicy(me.Document):
    '''
    Represents a notification policy associated with a
    user-organization pair, and containing a list of rules.
    '''
    rules = me.EmbeddedDocumentListField(NotificationRule)
    user = me.ReferenceField(User, required=True)
    organization = me.ReferenceField(Organization, required=True)

    def notification_allowed(self, notification):
        for rule in self.rules:
            # TODO: here eventually check for source as well
            if (rule.source == notification.source and
                    rule.value == 'BLOCK'):
                return False
        return True


class Notification():
    '''
    Represents a notification instance
    '''
    def __init__(self, subject, body, source, channel, user_id, org_id, summary=None):
        self.subject = subject
        self.summary = summary
        self.body = body
        self.source = source
        self.channel = channel
        self.user_id = user_id
        self.org_id = org_id
