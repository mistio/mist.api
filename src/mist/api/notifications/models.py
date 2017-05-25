import mongoengine as me

from mist.api.users.models import User, Organization, Owner


class UserNotificationPolicy(me.Document):
    '''
    Represents a notification policy associated with a
    user-organization pair, and containing a list of rules.
    '''
    rules = me.EmbeddedDocumentListField(NotificationRule)
    user = me.EmbeddedDocumentField(User)
    organization = me.EmbeddedDocumentField(Organization)

    def notification_allowed(self, notification):
        for rule in self.rules:
            # TODO: here eventually check for source as well
            if (rule.source == notification.source and
                    notification.value == 'BLOCK'):
                return False
        return True


class NotificationRule(me.EmbeddedDocument):
    '''
    Represents a single notification rule, with a notification source
    and optional channel.
    '''
    source = me.StringField(max_length=64, required=True, default="")
    channel = me.StringField(max_length=64, required=False, default="")
    value = me.StringField(max_length=7, required=True,
                           choices=('ALLOW', 'BLOCK'), default='BLOCK')


class Notification():
    '''
    Represents a notification instance
    '''

    def __init__(self, subject, summary=None, body, source, channel, user_id, org_id):
        self.subject = subject
        self.summary = summary
        self.body = body
        self.source = source
        self.channel = channel
        self.user_id = user_id
        self.org_id = org_id
