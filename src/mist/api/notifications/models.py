import mongoengine as me

from mist.api.users.models import User, Organization


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
        '''
        Accepts a notification and returns a boolean indicating
        whether it is allowed or has been blocked by the user
        '''
        for rule in self.rules:
            # TODO: here eventually check for source as well
            if (rule.source == notification.source and
                    rule.value == 'BLOCK'):
                return False
        return True


class Notification(me.Document):
    '''
    Represents a notification associated with a
    user-organization pair
    '''
    created_date = me.DateTimeField(required=False)
    expiry_date = me.DateTimeField(required=False)

    user = me.ReferenceField(User, required=True)
    organization = me.ReferenceField(Organization, required=True)

    summary = me.StringField(max_length=512, required=False, default="")
    subject = me.StringField(max_length=256, required=False, default="")
    body = me.StringField(required=True, default="")
    html_body = me.StringField(required=False, default="")

    source = me.StringField(max_length=64, required=True, default="")
    channel = me.StringField(max_length=64, required=True, default="")

    email = me.EmailField(required=False)
    ubsub_link = me.URLField(required=False)
