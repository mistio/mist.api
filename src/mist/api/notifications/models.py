from uuid import uuid4

import mongoengine as me

from mist.api.users.models import User, Organization
from mist.api.machines.models import Machine
from mist.api.clouds.models import Cloud


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
    id = me.StringField(primary_key=True,
                        default=lambda: uuid4().hex)

    created_date = me.DateTimeField(required=False)
    expiry_date = me.DateTimeField(required=False)

    user = me.ReferenceField(User, required=True)
    organization = me.ReferenceField(Organization, required=True)

    # content fields
    summary = me.StringField(max_length=512, required=False, default="")
    subject = me.StringField(max_length=256, required=False, default="")
    body = me.StringField(required=True, default="")
    html_body = me.StringField(required=False, default="")

    # source fields
    source = me.StringField(max_length=64, required=True, default="")
    channel = me.StringField(max_length=64, required=True, default="")

    # resource and action fields
    kind = me.StringField(required=True, default="")
    resource = me.GenericReferenceField(required=False)
    action_link = me.URLField(required=False)

    # email-specific fields
    email = me.EmailField(required=False)
    unsub_link = me.URLField(required=False)

    # user action fields
    viewed = me.BooleanField(required=True, default=False)
    dismissed = me.BooleanField(required=True, default=False)

    severity = me.StringField(
        max_length=7,
        required=True,
        choices=(
            'LOW',
            'DEFAULT',
            'HIGH'),
        default='DEFAULT')

    feedback = me.StringField(
        max_length=8,
        required=True,
        choices=(
            'NEGATIVE',
            'NEUTRAL',
            'POSITIVE'),
        default='NEUTRAL')

    def get_action_link(self):
        '''
        Either returns the action_link property if it exists,
        or generates a link using the associated resource and
        kind properties
        '''
        if self.action_link:
            return action_link
        if self.resource is Machine:
            return "/machines/" + self.resource.id
        if self.resource is Cloud:
            return "/clouds/" + self.resource.id
        return None
