from uuid import uuid4
from datetime import datetime

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
        Accepts a notification or string token and returns a boolean
        indicating whether corresponding notification is allowed
        or is blocked
        '''
        source = type(notification).__name__
        for rule in self.rules:
            if (rule.source == source and
                    rule.value == 'BLOCK'):
                return False
            elif (rule.source == source and
                    rule.value == 'ALLOW'):
                return True
        return not notification.explicit_allow

    def channel_allowed(self, channel, default=False):
        '''
        Accepts a notification or string token and returns a boolean
        indicating whether corresponding notification is allowed
        or is blocked
        '''
        for rule in self.rules:
            if (rule.source == channel and
                    rule.value == 'BLOCK'):
                return False
            elif (rule.source == channel and
                    rule.value == 'ALLOW'):
                return True
        return default


class Notification(me.Document):
    '''
    Represents a notification associated with a
    user-organization pair
    '''
    meta = {'allow_inheritance': True}

    id = me.StringField(primary_key=True,
                        default=lambda: uuid4().hex)

    created_date = me.DateTimeField(required=False)
    expiry_date = me.DateTimeField(required=False)

    user = me.ReferenceField(User, required=True)
    organization = me.ReferenceField(Organization, required=True)

    # content fields
    summary = me.StringField(max_length=512, required=False, default="")
    body = me.StringField(required=True, default="")
    html_body = me.StringField(required=False, default="")

    # taxonomy fields
    source = me.StringField(max_length=64, required=True, default="")
    resource = me.GenericReferenceField(required=False)
    action_link = me.URLField(required=False)

    unique = me.BooleanField(required=True, default=True)

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

    # if true, only send (show) if explicitly
    # allowed by a notifications rule
    explicit_allow = me.BooleanField(required=True, default=False)

    def __init__(self, *args, **kwargs):
        super(Notification, self).__init__(*args, **kwargs)
        if not self.created_date:
            self.created_date = datetime.now()


class EmailReport(Notification):
    '''
    Represents a notification corresponding to
    an email report
    '''
    subject = me.StringField(max_length=256, required=False, default="")
    email = me.EmailField(required=False)
    unsub_link = me.URLField(required=False)


class InAppNotification(Notification):
    '''
    Represents an in-app notification
    '''
    model_id = me.StringField(required=True, default="")  # "autoscale_v1"
    model_output = me.DictField(
        required=True,
        default={})  # {"direction": "up"}

    dismissed = me.BooleanField(required=True, default=False)


class InAppRecommendation(InAppNotification):
    '''
    Represents an in-app recommendation
    '''
    def __init__(self, *args, **kwargs):
        super(InAppNotification, self).__init__(*args, **kwargs)
        # recommendations should be explicitly allowed by
        # the user
        if not self.explicit_allow:
            self.explicit_allow = True
