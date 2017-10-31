from uuid import uuid4
from datetime import datetime

import mongoengine as me

from mist.api import config

from mist.api.users.models import User, Organization


class NotificationOverride(me.EmbeddedDocument):
    '''
    Represents a single notification override.
    '''
    id = me.StringField(primary_key=True,
                        default=lambda: uuid4().hex)

    source = me.StringField(
        max_length=64,
        required=True,
        default="")  # eg "alerts"
    channel = me.StringField(
        max_length=64,
        required=False,
        default="")  # eg "InAppNotification"

    machine = me.GenericReferenceField(required=False)
    tag = me.GenericReferenceField(required=False)
    cloud = me.GenericReferenceField(required=False)

    value = me.StringField(max_length=7, required=True,
                           choices=('ALLOW', 'BLOCK'), default='BLOCK')

    def matches_notification(self, notification):
        if self.machine and notification.machine:
            if self.machine != notification.machine:
                return False
        if self.tag and notification.tag:
            if self.tag != notification.tag:
                return False
        if self.cloud and notification.cloud:
            if self.cloud != notification.cloud:
                return False
        return self.source == type(notification).__name__


class UserNotificationPolicy(me.Document):
    '''
    Represents a notification policy associated with a
    user-organization pair, and containing a list of overrides.
    '''
    overrides = me.EmbeddedDocumentListField(NotificationOverride)
    user = me.ReferenceField(User, required=True)
    organization = me.ReferenceField(Organization, required=True)

    def notification_allowed(self, notification, default=True):
        '''
        Accepts a notification and returns a boolean
        indicating whether corresponding notification is allowed
        or is blocked
        '''
        for override in self.overrides:
            if override.matches_notification(notification):
                if override.value == 'BLOCK':
                    return False
                elif override.value == 'ALLOW':
                    return True
        return default

    def channel_allowed(self, channel, default=True):
        '''
        Accepts a string token and returns a boolean
        indicating whether corresponding notification is allowed
        or is blocked
        '''
        for override in self.overrides:
            if (override.source == channel and
                    override.value == 'BLOCK'):
                return False
            elif (override.source == channel and
                    override.value == 'ALLOW'):
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
    machine = me.GenericReferenceField(required=False)
    tag = me.GenericReferenceField(required=False)
    cloud = me.GenericReferenceField(required=False)

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

    def __init__(self, *args, **kwargs):
        super(Notification, self).__init__(*args, **kwargs)
        if not self.created_date:
            self.created_date = datetime.now()

    def update_from(self, notification):
        self.created_date = notification.created_date
        self.expiry_date = notification.expiry_date

        self.user = notification.user
        self.organization = notification.organization

        self.summary = notification.summary
        self.body = notification.body
        self.html_body = notification.html_body

        self.source = notification.source
        self.machine = notification.machine
        self.tag = notification.tag
        self.cloud = notification.cloud

        self.unique = notification.unique

        self.action_link = notification.action_link

        self.severity = notification.severity
        self.feedback = notification.feedback


class EmailNotification(Notification):
    '''
    Represents a generic email notification
    '''
    sender_email = me.StringField(max_length=256, required=True)
    sender_title = me.StringField(max_length=256, required=True)

    subject = me.StringField(max_length=256, required=False, default="")
    email = me.EmailField(required=False)
    unsub_link = me.URLField(required=False)

    def __init__(self, *args, **kwargs):
        super(EmailNotification, self).__init__(*args, **kwargs)
        if not self.sender_email:
            self.sender_email = config.EMAIL_NOTIFICATIONS_SENDER
        if not self.sender_title:
            self.sender_title = "Mist.io Notifications"

    def update_from(self, notification):
        super(EmailNotification, self).update_from(notification)

        self.subject = notification.subject
        self.email = notification.email
        self.unsub_link = notification.unsub_link


class EmailAlert(EmailNotification):
    '''
    Represents a notification corresponding to
    an email alert
    '''

    def __init__(self, *args, **kwargs):
        super(EmailNotification, self).__init__(*args, **kwargs)
        if not self.sender_email:
            self.sender_email = config.EMAIL_ALERTS_SENDER
        if not self.sender_title:
            self.sender_title = "Mist.io Alerts"


class EmailReport(EmailNotification):
    '''
    Represents a notification corresponding to
    an email report
    '''

    def __init__(self, *args, **kwargs):
        super(EmailNotification, self).__init__(*args, **kwargs)
        if not self.sender_email:
            self.sender_email = config.EMAIL_REPORTS_SENDER
        if not self.sender_title:
            self.sender_title = "Mist.io Reports"


class InAppNotification(Notification):
    '''
    Represents an in-app notification
    '''
    model_id = me.StringField(required=True, default="")  # "autoscale_v1"
    model_output = me.DictField(
        required=True,
        default={})  # {"direction": "up"}

    dismissed = me.BooleanField(required=True, default=False)

    def update_from(self, notification):
        super(InAppNotification, self).update_from(notification)

        self.model_id = notification.model_id
        self.model_output = notification.model_output
        # do not include dismissed atribute in updates
        # self.dismissed = notification.dismissed


class InAppRecommendation(InAppNotification):
    '''
    Represents an in-app recommendation
    '''
    pass
