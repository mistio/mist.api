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

    # FIXME: Shouldn't be specific to machines. This should be replaced with a
    # (resource_type, resource_uuid) combination.
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
        return self.channel == type(notification).__name__


class UserNotificationPolicy(me.Document):
    '''
    Represents a notification policy associated with a
    user-organization pair, and containing a list of overrides.
    '''
    overrides = me.EmbeddedDocumentListField(NotificationOverride)
    user = me.ReferenceField(User)
    organization = me.ReferenceField(Organization, required=True)

    email = me.EmailField(required=True)

    meta = {
        'indexes': [
            {
                'fields': ['email', 'organization'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ],
    }

    # NOTE The UserNotificationPolicy should be dynamic. What if an external
    # user e-mail is provided, but the user afterwards joins the organization
    # or an organization member decides to leave down the road? Wouldn't it be
    # enough for a UserNotificationPolicy to map to an (organization, e-mail)
    # combination and check on the fly whether the e-mail belongs to a member
    # of the organization?
    # @property
    # def is_user_external(self):
    #     try:
    #         User.objects.get(email=self.email)
    #     except User.DoesNotExist:
    #         return True
    #     else:
    #         return False

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
            if (override.channel == channel and
                    override.value == 'BLOCK'):
                return False
            elif (override.channel == channel and
                    override.value == 'ALLOW'):
                return True
        return default

    # FIXME This is here just to auto-populate the `email` field.
    def clean(self):
        if not self.email and self.user:
            self.email = self.user.email


class Notification(me.Document):
    '''
    Represents a notification associated with a
    user-organization pair
    '''

    id = me.StringField(primary_key=True,
                        default=lambda: uuid4().hex)

    created_date = me.DateTimeField(required=False)
    expiry_date = me.DateTimeField(required=False)

    # FIXME: Should the user/e-mail be stored? Shouldn't a single notification
    # exist per event? For instance, if an e-mail is sent to X members, should
    # we persist X documents to mongodb? Isn't 1 enough?
    user = me.ReferenceField(User)
    email = me.EmailField(required=True)
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

    meta = {
        'strict': False,
        'allow_inheritance': True,
        'indexes': [
            'organization'
        ]
    }

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

    def clean(self):
        if not self.email and self.user:  # FIXME Remove alongside `self.user`.
            self.email = self.user.email
        if not self.created_date:
            self.created_date = datetime.now()


class EmailNotification(Notification):
    '''
    Represents a generic email notification
    '''
    sender_email = me.StringField(max_length=256, required=True)
    sender_title = me.StringField(max_length=256, required=True)

    subject = me.StringField(max_length=256, required=False, default="")
    unsub_link = me.URLField(required=False)

    # FIXME: Couldn't these just be regular class attributes instead of fields?
    def __init__(self, *args, **kwargs):
        super(EmailNotification, self).__init__(*args, **kwargs)
        if not self.sender_email:
            self.sender_email = config.EMAIL_NOTIFICATIONS
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

    rule_id = me.StringField(required=True)
    incident_id = me.StringField(required=True)
    reminder_count = me.IntField(required=True, min_value=0, default=0)

    def __init__(self, *args, **kwargs):
        super(EmailNotification, self).__init__(*args, **kwargs)
        if not self.sender_email:
            self.sender_email = config.EMAIL_ALERTS
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
            self.sender_email = config.EMAIL_REPORTS
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
