import models
from models import Notification
import channels


'''
NOTIFICATION POLICIES
'''


def add_override(notification, value='BLOCK'):
    '''
    Adds a notification override to a user-org policy
    using matching fields of the specified notification.
    Creates the policy if it does not exist.
    '''
    user = notification.user
    org = notification.organization
    policy = get_policy(user, org)
    source = notification.source
    channel = type(notification).__name__
    overrides = []

    for override in policy.overrides:
        if override.channel == channel:
            if (source and override.source == source) or (not source):
                return

    override = models.NotificationOverride()
    override.source = source
    override.channel = channel
    override.value = value
    if notification.machine:
        override.machine = notification.machine
    if notification.tag:
        override.tag = notification.tag
    if notification.cloud:
        override.cloud = notification.cloud
    policy.overrides.append(override)
    policy.save()


def add_override_channel(user, org, channel, value='BLOCK'):
    '''
    Adds a notification override to a user-org policy
    for the specified channel (e.g. "InAppNotifications").
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    for override in policy.overrides:
        if override.channel == channel:
            return

    override = models.NotificationOverride()
    override.channel = channel
    override.value = value
    policy.overrides.append(override)
    policy.save()


def remove_override(notification):
    '''
    Removes a notification override to a user-org policy
    for the specified notification type.
    Creates the policy if it does not exist.
    '''
    user = notification.user
    org = notification.organization
    policy = get_policy(user, org)
    source = type(notification).__name__
    for override in policy.overrides:
        if (override.tag and notification.tag and
                override.tag != notification.tag):
            continue
        if (override.cloud and notification.cloud and
                override.cloud != notification.cloud):
            continue
        if (override.machine and notification.machine and
                override.machine != notification.machine):
            continue
        if override.source == source:
            policy.overrides.remove(override)
    policy.save()


def get_policy(user, org, create=True):
    '''
    Accepts a user-org pair and returns the corresponding notification
    policy, with the option to create one if not exist.
    '''
    policies = models.UserNotificationPolicy.objects(
        user=user, organization=org)
    if not policies:
        if create:
            policy = models.UserNotificationPolicy()
            policy.user = user
            policy.organization = org
            policy.save()
            return policy
        else:
            return None
    return policies[0]


def get_non_member_policy(email, org, create=True):
    '''
    Accepts an email and returns the corresponding notification
    policy, with the option to create one if not exist.
    '''
    policies = models.NonMemberNotificationPolicy.objects(
        email=email, organization=org)
    if not policies:
        if create:
            policy = models.NonMemberNotificationPolicy()
            policy.email = email
            policy.organization = org
            policy.save()
            return policy
        else:
            return None
    return policies[0]


'''
NOTIFICATION HELPERS
'''


def send_notification(notification):
    '''
    Accepts a notification instance, checks against user
    or non-member notification policy and sends the
    notification through specified channels.
    '''
    if notification.user:
        policy = get_policy(notification.user, notification.organization)
    elif notification.email:
        policy = get_non_member_policy(
            notification.email, notification.organization)

    if policy.notification_allowed(notification):
        chan = channels.channel_instance_for_notification(notification)
        if chan:
            chan.send(notification)


def send_notifications(notifications):
    '''
    Accepts a list of notifications and sends the ones allowed.
    Calls send_notification
    '''
    for notification in notifications:
        send_notification(notification)


def dismiss_scale_notifications(machine, feedback='NEUTRAL'):
    '''
    Convenience function to dismiss scale notifications from
    a machine.
    Calls dismiss on each notification's channel. May update
    the feedback field on each notification.
    '''
    notifications = Notification.objects(machine=machine,
                                         model_id__contains="autoscale")
    for notification in notifications:
        notification.feedback = feedback
        chan = channels.channel_instance_for_notification(notification)
        if chan:
            chan.dismiss(notification)
