import models
from models import Notification
import channels


'''
NOTIFICATION POLICIES
'''


def add_override(user, org, notification, value='BLOCK'):
    '''
    Adds a notification override to a user-org policy
    using matching fields of the specified notification.
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    source = type(notification).__name__
    overrides = [override for override in policy.overrides if override.source == source]
    if not overrides:
        override = models.NotificationOverride()
        override.source = source
        override.value = value
        if notification.machine:
            override.machine_id = notification.machine.id
        if notification.tag:
            override.tag_id = notification.tag.id
        if notification.cloud:
            override.cloud_id = notification.cloud.id
        policy.overrides.append(override)
        policy.save()


def add_override_source(user, org, source, value='BLOCK'):
    '''
    Adds a notification override to a user-org policy
    for the specified source.
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    overrides = [override for override in policy.overrides if override.source == source]
    if not overrides:
        override = models.NotificationOverride()
        override.source = source
        override.value = value
        policy.overrides.append(override)
        policy.save()


def remove_override(user, org, notification):
    '''
    Removes a notification override to a user-org policy
    for the specified notification type.
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    source = type(notification).__name__
    for override in policy.overrides:
        if (override.tag_id and notification.tag and
                override.tag_id != notification.tag.id):
            continue
        if (override.cloud_id and notification.cloud and
                override.cloud_id != notification.cloud.id):
            continue
        if (override.machine_id and notification.machine and
                override.machine_id != notification.machine.id):
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


'''
NOTIFICATION HELPERS
'''


def send_notification(notification):
    '''
    Accepts a notification instance, checks against user
    notification policy and sends the notification
    through specified channels.
    '''
    policy = get_policy(notification.user, notification.organization)
    if policy.notification_allowed(notification):
        chan = channels.channel_instance_for_notification(notification)
        if chan:
            chan.send(notification)


def dismiss_scale_notifications(machine, feedback='NEUTRAL'):
    '''
    Convenience function to dismiss scale notifications from
    a machine.
    Calls dismiss on each notification's channel. May update
    the feedback field on each notification.
    '''
    notifications = Notification.objects(resource=machine,
                                         model_id__contains="autoscale")
    for notification in notifications:
        notification.feedback = feedback
        chan = channels.channel_instance_for_notification(notification)
        if chan:
            chan.dismiss(notification)
