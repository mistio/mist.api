import models
from models import Notification
import channels


'''
NOTIFICATION POLICIES
'''


def add_rule(user, org, notification, value='BLOCK'):
    '''
    Adds a notification rule to a user-org policy
    for the specified notification type.
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    source = type(notification).__name__
    rules = [rule for rule in policy.rules if rule.source == source]
    if not rules:
        rule = models.NotificationOverride()
        rule.source = source
        rule.value = value
        if notification.machine:
            rule.machine_id = notification.machine.id
        if notification.tag:
            rule.tag_id = notification.tag.id
        if notification.cloud:
            rule.cloud_id = notification.cloud.id
        policy.rules.append(rule)
        policy.save()


def remove_rule(user, org, notification):
    '''
    Removes a notification rule to a user-org policy
    for the specified notification type.
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    source = type(notification).__name__
    for rule in policy.rules:
        if (rule.tag_id and notification.tag and
            rule.tag_id != notification.tag.id):
            continue
        if (rule.cloud_id and notification.cloud and
            rule.cloud_id != notification.cloud.id):
            continue
        if (rule.machine_id and notification.machine and
            rule.machine_id != notification.machine.id):
            continue
        if rule.source == source:
            policy.rules.remove(rule)
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
