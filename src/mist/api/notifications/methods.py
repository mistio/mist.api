import models
from models import Notification
import channels


'''
NOTIFICATION POLICIES
'''


def add_block_rule(user, org, notification):
    '''
    Adds a block rule to a user-org policy for the specified
    notification type.
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    source = type(notification).__name__
    rules = [rule for rule in policy.rules if rule.source == source]
    if not rules:
        rule = models.NotificationRule()
        rule.source = source
        rule.value = "BLOCK"
        policy.rules.append(rule)
        policy.save()


def remove_block_rule(user, org, notification):
    '''
    Removes a block rule to a user-org policy for the specified
    notification type.
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    source = type(notification).__name__
    rules = [rule for rule in policy.rules if rule.source == source]
    if rules:
        policy.rules.remove(rules[0])
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
