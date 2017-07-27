from datetime import datetime

from mist.api.users.models import User, Organization
import models
from models import Notification
import channels

'''
NOTIFICATION POLICIES
'''


def add_block_rule(user, org, source):
    '''
    Adds a block rule to a user-org policy for the specified source.
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    rules = [rule for rule in policy.rules if rule.source == source]
    if not rules:
        rule = models.NotificationRule()
        rule.source = source
        rule.value = "BLOCK"
        policy.rules.append(rule)
        policy.save()


def remove_block_rule(user, org, source):
    '''
    Removes a block rule to a user-org policy for the specified source.
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    rules = [rule for rule in policy.rules if rule.source == source]
    if rules:
        policy.rules.remove(rules[0])
        policy.save()


def has_block_rule(user, org, source):
    '''
    Accepts a user and org and queries whether
    there is a block rule in place.
    Creates the policy if it does not exist.
    '''
    policy = get_policy(user, org)
    rules = [rule for rule in policy.rules if rule.source == source]
    if rules:
        return True
    return False


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
        chan = channels.channel_instance_with_name(notification.channel)
        if chan:
            chan.send([notification])


def get_notifications(user, org, channel, get_dismissed=False):
    '''
    Gets notifications with user, org and channel as parameters.
    By default only gets active (i.e. not dismissed)
    notifications.
    '''
    org = Organization.objects.get(id=org['id'])
    if get_dismissed:
        notifications = Notification.objects(
            user=user, organization=org, channel=channel)
    else:
        notifications = Notification.objects(
            user=user, organization=org, channel=channel, dismissed=False)
    return notifications


def make_notification(
        subject,
        body,
        source,
        channel,
        user,
        org,
        summary=None,
        html_body=None,
        unsub_link=None,
        resource=None,
        kind="",
        save=False):
    '''
    Generates a notification. By default the notification is not
    saved for efficiency. If required, it will be saved later on
    by the appropriate channel.
    '''
    notification = Notification()
    notification.created_date = datetime.now()
    notification.subject = subject
    notification.body = body
    notification.source = source
    notification.channel = channel
    notification.user = user
    notification.organization = org
    notification.resource = resource
    notification.kind = kind
    if summary:
        notification.summary = summary
    if html_body:
        notification.html_body = html_body
    if unsub_link:
        notification.unsub_link = unsub_link
    if save:
        notification.save()
    return notification


def dismiss_scale_notifications(machine, feedback='neutral'):
    '''
    Convenience function to dismiss scale notifications from
    a machine.
    Calls dismiss on each notification's channel. May update
    the feedback field on each notification.
    '''
    notifications = Notification.objects(resource=machine,
                                         kind__contains="machine.scale")
    for notification in notifications:
        notification.feedback = feedback
        chan = channels.channel_instance_with_name(notification.channel)
        if chan:
            chan.dismiss([notification])


def test():
    '''
    Test this
    '''
    user = User.objects.get(email="yconst@mist.io")
    org = Organization.objects.get(members=user)

    notification = make_notification("some spam", "more spam",
                                     "alerts", "stdout", user, org)

    # first send with no rules - it should pass
    remove_block_rule(user, org, "alerts")
    print "Sending with no rules - message should appear below:"
    send_notification(notification)

    # now create a rule - it should fail
    add_block_rule(user, org, "alerts")
    print "Sending with block rule - nothing should appear below:"
    send_notification(notification)


if __name__ == "__main__":
    test()
