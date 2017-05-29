
from mist.api.users.models import User, Organization
import models
import channels


def send_notification(notification):
    '''
    Accepts a notification instance, checks against user
    notification policy and sends the notification
    through specified channels.
    '''
    user = User.objects.get(id=notification.user_id)
    org = Organization.objects.get(id=notification.org_id)
    policies = models.UserNotificationPolicy.objects(user=user, organization=org)
    if policies:
        policy = policies[0]
        if policy.notification_allowed(notification):
            chan = channels.channel_instance_with_name(notification.channel)
            if chan:
                chan.send(notification)


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


def get_policy(user, org, create=True):
    '''
    Accepts a user-org pair and returns the corresponding notification
    policy, with the option to create one if not exist.
    '''
    policies = models.UserNotificationPolicy.objects(user=user, organization=org)
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


def test():
    '''
    Test this
    '''
    user = User.objects.get(email="yconst@mist.io")
    user_id = user.id
    org = Organization.objects.get(members=user)
    org_id = org.id

    ntf = models.Notification(subject="some spam", body="more spam",
                              source="alerts", channel="stdout",
                              user_id=user_id, org_id=org_id)
    
    # first send with no rules - it should pass
    remove_block_rule(user, org, "alerts")
    print "Sending with no rules - message should appear below:"
    send_notification(ntf)

    # now create a rule - it should fail
    add_block_rule(user, org, "alerts")
    print "Sending with block rule - nothing should appear below:"
    send_notification(ntf)

if __name__ == "__main__":
    test()
