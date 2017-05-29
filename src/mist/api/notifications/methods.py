
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



def test():
    '''
    Test this
    '''
    user = User.objects.get(email="yconst@mist.io")
    user_id = user.id
    org = Organization.objects.get(members=user)
    org_id = org.id

    # create policy if not exist
    policies = models.UserNotificationPolicy.objects(user=user, organization=org)
    if not policies:
        policy = models.UserNotificationPolicy()
        policy.user = user
        policy.organization = org
        policy.save()

        #retry
        policies = models.UserNotificationPolicy.objects(user=user, organization=org)
        assert(policies)

    #reset rules
    policy = policies[0]
    policy.rules = []
    policy.save()

    ntf = models.Notification(subject="some spam", body="more spam",
                              source="alerts", channel="stdout",
                              user_id=user_id, org_id=org_id)
    
    # first send with no rules - it should pass
    print "Sending with no rules - should appear below:"
    send_notification(ntf)

    # now create a rule for stdout - it should fail
    rule = models.NotificationRule()
    rule.source = "alerts"
    rule.value = "BLOCK"

    policy.rules.append(rule)
    policy.save()

    print "Sending with block rule - nothing should appear below:"
    send_notification(ntf)

if __name__ == "__main__":
    test()
