
from mist.api.users.models import User, Organization
import models
import channels

def send_notification(notification):
	'''
	Accepts a notification instance, checks against user
	notification policy and sends the notification
	through specified channels.
	'''
	user = User(id=notification.user_id)
	org = Organization()
	policy = models.UserNotificationPolicy(user=user, organization=org)
	if policy.notification_allowed(notification):
		chan = channels.channel_instance_with_name(notification.channel)
		if chan:
			chan.send(notification)

def test():
	'''
	Test this
	'''
	user=User()
	user_id=user.id
	org=Organization(members=user)
	org_id=org.id

	ntf = models.Notification(subject="some spam", body="more spam", 
		source="alerts", channel="stdout", 
		user_id=user_id, org_id=org_id)
	send_notification(ntf)

if __name__ == "__main__":
	test()