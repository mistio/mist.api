
import logging

from mist.api.users.models import User, Organization
from mist.api.notifications.models import NotificationPolicy, Notification

log = logging.getLogger(__name__)

def handle_log_event(msg):
	'''
	Accepts an event passed by the messaging queue and
	pushes it to different channels according to
	default, organization and user policies
	'''
	user_id = msg.body["user_id"] # TODO: replace with actual message content
	user = User.objects(id=user_id)

	import ipdb; ipdb.set_trace()

	if user is not None:
		orgs = Organization.objects(members=user)

	 	default_policy = NotificationPolicy(default=True)
	 	user_policy = NotificationPolicy.objects(owner=user)
	 	org_policy = NotificationPolicy.objects(owner=organization)

	 	notification = models.Notification("test", "text", 
	 		msg.body["type"], msg.body["tag"], msg.body["action"])

	 	channels = default_policy.channels_for_notification(notification)
	 	channels = org_policy.channels_for_notification(notification, inherited_channels=channels)
	 	channels = user_policy.channels_for_notification(notification, inherited_channels=channels)

	 	for channel in channels:
	 		channel.send(notification, user)


def register_notification_policy(channels, default=True, owner=None):
	'''
	Create, register and return a new notification policy
	'''
	policy = NotificationPolicy()
	if owner:
		policy.owner = owner
	policy.default = default
	policy.channels = channels
	policy.save()
	return policy


def get_channel(name):
	pass