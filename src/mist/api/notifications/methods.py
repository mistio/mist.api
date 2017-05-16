
import logging

from mist.api.users.models import User, Organization

import models

log = logging.getLogger(__name__)

def handle_log_event(msg):

	user_id = msg.body["user_id"] # TODO: replace with actual message content
	user = User.objects(id=user_id)

	import ipdb; ipdb.set_trace()

	if user is not None:
		orgs = Organization.objects(members=user)

	# 	default_policy = NotificationPolicy()
	# 	user_policy = NotificationPolicy.objects(owner=user)
	# 	org_policy = NotificationPolicy.objects(owner=organization)

	# 	event_type = msg.body["type"]
