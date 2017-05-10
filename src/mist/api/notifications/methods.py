
import logging
import models

log = logging.getLogger(__name__)

def handle_log_event(msg):
	log.info("Received log event: %s", msg)

	# here find out which org the log belongs to

	# for policy in NotificationPolicy.objects(org=org):
	# 	channels = policy.get_channels(msg.channels)
	# 	for channel in channels:
	# 		channel.send(msg.content)