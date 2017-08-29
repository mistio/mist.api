
from mist.api.helpers import view_config
from mist.api.auth.methods import user_from_request
from mist.api.notifications.channels import channel_instance_for_notification

from models import Notification


@view_config(route_name='api_v1_dismiss_notification',
             request_method='DELETE', renderer='json')
def dismiss_notification(request):
    """
    Dismiss notification
    Dismisses specified notification
    ---
    """
    user = user_from_request(request)
    if user:
        notification_id = request.matchdict.get("notification_id")
        if notification_id:
            notifications = Notification.objects(id=notification_id)
            if notifications:
                notification = notifications[0]
                if notification.user == user:
                    chan = channel_instance_for_notification(notification)
                    chan.dismiss(notification)
