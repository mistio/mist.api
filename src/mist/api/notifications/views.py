
from mist.api.helpers import params_from_request
from mist.api.auth.methods import user_from_request

from models import Notification


@view_config(route_name='api_v1_dismiss_notification',
             request_method='POST', renderer='json')
def dismiss_notification(request):
    """
    Dismiss notification
    Dismisses specified notification
    ---
    """
    user = user_from_request(request)
    if user:
        params = params_from_request(request)
        ntfs = Notification.objects(id=params["notification_id"])
        if ntfs:
            ntf = ntfs[0]
            if ntf.user == user:
                ntf.dismissed = True
                ntf.save()
                return ntf.to_json()
