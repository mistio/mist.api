
from mist.api.helpers import params_from_request, view_config
from mist.api.auth.methods import user_from_request

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
            params = params_from_request(request)
            ntfs = Notification.objects(id=notification_id)
            if ntfs:
                ntf = ntfs[0]
                if ntf.user == user:
                    ntf.dismissed = True
                    ntf.save()
                    return ntf.to_json()
