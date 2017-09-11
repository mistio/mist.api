
from mist.api.helpers import view_config
from mist.api.auth.methods import user_from_request, org_from_request
from mist.api.notifications.channels import channel_instance_for_notification

from models import Notification, NotificationPolicy, NotificationRule


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


@view_config(route_name='api_v1_notification_rules',
             request_method='PUT', renderer='json')
def set_notification_rules(request):
    """
    Set notification rules for user, org policy
    ---
    """
    new_rules = request.matchdict.get("rules")
    user = user_from_request(request)
    org = org_from_request(request)
    policies = NotificationPolicy.objects(user=user, org=org)
    if policies:
        policy = policies[0]
        for i in len(policy.rules):
            rule = policy.rules[i]
            new_rule = new_rules[i]
            assert(rule.source == new_rule["source"])
            assert(rule.channel == new_rule["channel"])
            rule.value = new_rule["value"]

        


