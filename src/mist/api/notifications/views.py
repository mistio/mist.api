import json

from mist.api.helpers import view_config
from mist.api.auth.methods import auth_context_from_request
from mist.api.notifications.channels import (channel_instance_for_notification,
                                             NotificationsEncoder)

from models import Notification, UserNotificationPolicy


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
             request_method='GET', renderer='json')
def get_notification_rules(request):
    """
    Get notification rules for user, org policy
    ---
    """
    auth_context = auth_context_from_request(request)
    user = auth_context.user
    org = auth_context.org
    policies = UserNotificationPolicy.objects(user=user, organization=org)
    if policies:
        policy = policies[0]
        return json.dumps(policy.rules, cls=NotificationsEncoder)


@view_config(route_name='api_v1_notification_rules',
             request_method='PUT', renderer='json')
def set_notification_rules(request):
    """
    Set notification rules for user, org policy
    ---
    """
    auth_context = auth_context_from_request(request)
    request_body = json.loads(request.body)
    new_rules = request_body["rules"]
    user = auth_context.user
    org = auth_context.org
    policies = UserNotificationPolicy.objects(user=user, organization=org)
    if policies:
        policy = policies[0]
        for i in range(len(policy.rules)):
            rule = policy.rules[i]
            new_rule = new_rules[i]
            assert(rule.source == new_rule["source"])
            assert(rule.channel == new_rule["channel"])
            import ipdb
            ipdb.set_trace()
            rule.value = new_rule["value"]
            rule.save()
