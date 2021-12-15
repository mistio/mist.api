import logging
from time import time

from mist.api.users.models import User
from mist.api.users.models import Organization
from mist.api.users.models import WhitelistIP

from mongoengine import ValidationError
from mongoengine import OperationError
from mongoengine import InvalidQueryError

from mist.api.auth.models import get_secure_rand_token

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import MethodNotAllowedError
from mist.api.exceptions import OrganizationOperationError

from mist.api.portal.models import Portal

from mist.api.helpers import ip_from_request

from mist.api import config

log = logging.getLogger(__name__)


def get_users_count(mongo_uri=None, confirmed=False):
    # return the number of all users, optionally confirmed only users
    if confirmed:
        return User.objects(status="confirmed").count()
    else:
        return User.objects().count()


def register_user(email, first_name, last_name, registration_method,
                  selected_plan=None, promo_code=None, token=None,
                  status='pending', create_organization=True, request=None):
    # User does not exist so we have to add him/her to the database
    # First make sure that email is not banned
    # Then create the User objects and the Organization
    if email.split('@')[1] in config.BANNED_EMAIL_PROVIDERS:
        raise MethodNotAllowedError("Email provider is banned.")

    user = User()
    user.email = email
    user.first_name = first_name
    user.last_name = last_name
    user.registration_method = registration_method
    user.registration_date = time()
    user.status = status
    user.activation_key = get_secure_rand_token()
    user.can_create_org = True
    user.save()

    # For some users registering through sso it might not be necessary to
    # create an organization, hence the flag
    org = create_org_for_user(user, '', promo_code, token, selected_plan) \
        if create_organization else None

    log_event_args = {
        'owner_id': org and org.id or '',
        'user_id': user.id,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'company': user.feedback.company_name,
        'event_type': 'request',
        'action': 'register',
        'authentication_provider': registration_method
    }

    if request:
        log_event_args.update({
            'request_method': request.method,
            'request_path': request.path,
            'request_ip': ip_from_request(request),
            'user_agent': request.user_agent,
        })

    if org:
        log_event_args.update({
            'org_id': org.id,
            'org_name': org.name
        })

    # Create log for the registration of a user and if an org has been created
    # add the id and name of the org
    from mist.api.logs.methods import log_event
    log_event(**log_event_args)

    return user, org


def create_org_for_user(user, org_name='', promo_code=None, token=None,
                        selected_plan=None):
    org = Organization(name=org_name, selected_plan=selected_plan)
    org.add_member_to_team('Owners', user)
    org.name = org_name
    try:
        org.save()
    except ValidationError as e:
        raise BadRequestError({"msg": str(e), "errors": e.to_dict()})
    except OperationError:
        raise OrganizationOperationError()

    # assign promo if applicable
    if promo_code or token:
        if config.HAS_BILLING:
            from mist.billing.methods import assign_promo
            assign_promo(org, promo_code, token)
    return org


def get_user_data(auth_context):
    """
    This function sends user's data to socket
    :param auth_context:
    :return: dict
    """
    user = auth_context.user

    orgs = []
    for org in Organization.objects(members=user):
        o_dict = {
            'id': org.id,
            'name': org.name,
            'avatar': org.avatar,
            'members': len(org.members),
            'isOwner': user in org.get_team('Owners').members,
            'super_org': org.super_org
        }

        if org.super_org and Organization.objects(parent=org.id):
            sub_orgs = Organization.objects(parent=org.id)
            for sub_org in sub_orgs:
                sub = {
                    'id': sub_org.id,
                    'parent_id': sub_org.parent.id,
                    'name': sub_org.name,
                    'members': len(sub_org.members),
                    'isOwner': user in org.get_team('Owners').members,
                }
                orgs.append(sub)

        orgs.append(o_dict)

    ret = {
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'username': user.username,
        'ips': [ip.as_dict() for ip in user.ips],
        'current_ip': auth_context.token.ip_address,
        'has_pass': user.password is not None and user.password != '',
        'orgs': orgs,
        'csrf_token': auth_context.token.csrf_token,
    }
    if user.role == 'Admin':
        upgrades = Portal.get_singleton().get_available_upgrades()
        ret['available_upgrades'] = upgrades
    if config.HAS_BILLING:
        ret.update({
            'stripe_public_apikey': config.STRIPE_PUBLIC_APIKEY,
        })
    return ret


def filter_org(auth_context):
    org_dict = auth_context.org.as_dict()
    owner_policy = config.OWNER_POLICY
    rules = []
    for resource in owner_policy.keys():
        for action in owner_policy[resource].keys():
            tags, constraints = owner_policy[resource][action]
            rule = {"operator": "ALLOW", "action": action, "rtype": resource,
                    "rtags": tags, "constraints": constraints}
            rules.append(rule)

    org_dict['owner_policy'] = {"rules": rules, "operator": "ALLOW"}
    org_dict['is_owner'] = auth_context.is_owner()

    # SEC return my teams + visible teams or all teams if owner
    teams = [team for team in org_dict['teams']
             if team['visible'] or
             auth_context.user.id in team['members'] or
             auth_context.is_owner()]

    # Get info about members in my teams or of all org if owner
    team_mates = set()
    for t in teams:
        for m in t['members']:
            team_mates.add(m)

    members = [m for m in org_dict['members']
               if auth_context.is_owner() or m['id'] in team_mates]
    org_dict['teams'] = teams
    org_dict['members'] = members
    # Billing info
    if config.HAS_BILLING:
        from mist.billing.methods import populate_billing_info
        org_dict.update(populate_billing_info(auth_context.org))

    return org_dict


def update_whitelist_ips(auth_context, ips):
    """
    This function takes a list of dicts in the form:
    [{cidr:'cidr1', 'description:'desc1'},
    {cidr:'cidr2', 'description:'desc2'}]
    and saves them in the User.ips field.
    """

    user = auth_context.user

    user.ips = []
    for ip_dict in ips:
        wip = WhitelistIP()
        wip.cidr = ip_dict['cidr']
        wip.description = ip_dict['description']
        user.ips.append(wip)

    try:
        user.save()
    except ValidationError as e:
        raise BadRequestError({"msg": str(e), "errors": e.to_dict()})


def purge_org(org):
    from mist.api.clouds.models import Cloud
    from mist.api.clouds.methods import purge_cloud
    from mist.api.keys.models import Key
    from mist.api.scripts.models import Script
    from mist.api.schedules.models import Schedule
    from mist.api.rules.models import Rule
    from mist.api.notifications.models import Notification
    from mist.api.notifications.models import UserNotificationPolicy
    from mist.api.poller.models import OwnerPollingSchedule
    rtypes = [
        Key, Script, Schedule, Rule, Notification, UserNotificationPolicy,
        OwnerPollingSchedule]
    try:
        from mist.orchestration.models import Stack, Template
        rtypes.append(Stack)
        rtypes.append(Template)
        from mist.vpn.models import Tunnel
        rtypes.append(Tunnel)
    except ImportError:
        pass
    clouds = Cloud.objects(owner=org)
    for cloud in clouds:
        print("Purging cloud %s" % cloud)
        purge_cloud(cloud.id)
        print("Done")
    for rtype in rtypes:
        try:
            rtype.objects(owner=org).delete()
        except InvalidQueryError:
            try:
                org_id = org.id
            except AttributeError:
                org_id = org
            rtype.objects(owner_id=org_id).delete()
    try:
        from mist.rbac.mappings import UserMapping, RBACMapping
        UserMapping.objects(org=org).delete()
        RBACMapping.objects(org=org).delete()
    except ImportError:
        pass
    org.delete()
