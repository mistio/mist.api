import logging
from time import time

from mist.api.users.models import User
from mist.api.users.models import Organization

from mongoengine import ValidationError
from mongoengine import OperationError

from mist.api.auth.models import get_secure_rand_token

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import MethodNotAllowedError
from mist.api.exceptions import OrganizationOperationError

from mist.api import config

try:
    from mist.core.methods import assign_promo
except ImportError:
    from mist.api.dummy.methods import assign_promo

log = logging.getLogger(__name__)


def get_users_count(mongo_uri=None, confirmed=False):
    # return the number of all users, optionally confirmed only users
    if confirmed:
        return User.objects(status="confirmed").count()
    else:
        return User.objects().count()


def register_user(email, first_name, last_name, registration_method,
                  selected_plan=None, promo_code=None, token=None,
                  status='pending', create_organization=True):
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

    log_event_args = {
        'owner_id': '',
        'user_id': user.id,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'company': user.feedback.company_name,
        'event_type': 'request',
        'action': 'register',
        'authentication_provider': registration_method
    }

    # For some users registering through sso it might not be necessary to
    # create an organization, hence the flag
    org = create_org_for_user(user, '', promo_code, token, selected_plan) \
        if create_organization else None

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
        raise BadRequestError({"msg": e.message, "errors": e.to_dict()})
    except OperationError:
        raise OrganizationOperationError()

    # assign promo if applicable
    if promo_code or token:
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
            'members': len(org.members),
            'isOwner': user in org.get_team('Owners').members,
            'super_org': org.super_org
        }

        if org.super_org and Organization.objects(parent=org.id):
            sub_orgs = Organization.objects(parent=org.id)
            subs = []
            for sub_org in sub_orgs:
                subs.append({
                'sub_org': sub_org.parent.id,
                'sub_org_name': sub_org.parent.name
                })
            o_dict.update({'sub_orgs': subs})

        orgs.append(o_dict)

    ret = {
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'username': user.username,
        'has_pass': user.password is not None and user.password != '',
        'orgs': orgs,
        'csrf_token': auth_context.token.csrf_token,
    }
    return ret


def filter_org(auth_context):
    org = auth_context.org.as_dict()
    org['is_owner'] = auth_context.is_owner()

    # SEC return my teams + visible teams or all teams if owner
    teams = [team for team in org['teams']
             if team['visible'] or
             auth_context.user.id in team['members'] or
             auth_context.is_owner()]

    # Get info about members in my teams or of all org if owner
    team_mates = set()
    for t in teams:
        for m in t['members']:
            team_mates.add(m)

    members = [m for m in org['members']
               if auth_context.is_owner() or m['id'] in team_mates]
    org['teams'] = teams
    org['members'] = members

    return org
