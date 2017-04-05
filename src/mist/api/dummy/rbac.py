import mist.api.users.models
import mist.api.auth.models
import mist.api.tag.models


class AuthContext(object):
    def __init__(self, user, token):

        assert isinstance(user, mist.api.users.models.User)
        self.user = user

        assert isinstance(token, mist.api.auth.models.AuthToken)
        self.token = token

        assert (
            hasattr(token, 'org') and
            isinstance(token.org, mist.api.users.models.Organization)
        )
        self.org = token.org

        # For backwards compatibility.
        self.owner = self.org

    def is_owner(self):
        return self.user in self.org.teams.get(name='Owners').members

    def _raise(self, rtype, action, rid='', rtags=''):
        pass

    def check_perm(self, rtype, action, rid):
        return

    def get_security_tags(self):
        return []

    def get_allowed_resources(self, action='read', rtype=None):
        return {}

    def _get_matching_tags(self, rtype, action):
        return {}


def validate_rule_rid(rule, owner):
    return


def filter_org(auth_context):
    return


def rbac_filter(auth_context, query):
    return


def filter_logs(auth_context, kwargs):
    return
