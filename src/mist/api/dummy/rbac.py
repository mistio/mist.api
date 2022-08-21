import logging

import mist.api.users.models
import mist.api.auth.models
import mist.api.tag.models


log = logging.getLogger(__name__)


class AuthContext(object):
    def __init__(self, user, token, org=None):

        assert isinstance(user, mist.api.users.models.User)
        self.user = user

        assert isinstance(token, mist.api.auth.models.AuthToken)
        self.token = token

        if not token.orgs:
            self.org = None
        elif org in token.orgs:
            self.org = org
        else:
            for o in token.orgs:
                if org == o.id or org == o.name:
                    self.org = o
                    break
            else:
                self.org = token.orgs[0]

        # For backwards compatibility.
        self.owner = self.org

    def is_owner(self):
        return True

    def _raise(self, rtype, action, rid='', rtags=''):
        pass

    def check_perm(self, rtype, action, rid):
        return {}, {}

    def get_security_tags(self):
        return []

    def get_allowed_resources(self, action='read', rtype=None):
        return {}

    def _get_matching_tags(self, rtype, action):
        return {}

    def _get_matching_constraints(self, rtype, action):
        return {}

    def serialize(self):
        """This returns the basic context info in a dict of strings and can
        safely be passed to dramatiq tasks etc. To recreate the context, just
        feed it to AuthContext.deserialize"""
        return {
            'user_id': self.user.id,
            'token_id': str(self.token.id) if self.token is not None else None,
        }

    @staticmethod
    def deserialize(serialized):
        if not isinstance(serialized, dict):
            raise TypeError("Expected serialized AuthContext as dict, "
                            "got %r instead." % serialized)
        user_id = serialized.get('user_id')
        token_id = serialized.get('token_id')
        user = mist.api.users.models.User.objects.get(id=user_id)
        if token_id:
            token = mist.api.auth.models.AuthToken.objects.get(id=token_id)
        else:
            token = None
        return AuthContext(user, token)


def filter_logs(auth_context, kwargs):
    log.warning('Call to dummy.filter_logs')
    return
