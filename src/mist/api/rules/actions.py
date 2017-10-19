import re
import mongoengine as me

from mist.api.config import BANNED_EMAIL_PROVIDERS


ACTIONS = {}  # This is a map of action types to action classes.


def _populate_actions():
    """Populate ACTIONS variable."""
    for key, value in globals().iteritems():
        if key.endswith('Action') and key != 'Action':
            if issubclass(value, BaseAlertAction) and value.atype is not None:
                ACTIONS[value.atype] = value


def is_email_valid(email):
    """E-mail address validator.

    Ensure the e-mail is a valid expression and the provider is not banned.

    """
    # TODO Move this to mist.api.helpers.
    regex = '(^[\w\.-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-.]+)+$)'
    return (re.match(regex, email) and
            email.split('@')[1] not in BANNED_EMAIL_PROVIDERS)


class BaseAlertAction(me.EmbeddedDocument):
    """The base class for all alert actions.

    This class serves as very basic, common interface amongst subclasses that
    define alert actions. Every subclass of the `BaseAlertAction` MUST define
    at least its own `run` method, which holds all the logic of the action's
    execution, and a descriptive `atype`.

    A rule may define a list of actions to be executed once it's triggered. The
    actions will be sequentially executed in the order they have been provided.

    """

    meta = {'allow_inheritance': True}

    atype = None

    def update(self, fail_on_error=True, **kwargs):
        for key, value in kwargs.iteritems():
            if key not in self._fields:
                if not fail_on_error:
                    continue
                raise me.ValidationError('Field "%s" does not exist on %s',
                                         key, type(self))
            setattr(self, key, value)

    def run(self):
        """Execute self.

        Subclasses MUST override this method.

        """
        raise NotImplementedError()

    def as_dict(self):
        return {'type': self.atype}


class NotificationAction(BaseAlertAction):
    """An action that notifies the users, once a rule has been triggered."""

    # TODO Use the Notifications system.
    # TODO Concat owner.alerts_email in here.

    atype = 'notification'

    emails = me.ListField(me.StringField(), default=lambda: [])

    def clean(self):
        """Perform e-mail address validation."""
        emails = []
        for email in self.emails:
            if is_email_valid(email) and email not in emails:
                emails.append(email)
        self.emails = emails

    def as_dict(self):
        return {'type': self.atype, 'emails': self.emails}


class CommandAction(BaseAlertAction):
    """Execute a remote command."""

    # TODO: Deprecate in favor of a ScriptAction?

    atype = 'command'

    command = me.StringField(required=True)

    def as_dict(self):
        return {'type': self.atype, 'command': self.command}


class MachineAction(BaseAlertAction):
    """Perform a machine action."""

    atype = 'machine_action'

    action = me.StringField(required=True, choices=('reboot', 'destroy'))

    def as_dict(self):
        return {'type': self.atype, 'action': self.action}


_populate_actions()
