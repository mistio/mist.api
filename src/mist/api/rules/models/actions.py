import re
import uuid
import time
import logging
import mongoengine as me

from mist.api import config
from mist.api.helpers import is_email_valid
from mist.api.logs.methods import log_event
from mist.api.users.models import User
from mist.api.machines.models import Machine


log = logging.getLogger(__name__)


ACTIONS = {}  # This is a map of action types to action classes.


def _populate_actions():
    """Populate ACTIONS variable."""
    for key, value in globals().iteritems():
        if key.endswith('Action') and key != 'Action':
            if issubclass(value, BaseAlertAction):
                if value.atype not in (None, 'no_data', ):  # Exclude these.
                    ACTIONS[value.atype] = value


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

    id = me.StringField(required=True, default=lambda: uuid.uuid4().hex)

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

        The body of the action to be executed. Subclasses MUST override this.

        """
        raise NotImplementedError()

    def as_dict(self):
        return {'type': self.atype}

    def __str__(self):
        return '%s %s' % (self.__class__.__name__, self.id)


class NotificationAction(BaseAlertAction):
    """An action that notifies the users, once a rule has been triggered."""

    atype = 'notification'

    users = me.ListField(me.StringField(), default=lambda: [])
    teams = me.ListField(me.StringField(), default=lambda: [])
    emails = me.ListField(me.StringField(), default=lambda: [])

    def run(self, machine, value, triggered, timestamp, incident_id, action='',
            notification_level=0):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.notifications.methods import send_alert_email
        # TODO Shouldn't be specific to machines.
        assert isinstance(machine, Machine)
        assert machine.owner == self._instance.owner
        emails = set(self.emails)
        user_ids = set(self.users)
        if not (self.users or self.teams):
            emails |= set(self._instance.owner.get_emails())
            emails |= set(self._instance.owner.alerts_email)
        if user_ids:
            user_ids &= set([m.id for m in self._instance.owner.members])
        for user in User.objects(id__in=user_ids):
            emails.add(user.email)
        for team_id in self.teams:
            try:
                team = self._instance.owner.teams.get(id=team_id)
                emails |= set([member.email for member in team.members])
            except me.DoesNotExist:
                continue
        send_alert_email(machine.owner, self._instance.id, value,
                         triggered, timestamp, incident_id, emails,
                         cloud_id=machine.cloud.id,
                         machine_id=machine.machine_id, action=action)

    def clean(self):
        """Perform e-mail address validation."""
        for email in self.emails:
            if not is_email_valid(email):
                raise me.ValidationError('Invalid e-mail address: %s' % email)

    def as_dict(self):
        return {'type': self.atype, 'emails': self.emails,
                'users': self.users, 'teams': self.teams}


class NoDataAction(NotificationAction):
    """An action triggered in case of a NoData alert."""

    atype = 'no_data'

    def run(self, machine, value, triggered, timestamp, incident_id, **kwargs):
        if timestamp + 60 * 60 * 24 < time.time():
            # FIXME Imported here due to circular dependency issues.
            from mist.api.monitoring.methods import disable_monitoring
            # If NoData alerts are being triggered for over 24h, disable
            # monitoring and log the action to close any open incidents.
            disable_monitoring(machine.owner, machine.cloud.id,
                               machine.machine_id, no_ssh=True)
            log_event(
                machine.owner.id, 'incident', 'disable_monitoring',
                cloud_id=machine.cloud.id, machine_id=machine.machine_id,
                incident_id=incident_id
            )
            action = 'Disable Monitoring'
            notification_level = 0
        else:
            action = 'Alert'
            notification_level = kwargs.get('notification_level', 0)
        super(NoDataAction, self).run(machine, value, triggered, timestamp,
                                      incident_id, action, notification_level)


class CommandAction(BaseAlertAction):
    """Execute a remote command."""

    # TODO: Deprecate in favor of a ScriptAction?

    atype = 'command'

    command = me.StringField(required=True)

    def run(self, machine, *args, **kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.methods import ssh_command
        assert isinstance(machine, Machine)
        assert machine.owner == self._instance.owner
        return ssh_command(machine.owner, machine.cloud.id, machine.machine_id,
                           machine.hostname, self.command)

    def as_dict(self):
        return {'type': self.atype, 'command': self.command}


class MachineAction(BaseAlertAction):
    """Perform a machine action."""

    atype = 'machine_action'

    action = me.StringField(required=True, choices=('reboot', 'destroy'))

    def run(self, machine, *args, **kwargs):
        assert isinstance(machine, Machine)
        assert machine.owner == self._instance.owner
        getattr(machine.ctl, self.action)()
        if self.action == 'destroy':  # If destroy, disable monitoring, too.
            # FIXME Imported here due to circular dependency issues.
            from mist.api.monitoring.methods import disable_monitoring
            # TODO Move this into machine.ctl.destroy method and
            # deprecate mist.api.machines.methods:destroy_machine.
            # Could also be implemented as new method inside the
            # MachineController.
            disable_monitoring(machine.owner, machine.cloud.id,
                               machine.machine_id, no_ssh=True)

    def as_dict(self):
        return {'type': self.atype, 'action': self.action}


_populate_actions()
