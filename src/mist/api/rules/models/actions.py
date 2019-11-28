import uuid
import time
import logging
import json
import requests
import mongoengine as me

from mist.api.helpers import is_email_valid
from mist.api.logs.methods import log_event
from mist.api.users.models import User
from mist.api.machines.models import Machine


log = logging.getLogger(__name__)


ACTIONS = {}  # This is a map of action types to action classes.


def _populate_actions():
    """Populate ACTIONS variable."""
    for key, value in globals().items():
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
        for key, value in kwargs.items():
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
    level = me.StringField(default='warning', choices=(
        'info', 'warning', 'critical'))
    description = me.StringField(required=False, default='')

    def run(self, resource, value, triggered, timestamp, incident_id,
            action=''):
        # Validate `resource` based on the rule's type. The `resource` must
        # be a me.Document subclass, if the corresponding rule is resource-
        # bound, otherwise None.
        if resource is not None:
            assert isinstance(resource, me.Document)
            assert resource.owner == self._instance.owner
        else:
            assert self._instance.is_arbitrary()

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

        # FIXME Imported here due to circular dependency issues.
        from mist.api.notifications.methods import send_alert_email
        send_alert_email(self._instance, resource, incident_id, value,
                         triggered, timestamp, emails, action=action,
                         level=self.level, description=self.description)

    def clean(self):
        """Perform e-mail address validation."""
        for email in self.emails:
            if not is_email_valid(email):
                raise me.ValidationError('Invalid e-mail address: %s' % email)

    def as_dict(self):
        return {'type': self.atype, 'emails': self.emails,
                'users': self.users, 'teams': self.teams,
                'level': self.level, 'description': self.description}


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
                cloud_id=machine.cloud.id, machine_id=machine.id,
                external_id=machine.machine_id, incident_id=incident_id
            )
            action = 'Disable Monitoring'
        else:
            action = 'Alert'
        super(NoDataAction, self).run(machine, value, triggered, timestamp,
                                      incident_id, action)


class CommandAction(BaseAlertAction):
    """Execute a remote command."""

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


class ScriptAction(BaseAlertAction):
    """Execute a remote script."""

    atype = 'script'

    script = me.ReferenceField('Script', required=True)
    params = me.StringField(required=True)

    def run(self, machine, *args, **kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api import tasks
        assert isinstance(machine, Machine)
        assert machine.owner == self._instance.owner
        job_id = uuid.uuid4().hex
        job = 'run_script'
        tasks.run_script(machine.owner.id, self.script.id,
                         machine.id, params=self.params,
                         job_id=job_id, job=job)
        return {'job_id': job_id, 'job': job}

    def as_dict(self):
        return {'type': self.atype, 'script': self.script.id,
                'params': self.params}


class WebhookAction(BaseAlertAction):
    """Perform an HTTP request."""

    atype = 'webhook'

    method = me.StringField(required=True, default='post', choices=(
        'post', 'delete', 'put', 'patch'))
    url = me.StringField(required=True)
    params = me.StringField(required=False)
    data = me.StringField(required=False)
    json = me.StringField(required=False)
    headers = me.StringField(required=False)

    def clean(self):
        if self.json:
            try:
                json.loads(self.json)
            except json.decoder.JSONDecodeError as e:
                raise me.ValidationError(
                    "Invalid JSON payload: %s" % e.args[0]
                )
        if self.headers:
            try:
                json.loads(self.headers)
            except json.decoder.JSONDecodeError as e:
                raise me.ValidationError(
                    "HTTP Headers should be defined as a valid "
                    "JSON dictionary: %s" % e.args[0]
                )

    def run(self, resource, *args, **kwargs):
        from mist.api.config import CORE_URI
        resource_type = self._instance.resource_model_name
        resource_url = resource_type and '%s/%ss/%s' % (
            CORE_URI, resource_type, resource.id) or CORE_URI
        if hasattr(resource, "name"):
            resource_name = resource.name
        elif hasattr(resource, "title"):
            resource_name = resource.title
        else:
            resource_name = 'unknown'
        if self.json:
            json_body = self.json.replace(
                "{resource_id}", resource.id).replace(
                    "{resource_url}", resource_url).replace(
                        "{resource_name}", resource_name)
            json_body = json.loads(json_body)
        else:
            json_body = None
        data = self.data.replace("{resource_id}", resource.id).replace(
            "{resource_url}", resource_url).replace("{resource_name}",
                                                    resource.name)
        headers = json.loads(self.headers) if self.headers else None
        response = requests.request(
            self.method, self.url, params=self.params, data=data,
            json=json_body, headers=headers)

        # Notify user & admin if response indicates an error
        if not response.ok:
            title = "Webhook for rule `%s` responded with http code `%d`" % (
                self._instance.title, response.status_code)
            try:
                body = "URL: %s\n Response body: %s\n" % (
                    self.url, str(response.json()))
            except json.JSONDecodeError:
                body = "URL: %s\n Response body: %s\n" % (
                    self.url, response.text)
            log.info("%s - %s - %s", title, self._instance.id, body)
            from mist.api.methods import notify_user, notify_admin
            notify_user(self._instance.owner, title, message=body)
            notify_admin(title + ' ' + self._instance.id, body)
        return {'status_code': response.status_code}

    def as_dict(self):
        return {'type': self.atype, 'method': self.method, 'url': self.url,
                'params': self.params, 'json': self.json,
                'headers': self.headers}


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
