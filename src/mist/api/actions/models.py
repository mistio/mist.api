import uuid
import time
import logging
import json
import requests
import mongoengine as me

from mist.api.helpers import is_email_valid
from mist.api.logs.methods import log_event
from mist.api.users.models import User


log = logging.getLogger(__name__)


ACTIONS = {}  # This is a map of action types to action classes.


def _populate_actions():
    """Populate ACTIONS variable."""
    for key, value in globals().items():
        if key.endswith('Action') and key != 'Action':
            if issubclass(value, BaseAction):
                if value.atype not in (None, 'no_data', ):  # Exclude these.
                    ACTIONS[value.atype] = value


class BaseAction(me.EmbeddedDocument):
    """The base class for all actions.

    This class serves as very basic, common interface amongst subclasses that
    define actions. Every subclass of the `BaseAction` MUST define
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

    @property
    def task(self):
        raise NotImplementedError()

    @property
    def args(self):
        raise NotImplementedError()

    @property
    def kwargs(self):
        raise NotImplementedError()

    def as_dict(self):
        return {'type': self.atype}

    def __str__(self):
        return '%s %s' % (self.__class__.__name__, self.id)


class ActionClassMixin(object):
    """Generic action mixin class used as a handler for different
    query sets for a specific collection. It constructs a query from
    a list of query sets which chains together with logical & operator."""

    actions = me.EmbeddedDocumentListField(BaseAction)

    def owner_query(self):
        return me.Q(owner=self.org_id)


class NotificationAction(BaseAction):
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
            assert resource.org == self._instance.org
        else:
            assert self._instance.is_arbitrary()

        emails = set(self.emails)
        user_ids = set(self.users)
        if not (self.users or self.teams):
            emails |= set(self._instance.org.get_emails())
            emails |= set(self._instance.org.alerts_email)
        if user_ids:
            user_ids &= set([m.id for m in self._instance.org.members])
        for user in User.objects(id__in=user_ids):
            emails.add(user.email)
        for team_id in self.teams:
            try:
                team = self._instance.org.teams.get(id=team_id)
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

    @property
    def args(self):
        return {'emails': self.emails, 'users': self.users,
                'teams': self.teams, 'level': self.level}

    @property
    def kwargs(self):
        return {'description': self.description}

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
                               machine.id, no_ssh=True)
            log_event(
                machine.owner.id, 'incident', 'disable_monitoring',
                cloud_id=machine.cloud.id, machine_id=machine.id,
                external_id=machine.external_id, incident_id=incident_id
            )
            action = 'Disable Monitoring'
        else:
            action = 'Alert'
        super(NoDataAction, self).run(machine, value, triggered, timestamp,
                                      incident_id, action)

    @property
    def args(self):
        return {}

    @property
    def kwargs(self):
        return {}


class CommandAction(BaseAction):
    """Execute a remote command."""

    atype = 'command'

    command = me.StringField(required=True)

    def run(self, machine, *args, **kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.methods import ssh_command
        from mist.api.machines.models import Machine
        assert isinstance(machine, Machine)
        assert machine.owner == self._instance.org
        return ssh_command(machine.owner, machine.cloud.id,
                           machine.external_id,
                           machine.hostname, self.command)

    @property
    def task(self):
        return 'mist.api.tasks.group_run_script'

    @property
    def args(self):
        return self.command

    @property
    def kwargs(self):
        return {}

    def as_dict(self):
        return {'type': self.atype, 'command': self.command}


class ScriptAction(BaseAction):
    """Execute a remote script."""

    atype = 'script'

    script = me.ReferenceField('Script', required=True)
    params = me.StringField(required=True)

    def run(self, machine, *args, **kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api import tasks
        from mist.api.machines.models import Machine
        assert isinstance(machine, Machine)
        assert machine.owner == self._instance.org
        job_id = uuid.uuid4().hex
        job = 'run_script'
        tasks.run_script(None, self.script.id,
                         machine.id, params=self.params,
                         job_id=job_id, job=job,
                         owner_id=machine.owner.id)
        return {'job_id': job_id, 'job': job}

    @property
    def task(self):
        return 'mist.api.tasks.group_run_script'

    @property
    def args(self):
        return self.script.id

    @property
    def kwargs(self):
        return {'params': self.params}

    def as_dict(self):
        return {'type': self.atype, 'script': self.script.id,
                'params': self.params}


class WebhookAction(BaseAction):
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
        from mist.api.config import PORTAL_URI
        resource_type = getattr(self._instance, 'resource_model_name', 'org')
        if resource_type == 'org':
            resource_url = PORTAL_URI
        else:
            resource_url = '%s/%ss/%s' % (
                PORTAL_URI, resource_type, resource.id)
        if hasattr(resource, "name"):
            resource_name = resource.name
        elif hasattr(resource, "title"):
            resource_name = resource.title
        else:
            resource_name = 'unknown'
        if self.json:
            json_body = self.json.replace(
                "{resource_id}", getattr(resource, 'id', '')).replace(
                    "{resource_url}", resource_url).replace(
                        "{resource_name}", resource_name)
            json_body = json.loads(json_body)
        else:
            json_body = None
        if self.data:
            data = self.data.replace(
                "{resource_id}", getattr(resource, 'id', '')).replace(
                    "{resource_url}", resource_url).replace(
                        "{resource_name}", resource.name)
        else:
            data = None
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
            notify_user(self._instance.org, title, message=body)
            notify_admin(title + ' ' + self._instance.id, body)
        return {'status_code': response.status_code}

    @property
    def args(self):
        return {'method': self.method, 'url': self.url}

    @property
    def kwargs(self):
        return {'params': self.params, 'json': self.json,
                'headers': self.headers}

    def as_dict(self):
        return {'type': self.atype, 'method': self.method, 'url': self.url,
                'params': self.params, 'json': self.json,
                'headers': self.headers}


# Base Resource Action for better abstraction
# Machine, Cluster, Volume and Network actions inherit from this class
class BaseResourceAction(BaseAction):
    """The base class for resource actions.

    This class serves as an intermediate level between BaseAction
    and Resource Action implementations.

    """

    meta = {'allow_inheritance': True}

    atype = None

    id = me.StringField(required=True, default=lambda: uuid.uuid4().hex)

    def run(self):
        """Execute self.

        The body of the action to be executed. Subclasses MUST override this.

        """
        raise NotImplementedError()

    @property
    def task(self):
        raise NotImplementedError()

    @property
    def args(self):
        raise NotImplementedError()

    @property
    def kwargs(self):
        raise NotImplementedError()

    def as_dict(self):
        return {'type': self.atype}

    def __str__(self):
        return '%s %s' % (self.__class__.__name__, self.id)


class MachineAction(BaseResourceAction):
    """Perform a machine action."""

    atype = 'machine_action'

    action = me.StringField(required=True, choices=('start', 'stop',
                                                    'reboot', 'destroy',
                                                    'notify'))

    def run(self, machine, *args, **kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.machines.models import Machine
        assert isinstance(machine, Machine)
        assert machine.owner == self._instance.org
        getattr(machine.ctl, self.action)()
        if self.action == 'destroy':  # If destroy, disable monitoring, too.
            # FIXME Imported here due to circular dependency issues.
            from mist.api.monitoring.methods import disable_monitoring
            # TODO Move this into machine.ctl.destroy method and
            # deprecate mist.api.machines.methods:destroy_machine.
            # Could also be implemented as new method inside the
            # MachineController.
            disable_monitoring(machine.owner, machine.cloud.id,
                               machine.id, no_ssh=True)

    @property
    def task(self):
        return 'mist.api.tasks.group_resources_actions'

    @property
    def args(self):
        return self.action

    @property
    def kwargs(self):
        return {}

    def as_dict(self):
        return {'type': self.atype, 'action': self.action}


class VolumeAction(BaseResourceAction):
    """Perform a volume action."""

    atype = 'volume_action'

    action = me.StringField(required=True, choices=('delete'))

    def run(self, volume, *args, **kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.volumes.models import Volume
        assert isinstance(volume, Volume)
        assert volume.owner == self._instance.org
        getattr(volume.ctl, self.action)()

    @property
    def task(self):
        return 'mist.api.tasks.group_resources_actions'

    @property
    def args(self):
        return self.action

    @property
    def kwargs(self):
        return {}

    def as_dict(self):
        return {'type': self.atype, 'action': self.action}


class ClusterAction(BaseResourceAction):
    """Perform a cluster action."""

    atype = 'cluster_action'

    action = me.StringField(required=True, choices=('delete'))

    def run(self, cluster, *args, **kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.containers.models.Cluster import Cluster
        assert isinstance(cluster, Cluster)
        assert cluster.owner == self._instance.org
        getattr(cluster.ctl, self.action)()

    @property
    def task(self):
        return 'mist.api.tasks.group_resources_actions'

    @property
    def args(self):
        return self.action

    @property
    def kwargs(self):
        return {}

    def as_dict(self):
        return {'type': self.atype, 'action': self.action}


class NetworkAction(BaseResourceAction):
    """Perform a network action."""

    atype = 'network_action'

    action = me.StringField(required=True, choices=('delete'))

    def run(self, network, *args, **kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.networks.models import Network
        assert isinstance(network, Network)
        assert network.owner == self._instance.org
        getattr(network.ctl, self.action)()

    @property
    def task(self):
        return 'mist.api.tasks.group_resources_actions'

    @property
    def args(self):
        return self.action

    @property
    def kwargs(self):
        return {}

    def as_dict(self):
        return {'type': self.atype, 'action': self.action}


_populate_actions()
