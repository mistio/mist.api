"""Machine entity model."""
import os
import json
import uuid
import logging
import datetime
import mongoengine as me

import mist.api.tag.models
from mist.api.keys.models import Key
from mist.api.machines.controllers import MachineController

from mist.api import config


log = logging.getLogger(__name__)


class KeyAssociation(me.EmbeddedDocument):
    keypair = me.ReferenceField(Key)
    last_used = me.IntField(default=0)
    ssh_user = me.StringField()
    sudo = me.BooleanField()
    port = me.IntField(default=22)

    def as_dict(self):
        return json.loads(self.to_json())


class InstallationStatus(me.EmbeddedDocument):
    # automatic: refers to automatic installations from mist.core
    # manual: refers to manual deployments and everything from
    #         standalone mist.api

    # automatic:
    # - preparing: Set on first API call before everything else
    # - pending: Enabled on mist.monitor, submitted celery task
    # - installing: Celery task running
    # - failed: Ansible job failed (also set finished_at)
    # - succeeded: Ansible job succeeded (also set finished_at)
    # manual:
    # - preparing: Same as for automatic
    # - installing: Enabled on mist.monitor,
    #               returned command for manual install
    # - succeeded: Set when activated_at is set (see below)
    state = me.StringField()
    # True only for mist.core automatic installations
    manual = me.BooleanField()

    activated_at = me.IntField()  # Data for period after started_at received

    started_at = me.IntField()  # timestamp: First enable_monitoring API call

    # following apply only for automatic:
    finished_at = me.IntField()  # Ansible job completed (also set state)
    stdout = me.StringField()  # Ansible job captured stdout/stderr mux streams
    error_msg = me.StringField()

    def as_dict(self):
        return json.loads(self.to_json())


class Actions(me.EmbeddedDocument):
    start = me.BooleanField(default=False)
    stop = me.BooleanField(default=False)
    reboot = me.BooleanField(default=False)
    destroy = me.BooleanField(default=False)
    resize = me.BooleanField(default=False)
    rename = me.BooleanField(default=False)
    remove = me.BooleanField(default=False)
    tag = me.BooleanField(default=False)
    resume = me.BooleanField(default=False)
    suspend = me.BooleanField(default=False)
    undefine = me.BooleanField(default=False)


class Monitoring(me.EmbeddedDocument):
    # Most of these will change with the new UI.
    hasmonitoring = me.BooleanField()
    monitor_server = me.StringField()  # Deprecated
    collectd_password = me.StringField(
        default=lambda: os.urandom(32).encode('hex'))
    metrics = me.ListField()  # list of metric_id's
    installation_status = me.EmbeddedDocumentField(InstallationStatus)
    method = me.StringField(default=config.DEFAULT_MONITORING_METHOD,
                            choices=config.MONITORING_METHODS)

    def get_commands(self):
        if self.method == 'collectd-graphite' and config.HAS_CORE:
            from mist.api.methods import get_deploy_collectd_command_unix
            from mist.api.methods import get_deploy_collectd_command_windows
            from mist.api.methods import get_deploy_collectd_command_coreos
            args = (self._instance.id, self.collectd_password,
                    config.COLLECTD_HOST, config.COLLECTD_PORT)
            return {
                'unix': get_deploy_collectd_command_unix(*args),
                'coreos': get_deploy_collectd_command_coreos(*args),
                'windows': get_deploy_collectd_command_windows(*args),
            }
        elif self.method in ('telegraf-influxdb', 'telegraf-graphite'):
            from mist.api.monitoring.commands import unix_install
            from mist.api.monitoring.commands import coreos_install
            from mist.api.monitoring.commands import windows_install
            return {
                'unix': unix_install(self._instance),
                'coreos': coreos_install(self._instance),
                'windows': windows_install(self._instance),
            }
        else:
            raise Exception("Invalid monitoring method %s" % self.method)

    def get_rules_dict(self):
        m = self._instance
        return {rid: rdict
                for rid, rdict in m.cloud.owner.get_rules_dict().items()
                if rdict['cloud'] == m.cloud.id and
                rdict['machine'] == m.machine_id}

    def as_dict(self):
        status = self.installation_status
        try:
            commands = self.get_commands()
        except:
            commands = {}
        return {
            'hasmonitoring': self.hasmonitoring,
            'monitor_server': config.COLLECTD_HOST,
            'collectd_password': self.collectd_password,
            'metrics': self.metrics,
            'installation_status': status.as_dict() if status else '',
            'commands': commands,
            'method': self.method,
        }


class Cost(me.EmbeddedDocument):
    hourly = me.FloatField(default=0)
    monthly = me.FloatField(default=0)

    def as_dict(self):
        return json.loads(self.to_json())


class PingProbe(me.EmbeddedDocument):
    packets_tx = me.IntField()
    packets_rx = me.IntField()
    packets_loss = me.FloatField()
    packet_duplicate = me.FloatField(default=0.0)
    rtt_min = me.FloatField()
    rtt_max = me.FloatField()
    rtt_avg = me.FloatField()
    rtt_std = me.FloatField()
    updated_at = me.DateTimeField()
    unreachable_since = me.DateTimeField()
    meta = {'strict': False}

    def update_from_dict(self, data):
        for key in data:
            setattr(self, key, data[key])
        self.updated_at = datetime.datetime.now()
        if self.packets_loss == 100:
            self.unreachable_since = datetime.datetime.now()
        else:
            self.unreachable_since = None

    def as_dict(self):
        data = {key: getattr(self, key) for key in (
            'packets_tx', 'packets_rx', 'packets_loss',
            'rtt_min', 'rtt_max', 'rtt_avg', 'rtt_std', 'updated_at',
            'unreachable_since',
        )}
        # Handle datetime objects
        for key in ('updated_at', 'unreachable_since'):
            if data[key]:
                data[key] = str(data[key].replace(tzinfo=None))
        return data


class SSHProbe(me.EmbeddedDocument):
    uptime = me.FloatField()  # seconds
    loadavg = me.ListField(me.FloatField())
    cores = me.IntField()
    users = me.IntField()
    pub_ips = me.ListField(me.StringField())
    priv_ips = me.ListField(me.StringField())
    macs = me.ListField(me.StringField())
    df = me.StringField()
    kernel = me.StringField()
    os = me.StringField()
    os_version = me.StringField()
    dirty_cow = me.BooleanField()
    updated_at = me.DateTimeField()
    unreachable_since = me.DateTimeField()
    meta = {'strict': False}

    def update_from_dict(self, data):

        uptime = data.get('uptime')
        try:
            self.uptime = float(uptime)
        except (ValueError, TypeError):
            log.error("Invalid uptime value: %s", uptime)
            self.uptime = 0

        loadavg = data.get('loadavg')
        try:
            assert isinstance(loadavg, list)
            assert len(loadavg) == 3
            for i in range(3):
                loadavg[i] = float(loadavg[i])
            self.loadavg = loadavg
        except Exception as exc:
            log.error("Invalid loadavg '%s': %r", loadavg, exc)
            self.loadavg = []

        for int_attr in ('cores', 'users'):
            val = data.get(int_attr)
            try:
                setattr(self, int_attr, int(val))
            except Exception as exc:
                log.error("Invalid %s '%s': %r", int_attr, val, exc)
                setattr(self, int_attr, 0)

        for strarr_attr in ('pub_ips', 'priv_ips', 'macs'):
            val = data.get(strarr_attr)
            try:
                assert isinstance(val, list)
                assert all(isinstance(item, basestring) for item in val)
                setattr(self, strarr_attr, val)
            except Exception as exc:
                log.error("Invalid %s '%s': %r", strarr_attr, val, exc)
                setattr(self, strarr_attr, [])

        for str_attr in ('df', 'kernel', 'os', 'os_version'):
            setattr(self, str_attr, str(data.get(str_attr, '')))

        self.dirty_cow = bool(data.get('dirty_cow'))
        self.unreachable_since = None
        self.updated_at = datetime.datetime.now()

    def as_dict(self):
        data = {key: getattr(self, key) for key in (
            'uptime', 'loadavg', 'cores', 'users', 'pub_ips', 'priv_ips', 'df',
            'macs', 'kernel', 'os', 'os_version', 'dirty_cow', 'updated_at',
            'unreachable_since',
        )}
        # Handle datetime objects
        for key in ('updated_at', 'unreachable_since'):
            if data[key]:
                data[key] = str(data[key].replace(tzinfo=None))
        return data


class Machine(me.Document):
    """The basic machine model"""

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)

    cloud = me.ReferenceField('Cloud', required=True)
    owner = me.ReferenceField('Organization', required=True)
    name = me.StringField()

    # Info gathered mostly by libcloud (or in some cases user input).
    # Be more specific about what this is.
    # We should perhaps come up with a better name.
    machine_id = me.StringField(required=True)
    hostname = me.StringField()
    public_ips = me.ListField()
    private_ips = me.ListField()
    ssh_port = me.IntField(default=22)
    OS_TYPES = ('windows', 'coreos', 'freebsd', 'linux', 'unix')
    os_type = me.StringField(default='unix', choices=OS_TYPES)
    rdp_port = me.IntField(default=3389)
    actions = me.EmbeddedDocumentField(Actions, default=lambda: Actions())
    extra = me.DictField()
    cost = me.EmbeddedDocumentField(Cost, default=lambda: Cost())
    image_id = me.StringField()
    size = me.StringField()
    # libcloud.compute.types.NodeState
    state = me.StringField(default='unknown',
                           choices=('running', 'starting', 'rebooting',
                                    'terminated', 'pending', 'unknown',
                                    'stopping', 'stopped', 'suspended',
                                    'error', 'paused', 'reconfiguring'))
    machine_type = me.StringField(default='machine',
                                  choices=('machine', 'vm', 'container',
                                           'hypervisor', 'container-host'))
    parent = me.ReferenceField('Machine', required=False)

    # We should think this through a bit.
    key_associations = me.EmbeddedDocumentListField(KeyAssociation)

    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    unreachable_since = me.DateTimeField()
    created = me.DateTimeField()

    monitoring = me.EmbeddedDocumentField(Monitoring,
                                          default=lambda: Monitoring())

    ssh_probe = me.EmbeddedDocumentField(SSHProbe, required=False)
    ping_probe = me.EmbeddedDocumentField(PingProbe, required=False)

    meta = {
        'collection': 'machines',
        'indexes': [
            {
                'fields': ['cloud', 'machine_id'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ],
        'strict': False,
    }

    def __init__(self, *args, **kwargs):
        super(Machine, self).__init__(*args, **kwargs)
        self.ctl = MachineController(self)

    def clean(self):
        # Remove any KeyAssociation, whose `keypair` has been deleted. Do NOT
        # perform an atomic update on self, but rather remove items from the
        # self.key_associations list by iterating over it and popping matched
        # embedded documents in order to ensure that the most recent list is
        # always processed and saved.
        for ka in reversed(range(len(self.key_associations))):
            if self.key_associations[ka].keypair.deleted:
                self.key_associations.pop(ka)
        # Populate owner field based on self.cloud.owner
        if not self.owner:
            self.owner = self.cloud.owner
        self.clean_os_type()

    def clean_os_type(self):
        """Clean self.os_type"""
        if self.os_type not in self.OS_TYPES:
            for os_type in self.OS_TYPES:
                if self.os_type.lower() == os_type:
                    self.os_type = os_type
                    break
            else:
                self.os_type = 'unix'

    def delete(self):
        super(Machine, self).delete()
        mist.api.tag.models.Tag.objects(resource=self).delete()
        try:
            self.owner.mapper.remove(self)
        except (AttributeError, me.DoesNotExist) as exc:
            log.error(exc)

    def as_dict(self):
        # Return a dict as it will be returned to the API

        # tags as a list return for the ui
        tags = {tag.key: tag.value for tag in mist.api.tag.models.Tag.objects(
            owner=self.cloud.owner, resource=self
        ).only('key', 'value')}
        # Optimize tags data structure for js...
        if isinstance(tags, dict):
            tags = [{'key': key, 'value': value}
                    for key, value in tags.iteritems()]
        return {
            'id': self.id,
            'hostname': self.hostname,
            'public_ips': self.public_ips,
            'private_ips': self.private_ips,
            'name': self.name,
            'ssh_port': self.ssh_port,
            'os_type': self.os_type,
            'rdp_port': self.rdp_port,
            'machine_id': self.machine_id,
            'actions': {action: self.actions[action]
                        for action in self.actions},
            'extra': self.extra,
            'cost': self.cost.as_dict(),
            'image_id': self.image_id,
            'size': self.size,
            'state': self.state,
            'tags': tags,
            'monitoring': self.monitoring.as_dict() if self.monitoring else '',
            'key_associations': [ka.as_dict() for ka in self.key_associations],
            'cloud': self.cloud.id,
            'cloud_title': self.cloud.title,
            'last_seen': str(self.last_seen.replace(tzinfo=None)
                             if self.last_seen else ''),
            'missing_since': str(self.missing_since.replace(tzinfo=None)
                                 if self.missing_since else ''),
            'unreachable_since': str(
                self.unreachable_since.replace(tzinfo=None)
                if self.unreachable_since else ''),
            'created': str(self.created.replace(tzinfo=None)
                           if self.created else ''),
            'machine_type': self.machine_type,
            'parent_id': self.parent.id if self.parent is not None else '',
            'probe': {
                'ping': (self.ping_probe.as_dict()
                         if self.ping_probe is not None
                         else PingProbe().as_dict()),
                'ssh': (self.ssh_probe.as_dict()
                        if self.ssh_probe is not None
                        else SSHProbe().as_dict()),
            },
        }

    def as_dict_old(self):
        # Return a dict as it was previously being returned by list_machines

        # This is need to be consistent with the previous situation
        self.extra.update({'created': str(self.created or ''),
                           'cost_per_month': '%.2f' % (self.cost.monthly),
                           'cost_per_hour': '%.2f' % (self.cost.hourly)})
        # tags as a list return for the ui
        tags = {tag.key: tag.value for tag in mist.api.tag.models.Tag.objects(
            owner=self.cloud.owner, resource=self).only('key', 'value')}
        # Optimize tags data structure for js...
        if isinstance(tags, dict):
            tags = [{'key': key, 'value': value}
                    for key, value in tags.iteritems()]
        return {
            'id': self.machine_id,
            'uuid': self.id,
            'name': self.name,
            'public_ips': self.public_ips,
            'private_ips': self.private_ips,
            'imageId': self.image_id,
            'os_type': self.os_type,
            'last_seen': str(self.last_seen or ''),
            'missing_since': str(self.missing_since or ''),
            'state': self.state,
            'size': self.size,
            'extra': self.extra,
            'tags': tags,
            'can_stop': self.actions.stop,
            'can_start': self.actions.start,
            'can_destroy': self.actions.destroy,
            'can_reboot': self.actions.reboot,
            'can_tag': self.actions.tag,
            'can_undefine': self.actions.undefine,
            'can_rename': self.actions.rename,
            'can_suspend': self.actions.suspend,
            'can_resume': self.actions.resume,
            'machine_type': self.machine_type,
            'parent_id': self.parent.id if self.parent is not None else '',
        }

    def __str__(self):
        return 'Machine %s (%s) in %s' % (self.name, self.id, self.cloud)
