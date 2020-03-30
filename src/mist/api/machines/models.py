"""Machine entity model."""
import os
import json
import uuid
import logging
import datetime
import mongoengine as me

import mist.api.tag.models

from future.utils import string_types

from mist.api.mongoengine_extras import MistDictField
from mist.api.keys.models import Key
from mist.api.schedules.models import Schedule
from mist.api.machines.controllers import MachineController
from mist.api.ownership.mixins import OwnershipMixin

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
    # automatic: refers to automatic agent installations
    # manual: refers to manual agent deployments

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
    clone = me.BooleanField(default=False)
    create_snapshot = me.BooleanField(default=False)
    remove_snapshot = me.BooleanField(default=False)
    revert_to_snapshot = me.BooleanField(default=False)


class Monitoring(me.EmbeddedDocument):
    # Most of these will change with the new UI.
    hasmonitoring = me.BooleanField()
    monitor_server = me.StringField()  # Deprecated
    collectd_password = me.StringField()  # Deprecated
    metrics = me.ListField()  # list of metric_id's
    installation_status = me.EmbeddedDocumentField(InstallationStatus)
    method = me.StringField(choices=config.MONITORING_METHODS)
    method_since = me.DateTimeField()

    def clean(self):
        if not self.collectd_password:
            self.collectd_password = os.urandom(32).hex()

    def get_commands(self):
        if self.method in ('telegraf-influxdb', 'telegraf-graphite'):
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
        from mist.api.rules.models import MachineMetricRule
        m = self._instance
        return {rule.id: rule.as_dict() for
                rule in MachineMetricRule.objects(owner_id=m.owner.id) if
                rule.ctl.includes_only(m)}

    def as_dict(self):
        status = self.installation_status
        try:
            commands = self.get_commands()
        except:
            commands = {}
        return {
            'hasmonitoring': self.hasmonitoring,
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
    distro = me.StringField()
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
            # macs may come in dicts that map ip to mac
            if strarr_attr == 'macs' and isinstance(val, dict):
                val = list(val.values())
            try:
                assert isinstance(val, list)
                assert all(isinstance(item, string_types) for item in val)
                setattr(self, strarr_attr, val)
            except Exception as exc:
                log.error("Invalid %s '%s': %r", strarr_attr, val, exc)
                setattr(self, strarr_attr, [])

        for str_attr in ('df', 'kernel', 'os', 'os_version', 'distro'):
            setattr(self, str_attr, str(data.get(str_attr, '')))

        self.dirty_cow = bool(data.get('dirty_cow'))
        self.unreachable_since = None
        self.updated_at = datetime.datetime.now()

    def as_dict(self):
        data = {key: getattr(self, key) for key in (
            'uptime', 'loadavg', 'cores', 'users', 'pub_ips', 'priv_ips', 'df',
            'macs', 'kernel', 'os', 'os_version', 'distro', 'dirty_cow',
            'updated_at', 'unreachable_since',
        )}
        # Handle datetime objects
        for key in ('updated_at', 'unreachable_since'):
            if data[key]:
                data[key] = str(data[key].replace(tzinfo=None))
        return data


class Machine(OwnershipMixin, me.Document):
    """The basic machine model"""

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)

    cloud = me.ReferenceField('Cloud', required=True,
                              reverse_delete_rule=me.CASCADE)
    owner = me.ReferenceField('Organization', required=True,
                              reverse_delete_rule=me.CASCADE)
    location = me.ReferenceField('CloudLocation', required=False,
                                 reverse_delete_rule=me.DENY)
    size = me.ReferenceField('CloudSize', required=False,
                             reverse_delete_rule=me.DENY)
    image = me.ReferenceField('CloudImage', required=False,
                              reverse_delete_rule=me.DENY)
    network = me.ReferenceField('Network', required=False,
                                reverse_delete_rule=me.NULLIFY)
    subnet = me.ReferenceField('Subnet', required=False,
                               reverse_delete_rule=me.NULLIFY)
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
    extra = MistDictField()
    cost = me.EmbeddedDocumentField(Cost, default=lambda: Cost())
    # libcloud.compute.types.NodeState
    state = me.StringField(default='unknown',
                           choices=tuple(config.STATES.values()))
    machine_type = me.StringField(default='machine',
                                  choices=('machine', 'vm', 'container',
                                           'hypervisor', 'container-host',
                                           'ilo-host'))
    parent = me.ReferenceField('Machine', required=False,
                               reverse_delete_rule=me.NULLIFY)

    # Deprecated TODO: Remove in v5
    key_associations = me.EmbeddedDocumentListField(KeyAssociation)

    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    unreachable_since = me.DateTimeField()
    created = me.DateTimeField()

    monitoring = me.EmbeddedDocumentField(Monitoring,
                                          default=lambda: Monitoring())

    ssh_probe = me.EmbeddedDocumentField(SSHProbe, required=False)
    ping_probe = me.EmbeddedDocumentField(PingProbe, required=False)

    expiration = me.ReferenceField(Schedule, required=False,
                                   reverse_delete_rule=me.NULLIFY)

    # Number of vCPUs gathered from various sources. This field is meant to
    # be updated ONLY by the mist.api.metering.tasks:find_machine_cores task.
    cores = me.IntField()

    meta = {
        'collection': 'machines',
        'indexes': [
            {
                'fields': [
                    'cloud',
                    'machine_id'
                ],
                'sparse': False,
                'unique': True,
                'cls': False,
            }, {
                'fields': [
                    'monitoring.installation_status.activated_at'
                ],
                'sparse': True,
                'unique': False
            }
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
        key_associations = KeyMachineAssociation.objects(machine=self)
        for ka in reversed(list(range(len(key_associations)))):
            if key_associations[ka].key.deleted:
                key_associations[ka].delete()

        # Reset key_associations in case self goes missing/destroyed. This is
        # going to prevent the machine from showing up as "missing" in the
        # corresponding keys' associated machines list.
        if self.missing_since:
            self.key_associations = []

        # Populate owner field based on self.cloud.owner
        if not self.owner:
            self.owner = self.cloud.owner

        self.clean_os_type()

        if self.monitoring.method not in config.MONITORING_METHODS:
            self.monitoring.method = config.DEFAULT_MONITORING_METHOD

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
        if self.expiration:
            self.expiration.delete()
        super(Machine, self).delete()
        mist.api.tag.models.Tag.objects(
            resource_id=self.id, resource_type='machine').delete()
        try:
            self.owner.mapper.remove(self)
        except (AttributeError, me.DoesNotExist) as exc:
            log.error(exc)
        try:
            if self.owned_by:
                self.owned_by.get_ownership_mapper(self.owner).remove(self)
        except (AttributeError, me.DoesNotExist) as exc:
            log.error(exc)

    def as_dict(self):
        # Return a dict as it will be returned to the API
        tags = {tag.key: tag.value for tag in mist.api.tag.models.Tag.objects(
            resource_id=self.id, resource_type='machine'
        ).only('key', 'value')}
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
            'extra': dict(self.extra),
            'cost': self.cost.as_dict(),
            'state': self.state,
            'tags': tags,
            'monitoring':
                self.monitoring.as_dict() if self.monitoring and
                self.monitoring.hasmonitoring else '',
            'key_associations':
                [ka.as_dict() for ka in KeyMachineAssociation.objects(
                    machine=self)],
            'cloud': self.cloud.id,
            'location': self.location.id if self.location else '',
            'size': self.size.name if self.size else '',
            'image': self.image.id if self.image else '',
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
            'parent': self.parent.id if self.parent is not None else '',
            'probe': {
                'ping': (self.ping_probe.as_dict()
                         if self.ping_probe is not None
                         else PingProbe().as_dict()),
                'ssh': (self.ssh_probe.as_dict()
                        if self.ssh_probe is not None
                        else SSHProbe().as_dict()),
            },
            'cores': self.cores,
            'network': self.network.id if self.network else '',
            'subnet': self.subnet.id if self.subnet else '',
            'owned_by': self.owned_by.id if self.owned_by else '',
            'created_by': self.created_by.id if self.created_by else '',
            'expiration': {
                'id': self.expiration.id,
                'action': self.expiration.task_type.action,
                'date': self.expiration.schedule_type.entry,
                'notify': self.expiration.reminder and int((
                    self.expiration.schedule_type.entry -
                    self.expiration.reminder.schedule_type.entry
                ).total_seconds()) or 0,
            } if self.expiration else None,
            'provider': self.cloud.ctl.provider
        }

    def __str__(self):
        return 'Machine %s (%s) in %s' % (self.name, self.id, self.cloud)


class KeyMachineAssociation(me.Document):
    meta = {
        'allow_inheritance': True,
        'collection': 'key_association',
        'indexes': [
            {
                'fields': ['key'],
                'sparse': False,
                'cls': False,
            }, {
                'fields': ['machine'],
                'sparse': False,
                'cls': False
            }
        ],
    }
    key = me.ReferenceField(Key, required=True, reverse_delete_rule=me.CASCADE)
    machine = me.ReferenceField(Machine, reverse_delete_rule=me.CASCADE)
    last_used = me.IntField(default=0)
    ssh_user = me.StringField(default='root')
    sudo = me.BooleanField(default=False)
    port = me.IntField(default=22)

    def as_dict(self):
        return json.loads(self.to_json())
