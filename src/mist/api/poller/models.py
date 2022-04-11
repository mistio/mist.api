import logging
import datetime

import mongoengine as me

from mist.api import config
from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.containers.models import Cluster
from mist.api.users.models import Owner
from mist.api.sharding.mixins import ShardedScheduleMixin


log = logging.getLogger(__name__)


class PollingInterval(me.EmbeddedDocument):

    name = me.StringField()  # optional field for labeling interval
    every = me.IntField(required=True)  # seconds
    expires = me.DateTimeField()

    @property
    def timedelta(self):
        return datetime.timedelta(seconds=self.every)

    def expired(self):
        return self.expires and self.expires < datetime.datetime.now()

    def __unicode__(self):
        msg = 'every %s' % self.timedelta
        if self.expires is not None:
            msg += ' until %s' % self.expires
        if self.expired():
            msg += ' **EXPIRED**'
        elif self.expires:
            msg += ' (in %s)' % (self.expires - datetime.datetime.now())
        if self.name:
            msg += ' [%s]' % self.name
        return msg


class PollingSchedule(ShardedScheduleMixin, me.Document):

    meta = {
        'allow_inheritance': True,
        'strict': False,
        'indexes': ['shard_id', 'shard_update_at']
    }

    # We use a unique name for easy identification and to avoid running the
    # same schedule twice. The name is autopopulated during the invocation of
    # the `clean` method.
    name = me.StringField(unique=True)

    # Scheduling information. Don't edit them directly, just use the model
    # methods.
    default_interval = me.EmbeddedDocumentField(
        PollingInterval, required=True, default=PollingInterval(every=0)
    )
    override_intervals = me.EmbeddedDocumentListField(PollingInterval)

    # Optional arguments.
    queue = me.StringField()
    exchange = me.StringField()
    routing_key = me.StringField()
    soft_time_limit = me.IntField()

    # Used internally by the scheduler.
    last_run_at = me.DateTimeField()
    total_run_count = me.IntField(min_value=0)
    run_immediately = me.BooleanField()

    def get_name(self):
        """Construct name based on self.task"""
        try:
            return self.task.split('.')[-1]
        except NotImplementedError:
            return '%s: No task specified.' % self.__class__.__name__

    def clean(self):
        """Automatically set value of name"""
        self.name = self.get_name()

    @property
    def task(self):
        """Return task name for this schedule

        Subclasses should define an attribute, property or field to do this.
        """
        raise NotImplementedError()

    @property
    def args(self):
        """Return task args for this schedule"""
        return [str(self.id)]

    @property
    def kwargs(self):
        """Return task kwargs for this schedule"""
        return {}

    @property
    def enabled(self):
        """Whether this task is currently enabled or not"""
        return bool(self.interval.timedelta)

    @property
    def interval(self):
        """Merge multiple intervals into one

        Returns a dynamic PollingInterval, with the highest frequency of any
        override schedule or the default schedule.

        """
        interval = self.default_interval
        for i in self.override_intervals:
            if not i.expired():
                if not interval.timedelta or i.timedelta < interval.timedelta:
                    interval = i
        return interval

    @property
    def expires(self):
        return None

    def add_interval(self, interval, ttl=300, name=''):
        """Add an override schedule to the scheduled task

        Override schedules must define an interval in seconds, as well as a
        TTL (time to live), also in seconds. Override schedules cannot be
        removed, so short TTL's should be used. You can however add a new
        override schedule again, thus practically extending the time where an
        override is in effect.

        Override schedules can only increase, not decrease frequency of the
        schedule, in relation to that define in the `default_interval`.
        """
        assert isinstance(interval, int) and interval > 0
        assert isinstance(ttl, int) and 0 < ttl < 3600
        expires = datetime.datetime.now() + datetime.timedelta(seconds=ttl)
        self.override_intervals.append(
            PollingInterval(name=name, expires=expires, every=interval)
        )

    def cleanup_expired_intervals(self):
        """Remove override schedules that have expired"""
        self.override_intervals = [override
                                   for override in self.override_intervals
                                   if not override.expired()]

    def set_default_interval(self, interval):
        """Set default interval

        This is the interval used for this schedule, if there is no active
        override schedule with a smaller interval. The default interval never
        expires. To disable a task, simply set `enabled` equal to False.
        """
        self.default_interval = PollingInterval(name='default', every=interval)

    def __unicode__(self):
        return "%s %s" % (self.get_name(), self.interval or '(no interval)')


class DebugPollingSchedule(PollingSchedule):

    task = 'mist.api.poller.tasks.debug'

    value = me.StringField()


class OwnerPollingSchedule(PollingSchedule):

    owner = me.ReferenceField('Organization', reverse_delete_rule=me.CASCADE)

    @property
    def org(self):
        return self.owner

    @classmethod
    def add(cls, owner, run_immediately=True, interval=None, ttl=300):
        try:
            schedule = cls.objects.get(owner=owner)
        except cls.DoesNotExist:
            schedule = cls(owner=owner)
            try:
                schedule.save()
            except me.NotUniqueError:
                # Work around race condition where schedule was created since
                # last time we checked.
                schedule = cls.objects.get(owner=owner)
        schedule.set_default_interval(60 * 30)
        if interval is not None:
            schedule.add_interval(interval, ttl)
        if run_immediately:
            schedule.run_immediately = True
        schedule.cleanup_expired_intervals()
        schedule.save()
        return schedule

    @property
    def args(self):
        return [str(self.owner.id)]

    def get_name(self):
        return '%s(%s)' % (super(OwnerPollingSchedule, self).get_name(),
                           self.owner.id)


class MeteringPollingSchedule(OwnerPollingSchedule):

    @property
    def task(self):
        return 'mist.api.metering.tasks.push_metering_info'

    @property
    def enabled(self):
        return (super(MeteringPollingSchedule, self).enabled and
                config.ENABLE_METERING)


class CloudPollingSchedule(PollingSchedule):

    cloud = me.ReferenceField(Cloud, reverse_delete_rule=me.CASCADE)

    meta = {
        'allow_inheritance': True,
        'strict': False,
        'indexes': ['cloud', 'shard_id', 'shard_update_at']
    }

    def get_name(self):
        return '%s(%s)' % (super(CloudPollingSchedule, self).get_name(),
                           self.cloud.id)

    @classmethod
    def add(cls, cloud, run_immediately=True, interval=None, ttl=300):
        try:
            schedule = cls.objects.get(cloud=cloud)
        except cls.DoesNotExist:
            schedule = cls(cloud=cloud)
            try:
                schedule.save()
            except me.NotUniqueError:
                # Work around race condition where schedule was created since
                # last time we checked.
                schedule = cls.objects.get(cloud=cloud)
        schedule.set_default_interval(cloud.polling_interval)
        if interval is not None:
            schedule.add_interval(interval, ttl)
        if run_immediately:
            schedule.run_immediately = True
        schedule.cleanup_expired_intervals()
        schedule.save()
        return schedule

    @property
    def enabled(self):
        try:
            return (super(CloudPollingSchedule, self).enabled and
                    self.cloud.enabled and not self.cloud.deleted)
        except me.DoesNotExist:
            log.error('Cannot get cloud for polling schedule.')
            return False


class ListMachinesPollingSchedule(CloudPollingSchedule):

    task = 'mist.api.poller.tasks.list_machines'

    @property
    def interval(self):
        try:
            if self.default_interval.every != self.cloud.polling_interval:
                log.warning("Schedule has different interval from cloud, "
                            "fixing")
                self.default_interval.every = self.cloud.polling_interval
                self.save()
            return super(CloudPollingSchedule, self).interval
        except me.DoesNotExist:
            log.error('Cannot get interval. Cloud is missing')
            return PollingInterval(every=0)


class ListClustersPollingSchedule(CloudPollingSchedule):

    task = 'mist.api.poller.tasks.list_clusters'

    @property
    def interval(self):
        try:
            if self.default_interval.every != self.cloud.polling_interval:
                log.warning("Schedule has different interval from cloud, "
                            "fixing")
                self.default_interval.every = self.cloud.polling_interval
                self.save()
            return super(CloudPollingSchedule, self).interval
        except me.DoesNotExist:
            log.error('Cannot get interval. Cloud is missing')
            return PollingInterval(every=0)

    @property
    def enabled(self):
        return super(ListClustersPollingSchedule, self).enabled and \
            hasattr(self.cloud.ctl, 'container') and \
            self.cloud.container_enabled


class ListLocationsPollingSchedule(CloudPollingSchedule):

    task = 'mist.api.poller.tasks.list_locations'


class ListSizesPollingSchedule(CloudPollingSchedule):

    task = 'mist.api.poller.tasks.list_sizes'


class ListImagesPollingSchedule(CloudPollingSchedule):

    task = 'mist.api.poller.tasks.list_images'


class ListNetworksPollingSchedule(CloudPollingSchedule):

    # task below is polling both networks and subnets
    task = 'mist.api.poller.tasks.list_networks'

    @property
    def enabled(self):
        return (super(ListNetworksPollingSchedule, self).enabled and
                hasattr(self.cloud.ctl, 'network'))


class ListZonesPollingSchedule(CloudPollingSchedule):

    # task below is polling both zones and records
    task = 'mist.api.poller.tasks.list_zones'

    @property
    def enabled(self):
        return (super(ListZonesPollingSchedule, self).enabled and
                hasattr(self.cloud.ctl, 'dns') and self.cloud.dns_enabled)


class ListVolumesPollingSchedule(CloudPollingSchedule):

    task = 'mist.api.poller.tasks.list_volumes'

    @property
    def enabled(self):
        return (super(ListVolumesPollingSchedule, self).enabled and
                hasattr(self.cloud.ctl, 'storage'))


class ListBucketsPollingSchedule(CloudPollingSchedule):
    task = 'mist.api.poller.tasks.list_buckets'

    @property
    def enabled(self):
        return (super(ListBucketsPollingSchedule, self).enabled and
                hasattr(self.cloud.ctl, 'objectstorage') and
                self.cloud.object_storage_enabled)


class MachinePollingSchedule(PollingSchedule):

    machine_id = me.StringField(required=True)

    @property
    def machine(self):
        return Machine.objects.get(id=self.machine_id)

    @property
    def enabled(self):
        try:
            machine = Machine.objects.get(id=self.machine_id,
                                          missing_since=None)
            return machine.cloud and machine.cloud.enabled
        except Machine.DoesNotExist:
            return False

    def get_name(self):
        return '%s(%s)' % (super(MachinePollingSchedule, self).get_name(),
                           self.machine_id)

    @classmethod
    def add(cls, machine, run_immediately=True, interval=None, ttl=300):
        try:
            schedule = cls.objects.get(machine_id=machine.id)
        except cls.DoesNotExist:
            schedule = cls(machine_id=machine.id)
            try:
                schedule.save()
            except me.NotUniqueError:
                # Work around race condition where schedule was created since
                # last time we checked.
                schedule = cls.objects.get(machine_id=machine.id)
        schedule.set_default_interval(60 * 60 * 2)
        if interval is not None:
            schedule.add_interval(interval, ttl)
        if run_immediately:
            schedule.run_immediately = True
        schedule.cleanup_expired_intervals()
        schedule.save()
        return schedule


class ClusterPollingSchedule(PollingSchedule):

    cluster_id = me.StringField(required=True)

    @property
    def cluster(self):
        return Cluster.objects.get(id=self.cluster_id)

    @property
    def enabled(self):
        try:
            cluster = Cluster.objects.get(id=self.cluster_id,
                                          missing_since=None)
            return cluster.cloud and cluster.cloud.enabled
        except Cluster.DoesNotExist:
            return False

    def get_name(self):
        return '%s(%s)' % (super(CloudPollingSchedule, self).get_name(),
                           self.cluster_id)

    @classmethod
    def add(cls, cluster, run_immediately=True, interval=None, ttl=300):
        try:
            schedule = cls.objects.get(id=cluster.id)
        except cls.DoesNotExist:
            schedule = cls(id=cluster.id)
            try:
                schedule.save()
            except me.NotUniqueError:
                # Work around race condition where schedule was created since
                # last time we checked.
                schedule = cls.objects.get(id=cluster.id)
        schedule.set_default_interval(60 * 60 * 2)
        if interval is not None:
            schedule.add_interval(interval, ttl)
        if run_immediately:
            schedule.run_immediately = True
        schedule.cleanup_expired_intervals()
        schedule.save()
        return schedule


class PingProbeMachinePollingSchedule(MachinePollingSchedule):

    task = 'mist.api.poller.tasks.ping_probe'


class SSHProbeMachinePollingSchedule(MachinePollingSchedule):

    task = 'mist.api.poller.tasks.ssh_probe'


class FindCoresMachinePollingSchedule(MachinePollingSchedule):

    @property
    def task(self):
        return 'mist.api.metering.tasks.find_machine_cores'

    @property
    def args(self):
        return (self.machine_id, )

    @property
    def enabled(self):
        return (super(FindCoresMachinePollingSchedule, self).enabled and
                config.ENABLE_METERING)


class SecretsPollingSchedule(PollingSchedule):

    owner = me.ReferenceField(Owner, reverse_delete_rule=me.CASCADE)

    @classmethod
    def add(cls, owner, run_immediately=True, interval=None, ttl=300):
        try:
            schedule = cls.objects.get(owner=owner)
        except cls.DoesNotExist:
            schedule = cls(owner=owner)
            try:
                schedule.save()
            except me.NotUniqueError:
                # Work around race condition where schedule was created since
                # last time we checked.
                schedule = cls.objects.get(owner=owner)
        schedule.set_default_interval(60 * 10)
        if interval is not None:
            schedule.add_interval(interval, ttl)
        if run_immediately:
            schedule.run_immediately = True
        schedule.cleanup_expired_intervals()
        schedule.save()
        return schedule

    def get_name(self):
        return '%s(%s)' % (super(SecretsPollingSchedule, self).get_name(),
                           self.owner.id)


class ListVaultSecretsPollingSchedule(SecretsPollingSchedule):

    task = 'mist.api.poller.tasks.list_vault_secrets'
