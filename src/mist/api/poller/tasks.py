import logging
import datetime
import hvac
import mongoengine as me

from mist.api.dramatiq_app import dramatiq

from mist.api.methods import notify_user

from mist.api.concurrency.models import PeriodicTaskLockTakenError
from mist.api.concurrency.models import PeriodicTaskTooRecentLastRun

log = logging.getLogger(__name__)

__all__ = [
    'debug',
    'list_machines',
    'list_locations',
    'list_sizes',
    'list_images',
    'list_networks',
    'list_zones',
    'list_volumes',
    'list_buckets',
    'ping_probe',
    'ssh_probe'
]


def autodisable_cloud(cloud):
    """Disable cloud after multiple failures and notify user"""
    log.warning("Autodisabling %s", cloud)
    cloud.ctl.disable()
    title = "Cloud %s has been automatically disabled" % cloud.name
    message = "%s after multiple failures to connect to it." % title
    notify_user(cloud.owner, title=title, message=message, email_notify=True)


@dramatiq.actor
def debug(schedule_id):
    # FIXME: Resolve circular imports
    from mist.api.poller.models import DebugPollingSchedule
    sched = DebugPollingSchedule.objects.get(schedule_id)
    path = '/tmp/poller-debug.txt'
    msg = '%s - %s' % (datetime.datetime.now(), sched.value)
    print(msg)
    with open(path, 'a') as fobj:
        fobj.write(msg)


@dramatiq.actor(queue_name='polling', time_limit=280_000, max_age=30_000)
def list_machines(schedule_id):
    """Perform list machines. Cloud controller stores results in mongodb."""

    # Fetch schedule and cloud from database.
    # FIXME: resolve circular deps error
    from mist.api.poller.models import ListMachinesPollingSchedule
    sched = ListMachinesPollingSchedule.objects.get(id=schedule_id)
    try:
        sched.cloud.ctl.compute.list_machines(persist=False)
    except (PeriodicTaskLockTakenError, PeriodicTaskTooRecentLastRun):
        pass


@dramatiq.actor(queue_name='polling', time_limit=280_000, max_age=30_000)
def list_clusters(schedule_id):
    """Perform list machines. Cloud controller stores results in mongodb."""

    # Fetch schedule and cloud from database.
    # FIXME: resolve circular deps error
    from mist.api.poller.models import ListClustersPollingSchedule
    sched = ListClustersPollingSchedule.objects.get(id=schedule_id)
    try:
        sched.cloud.ctl.container.list_clusters(persist=False)
    except (PeriodicTaskLockTakenError, PeriodicTaskTooRecentLastRun):
        pass


@dramatiq.actor(queue_name='polling', time_limit=160_000, max_age=30_000)
def list_locations(schedule_id):
    """Perform list locations. Cloud controller stores results in mongodb."""

    from mist.api.poller.models import ListLocationsPollingSchedule
    sched = ListLocationsPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.compute.list_locations(persist=False)


@dramatiq.actor(queue_name='polling', time_limit=60_000, max_age=30_000)
def list_sizes(schedule_id):
    """Perform list sizes. Cloud controller stores results in mongodb."""

    from mist.api.poller.models import ListSizesPollingSchedule
    sched = ListSizesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.compute.list_sizes(persist=False)


@dramatiq.actor(queue_name='polling', time_limit=60_000, max_age=30_000)
def list_images(schedule_id):
    """Perform list images. Cloud controller stores results in mongodb."""

    from mist.api.poller.models import ListImagesPollingSchedule
    sched = ListImagesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.compute.list_images(persist=False)


@dramatiq.actor(queue_name='polling', time_limit=60_000, max_age=30_000)
def list_networks(schedule_id):
    """Perform list networks and subnets (inside list_networks).
    Cloud controller stores results in mongodb."""

    from mist.api.poller.models import ListNetworksPollingSchedule
    sched = ListNetworksPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.network.list_networks(persist=False)


@dramatiq.actor(queue_name='polling', time_limit=60_000, max_age=30_000)
def list_zones(schedule_id):
    """Perform list zones and records.
       Cloud controller stores results in mongodb.
    """

    from mist.api.poller.models import ListZonesPollingSchedule
    sched = ListZonesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.dns.list_zones(persist=False)


@dramatiq.actor(queue_name='polling', time_limit=60_000, max_age=30_000)
def list_volumes(schedule_id):
    """Perform list volumes. Cloud controller stores results in mongodb."""

    from mist.api.poller.models import ListVolumesPollingSchedule
    sched = ListVolumesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.storage.list_volumes(persist=False)


@dramatiq.actor(queue_name='polling', time_limit=60_000, max_age=300_000)
def list_buckets(schedule_id):
    """
    Perform list buckets.
    Cloud controller stores results in mongodb.
    """

    from mist.api.poller.models import ListBucketsPollingSchedule
    sched = ListBucketsPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.objectstorage.list_buckets(persist=False)


@dramatiq.actor(queue_name='ping_probe', time_limit=45_000, max_age=30_000)
def list_secrets(schedule_id):
    """Perform list secrets in Vault. For every new secret found,
       a VaultSecret object is stored in MongoDB
    """

    from mist.api.poller.models import ListSecretsPollingSchedule
    sched = ListSecretsPollingSchedule.objects.get(id=schedule_id)

    client = hvac.Client(url=sched.url, token=sched.token)
    res = client.secrets.kv.v1.list_secrets(mount_point='kv1',
                                            path='.')
    keys = res['data'].get('keys', [])
    from mist.api.secrets.models import VaultSecret, SecretValue

    # parse the keys, if not found, create one
    for key in keys:
        try:
            VaultSecret.objects.get(name=key)
        except me.DoesNotExist:
            secret = VaultSecret(name=key)
            secret.save()
            secret_value = SecretValue(secret=secret)
            secret_value.save()


@dramatiq.actor(queue_name='ping_probe', time_limit=45_000, max_age=30_000)
def ping_probe(schedule_id):
    """Perform ping probe"""

    # Fetch schedule and machine from database.
    # FIXME: resolve circular deps error
    from mist.api.poller.models import PingProbeMachinePollingSchedule
    sched = PingProbeMachinePollingSchedule.objects.get(id=schedule_id)
    try:
        if sched.machine.state not in ['stopped', 'error'] \
                and sched.machine.machine_type != 'container':
            sched.machine.ctl.ping_probe(persist=False)
    except Exception as exc:
        log.error("Error while ping-probing %s: %r", sched.machine, exc)


@dramatiq.actor(queue_name='ssh_probe', time_limit=45_000, max_age=30_000)
def ssh_probe(schedule_id):
    """Perform ssh probe"""

    # Fetch schedule and machine from database.
    # FIXME: resolve circular deps error
    from mist.api.poller.models import SSHProbeMachinePollingSchedule
    sched = SSHProbeMachinePollingSchedule.objects.get(id=schedule_id)
    try:
        if sched.machine.state not in ['stopped', 'error'] \
                and sched.machine.machine_type != 'container':
            sched.machine.ctl.ssh_probe(persist=False)
    except Exception as exc:
        log.error("Error while ssh-probing %s: %r", sched.machine, exc)
