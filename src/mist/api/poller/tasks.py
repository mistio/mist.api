import logging
import datetime

from mist.api.celery_app import app

from mist.api.methods import notify_user

from mist.api.concurrency.models import PeriodicTaskLockTakenError
from mist.api.concurrency.models import PeriodicTaskTooRecentLastRun

log = logging.getLogger(__name__)


def autodisable_cloud(cloud):
    """Disable cloud after multiple failures and notify user"""
    log.warning("Autodisabling %s", cloud)
    cloud.ctl.disable()
    title = "Cloud %s has been automatically disabled" % cloud.title
    message = "%s after multiple failures to connect to it." % title
    notify_user(cloud.owner, title=cloud, message=message, email_notify=True)


@app.task
def debug(schedule_id):
    # FIXME: Resolve circular imports
    from mist.api.poller.models import DebugPollingSchedule
    sched = DebugPollingSchedule.objects.get(schedule_id)
    path = '/tmp/poller-debug.txt'
    msg = '%s - %s' % (datetime.datetime.now(), sched.value)
    print(msg)
    with open(path, 'a') as fobj:
        fobj.write(msg)


@app.task(time_limit=180, soft_time_limit=155)
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


@app.task(time_limit=60, soft_time_limit=55)
def list_locations(schedule_id):
    """Perform list locations. Cloud controller stores results in mongodb."""

    from mist.api.poller.models import ListLocationsPollingSchedule
    sched = ListLocationsPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.compute.list_locations(persist=False)


@app.task(time_limit=60, soft_time_limit=55)
def list_sizes(schedule_id):
    """Perform list sizes. Cloud controller stores results in mongodb."""

    from mist.api.poller.models import ListSizesPollingSchedule
    sched = ListSizesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.compute.list_sizes(persist=False)


@app.task(time_limit=60, soft_time_limit=55)
def list_images(schedule_id):
    """Perform list images. Cloud controller stores results in mongodb."""

    from mist.api.poller.models import ListImagesPollingSchedule
    sched = ListImagesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.compute.list_images(persist=False)


@app.task(time_limit=60, soft_time_limit=55)
def list_networks(schedule_id):
    """Perform list networks and subnets (inside list_networks).
    Cloud controller stores results in mongodb."""

    from mist.api.poller.models import ListNetworksPollingSchedule
    sched = ListNetworksPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.network.list_networks(persist=False)


@app.task(time_limit=60, soft_time_limit=55)
def list_zones(schedule_id):
    """Perform list zones and records.
       Cloud controller stores results in mongodb.
    """

    from mist.api.poller.models import ListZonesPollingSchedule
    sched = ListZonesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.dns.list_zones(persist=False)


@app.task(time_limit=60, soft_time_limit=55)
def list_volumes(schedule_id):
    """Perform list volumes. Cloud controller stores results in mongodb."""

    from mist.api.poller.models import ListVolumesPollingSchedule
    sched = ListVolumesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.storage.list_volumes(persist=False)


@app.task(time_limit=45, soft_time_limit=40)
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


@app.task(time_limit=45, soft_time_limit=40)
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
