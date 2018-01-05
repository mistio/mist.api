import logging
import datetime

from mist.api.methods import notify_user
from mist.api.tasks import app


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
    print msg
    with open(path, 'a') as fobj:
        fobj.write(msg)


@app.task(time_limit=60, soft_time_limit=55)
def list_machines(schedule_id):
    """Perform list machines. Cloud controller stores results in mongodb."""

    # Fetch schedule and cloud from database.
    # FIXME: resolve circular deps error
    from mist.api.poller.models import ListMachinesPollingSchedule
    sched = ListMachinesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.compute.list_machines(persist=False)


@app.task(time_limit=60, soft_time_limit=55)
def list_images(schedule_id):
    """Perform list images. Cloud controller stores results in mongodb."""

    # Fetch schedule and cloud from database.
    # FIXME: resolve circular deps error
    from mist.api.poller.models import ListImagesPollingSchedule
    sched = ListImagesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.compute.list_images(persist=False)


@app.task(time_limit=60, soft_time_limit=55)
def list_zones(schedule_id):
    """Perform list zones. Cloud controller stores results in mongodb."""

    # Fetch schedule and cloud from database.
    # FIXME: resolve circular deps error
    from mist.api.poller.models import ListZonesPollingSchedule
    sched = ListZonesPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.dns.list_zones(persist=False)


@app.task(time_limit=60, soft_time_limit=55)
def list_records(schedule_id):
    """Perform list records. Dns controller stores results in mongodb."""

    # Fetch schedule and zone from database.
    # FIXME: resolve circular deps error
    from mist.api.poller.models import ListRecordsPollingSchedule
    sched = ListRecordsPollingSchedule.objects.get(id=schedule_id)
    sched.cloud.ctl.dns.list_records(persist=False)


@app.task(time_limit=45, soft_time_limit=40)
def ping_probe(schedule_id):
    """Perform ping probe"""

    # Fetch schedule and machine from database.
    # FIXME: resolve circular deps error
    from mist.api.poller.models import PingProbeMachinePollingSchedule
    sched = PingProbeMachinePollingSchedule.objects.get(id=schedule_id)
    try:
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
        sched.machine.ctl.ssh_probe(persist=False)
    except Exception as exc:
        log.error("Error while ssh-probing %s: %r", sched.machine, exc)
