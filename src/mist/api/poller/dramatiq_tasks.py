import logging

import dramatiq

from mist.api.dramatiq_app import broker
from mist.api.poller.models import PingProbeMachinePollingSchedule

log = logging.getLogger(__name__)


@dramatiq.actor(time_limit=45000, queue_name="dramatiq_ping", broker=broker)
def ping_probe(schedule_id):
    """Perform ping probe"""
    # Fetch schedule and machine from database.
    sched = PingProbeMachinePollingSchedule.objects.get(id=schedule_id)
    try:
        if sched.machine.state not in ['stopped', 'error'] \
                and sched.machine.machine_type != 'container':
            sched.machine.ctl.ping_probe(persist=False)
    except Exception as exc:
        log.error("Error while ping-probing %s: %r", sched.machine, exc)
