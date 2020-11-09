import logging

from apscheduler.schedulers.blocking import BlockingScheduler

from mist.api.poller.dramatiq_tasks import ping_probe
from mist.api.poller.models import PingProbeMachinePollingSchedule

logging.basicConfig()
logging.getLogger("apscheduler").setLevel(logging.DEBUG)

schedules = []


def poll_db_for_ping_schedules(scheduler):
    """Poll mongodb for new ping probe schedule
    and add tasks to dramatiq
    """
    db_schedules = PingProbeMachinePollingSchedule.objects()
    for db_schedule in db_schedules:
        if db_schedule not in schedules:
            schedules.append(db_schedule)
            scheduler.add_job(
                ping_probe.send,
                "interval",
                args=[str(db_schedule.id)],
                seconds=20,
            )


if __name__ == "__main__":
    scheduler = BlockingScheduler()
    scheduler.add_job(
        poll_db_for_ping_schedules, "interval", args=[scheduler], minutes=1
    )
    scheduler.start()
