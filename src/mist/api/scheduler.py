import datetime
import logging
import importlib
import pytz

from time import sleep

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.base import JobLookupError

from mist.api import config
from mist.api.models import Schedule
from mist.api.poller.models import PollingSchedule
from mist.api.rules.models import Rule

log = logging.getLogger(__name__)

RELOAD_INTERVAL = 10


def schedule_to_actor(schedule):
    if isinstance(schedule, PollingSchedule) or isinstance(schedule, Rule):
        task_path = schedule.task.split('.')
    else:
        task_path = schedule.task_type.task.split('.')
    method = task_path[-1]
    module = '.'.join(task_path[:-1])
    return getattr(importlib.import_module(module), method)
    # return dramatiq.actor(
    #     task,
    #     queue_name="schedules",
    #     time_limit=30 * 60 * 1000,  # 30 minutes
    #     max_retries=None,
    #     broker=broker
    # )


def add_job(scheduler, schedule, actor, first_run=False):
    job = {
        'id': str(schedule.id),
        'name': schedule.name,
    }
    if isinstance(schedule, PollingSchedule):
        job['trigger'] = 'interval'
        job['seconds'] = schedule.interval.every
        job['args'] = schedule.args
    elif isinstance(schedule, Rule):
        job['trigger'] = 'interval'
        job['seconds'] = schedule.frequency.timedelta.total_seconds()
        job['args'] = schedule.args
    else:
        if schedule.schedule_type.type == 'interval':
            job['trigger'] = 'interval'
            period = schedule.schedule_type['period']
            job[period] = schedule.schedule_type['every']
        elif schedule.schedule_type.type == 'crontab':
            job['trigger'] = CronTrigger.from_crontab(
                schedule.schedule_type.as_cron())
        elif schedule.schedule_type.type == 'one_off':
            job['run_date'] = schedule.schedule_type.entry
        else:
            log.error('Invalid schedule type: %s' % schedule.schedule_type)
            raise
        if schedule.task_type._cls == 'ScriptTask':
            job['args'] = (
                schedule.org.id,
                schedule.task_type.script_id,
                schedule.name,
                [r.id for r in schedule.get_resources()],
                schedule.task_type.params,
            )
        elif schedule.task_type._cls == 'ActionTask':
            job['args'] = (
                schedule.org.id,
                schedule.task_type.action,
                schedule.name,
                [r.id for r in schedule.get_resources()],
            )
        else:
            log.error('Invalid task type: %s' % schedule.task_type._cls)

    new_job = scheduler.add_job(actor.send, **job)
    if not first_run and schedule.run_immediately:
        new_job.modify(next_run_time=datetime.datetime.now())
    return new_job


def update_job(scheduler, schedule, actor, existing):
    changes = {}
    interval = getattr(existing.trigger, 'interval', None)
    if isinstance(schedule, PollingSchedule):
        if interval.total_seconds() != schedule.interval.every:
            scheduler.remove_job(existing.id)
            add_job(scheduler, schedule, actor)
    elif isinstance(schedule, Rule):
        if interval.total_seconds() != \
                schedule.frequency.timedelta.total_seconds():
            scheduler.remove_job(existing.id)
            add_job(scheduler, schedule, actor)
    else:
        if schedule.schedule_type.type == 'interval' and interval:
            # Update interval
            delta = datetime.timedelta(**{
                schedule.schedule_type.period: schedule.schedule_type.every
            })
            if interval.total_seconds() != \
                    delta.total_seconds():
                changes[schedule.schedule_type['period']] = \
                    schedule.schedule_type['every']
        elif schedule.schedule_type.type == 'crontab':
            new_trigger = CronTrigger.from_crontab(
                schedule.schedule_type.as_cron())
            # Update crontab
            if str(new_trigger) != str(existing.trigger):
                changes['trigger'] = new_trigger
        elif schedule.schedule_type.type == 'one_off':
            # Update run_date
            if existing.trigger.run_date != \
                    pytz.utc.localize(schedule.schedule_type.entry):
                scheduler.remove_job(existing.id)
                add_job(scheduler, schedule, actor)
                return
        else:
            log.error('Invalid schedule type: %s' % schedule.schedule_type)
            raise

        if str(existing.func) != str(actor.send):
            # Update func
            changes['func'] = actor.send

        if schedule.task_type._cls == 'ScriptTask':
            new_args = (
                schedule.org.id,
                schedule.task_type.script_id,
                schedule.name,
                [r.id for r in schedule.get_resources()],
                schedule.task_type.params,
            )
        elif schedule.task_type._cls == 'ActionTask':
            new_args = (
                schedule.org.id,
                schedule.task_type.action,
                schedule.name,
                [r.id for r in schedule.get_resources()],
            )

        if existing.args != new_args:
            # Update args
            changes['args'] = new_args

        scheduler.modify_job(existing.id, **changes)


def load_config_schedules(scheduler):
    """ Load schedules from config """
    for sched in config._schedule:
        task_path = config._schedule[sched]['task'].split('.')
        method = task_path[-1]
        module = '.'.join(task_path[:-1])
        actor = getattr(importlib.import_module(module), method)
        interval = config._schedule[sched]['schedule'].total_seconds()
        scheduler.add_job(
            actor.send, trigger='interval', seconds=interval, name=sched)


def load_schedules_from_db(scheduler, schedules, first_run=False):
    """ Load schedules from db """
    old_schedule_ids = []
    new_schedule_ids = []
    for schedule in schedules:
        if not schedule.enabled:
            continue

        new_schedule_ids.append(str(schedule.id))
        existing = scheduler.get_job(str(schedule.id))
        actor = schedule_to_actor(schedule)

        if existing:  # Update existing job
            update_job(scheduler, schedule, actor, existing)
        else:  # Add new job
            add_job(scheduler, schedule, actor, first_run=first_run)

    # Cleanup deleted schedules
    for sid in old_schedule_ids:
        if sid not in new_schedule_ids:
            try:
                scheduler.remove_job(sid)
            except JobLookupError as e:
                print('Error cleaning up job: %r' % e)
    old_schedule_ids = new_schedule_ids


def start(**kwargs):
    if not kwargs.keys():
        kwargs['builtin'] = True
        kwargs['user'] = True
        kwargs['polling'] = True
        kwargs['rules'] = True

    # Init scheduler
    scheduler = BackgroundScheduler()

    # Load schedules from config
    if kwargs.get('builtin'):
        load_config_schedules(scheduler)

    try:  # Start scheduler
        scheduler.start()
        first_run = True
        while True:  # Start main loop
            if kwargs.get('user'):
                log.info('Reloading user schedules')
                load_schedules_from_db(
                    scheduler,
                    Schedule.objects(deleted=False),
                    first_run=first_run
                )
            if kwargs.get('polling'):
                log.info('Reloading polling schedules')
                load_schedules_from_db(
                    scheduler,
                    PollingSchedule.objects(),
                    first_run=first_run
                )
            if kwargs.get('rules'):
                log.info('Reloading rules')
                load_schedules_from_db(
                    scheduler,
                    Rule.objects()
                )
            sleep(RELOAD_INTERVAL)
            first_run = False
    except KeyboardInterrupt:
        import ipdb
        ipdb.set_trace()
        scheduler.shutdown()
    except Exception as e:
        print('Exception: %r' % e)
        import ipdb
        ipdb.set_trace()
