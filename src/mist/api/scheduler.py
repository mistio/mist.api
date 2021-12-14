import datetime
import logging
import importlib
import pytz
import threading
import os
from time import sleep

import mongoengine as me
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.base import JobLookupError

from mist.api import config
from mist.api.models import Schedule
from mist.api.poller.models import PollingSchedule
from mist.api.rules.models import Rule
try:
    from mist.billing.models import BillingUpdateSchedule  # noqa
except ImportError:
    pass

log = logging.getLogger(__name__)
log.setLevel('DEBUG')

RELOAD_INTERVAL = 5


def schedule_to_actor(schedule):
    if isinstance(schedule, PollingSchedule) or isinstance(schedule, Rule):
        task_path = schedule.task.split('.')
    else:
        task_path = schedule.task_type.task.split('.')
    method = task_path[-1]
    module = '.'.join(task_path[:-1])
    return getattr(importlib.import_module(module), method)


def add_job(scheduler, schedule, actor, first_run=False):
    job = {
        'id': str(schedule.id),
        'name': schedule.name,
    }
    if isinstance(schedule, PollingSchedule):
        if hasattr(schedule, 'crontab'):
            job['trigger'] = CronTrigger(**schedule.crontab)
        else:
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
        elif schedule.schedule_type.type in ('one_off', 'reminder'):
            job['run_date'] = schedule.schedule_type.entry
        else:
            log.error('Invalid schedule type: %s' % schedule.schedule_type)
            raise
        if schedule.task_type._cls == 'ScriptTask':
            job['args'] = (
                None,
                schedule.task_type.script_id,
                schedule.name,
                [r.id for r in schedule.get_resources()],
                schedule.task_type.params,
                schedule.org.id
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

    if not first_run and schedule.run_immediately:
        schedule.run_immediately = False
        try:
            schedule.save()
        except Exception as exc:
            log.critical(
                'Failed to save schedule: %s with exception: %s',
                schedule.id, repr(exc))
        else:
            job['next_run_time'] = datetime.datetime.now()
    new_job = scheduler.add_job(actor.send, **job)
    return new_job


def update_job(scheduler, schedule, actor, existing):
    changes = {}
    interval = getattr(existing.trigger, 'interval', None)
    if isinstance(schedule, PollingSchedule):
        if hasattr(schedule, 'crontab'):
            # Workaround for schedules that use a cron trigger and subclass
            # PollingSchedule. Currently only implemented by
            # BillingUpdateSchedule that never gets updated.
            pass
        elif (interval.total_seconds() != schedule.interval.every or
                schedule.run_immediately):
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
        elif schedule.schedule_type.type in ('one_off', 'reminder'):
            # Update run_date
            if (existing.trigger.run_date != pytz.utc.localize(schedule.schedule_type.entry) or  # noqa
                    schedule.run_immediately):
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
                None,
                schedule.task_type.script_id,
                schedule.name,
                [r.id for r in schedule.get_resources()],
                schedule.task_type.params,
                schedule.org.id,
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

        if schedule.run_immediately:
            schedule.run_immediately = False
            try:
                schedule.save()
            except Exception as exc:
                log.critical(
                    'Failed to save schedule: %s with exception: %s',
                    schedule.id, repr(exc))
            else:
                changes['next_run_time'] = datetime.datetime.now()

        if changes:
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


def load_schedules_from_db(scheduler, schedules, first_run=False,
                           old_schedule_ids=[]):
    """ Load schedules from db """
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
    return new_schedule_ids


def _start_shard_manager(schedule_cls, current_shard_id):
    """Start the sharding process."""

    # The time-frame for which a shard assignment is considered valid. If a
    # document's `shard_update_at` field is not touched/renewed within this
    # period of time, then the document may be re-assigned to a different
    # shard.
    max_shard_period = config.SHARD_MANAGER_MAX_SHARD_PERIOD

    # The maximum number of documents that may be assigned to a single shard
    # at a time. This should be set to a meaningful value to not delay shard
    # assignment, but also prevent the majority of the documents from being
    # assigned to the same shard.
    max_shard_claims = config.SHARD_MANAGER_MAX_SHARD_CLAIMS

    # The amount of time the sharding thread may sleep in between checks. We
    # set this to a meaningful value to not delay shard assignment, but also
    # give time to other processes of the scheduler to claim their piece of
    # the pie.
    manager_interval = config.SHARD_MANAGER_INTERVAL

    assert current_shard_id
    assert manager_interval < max_shard_period

    # Perform the sharding in a separate thread.
    t = threading.Thread(target=_do_sharding,
                         args=(schedule_cls,
                               current_shard_id,
                               max_shard_period,
                               max_shard_claims,
                               manager_interval),
                         daemon=True)

    t.start()


def _do_sharding(schedule_cls, current_shard_id, max_shard_period,
                 max_shard_claims, manager_interval):
    """Shard the schedules' collection.

    This function is executed in a separate thread and is responsible for
    sharding the respective collection. Documents, whose shard identifier
    has not been set or renewed within a given timeframe, may be assigned
    to another shard.

    Each running thread attempts to claim as many documents as possible,
    until all documents have been assigned to a specific shard.

    Every time a new sharding thread starts, all shard identifiers reset
    and re-sharding occurs.

    """

    schedule_cls.objects.update(shard_id=None, shard_update_at=None)

    while True:
        now = datetime.datetime.utcnow()

        # Touch existing documents to renew the sharding period.
        objects = schedule_cls.objects(shard_id=current_shard_id)
        renewed = objects.update(shard_update_at=now)
        log.debug('%s renewed %s docs', current_shard_id, renewed)

        # Fetch documents which have either not been claimed or renewed.
        d = now - datetime.timedelta(seconds=max_shard_period)
        q = (me.Q(shard_update_at__lt=d) | me.Q(shard_update_at=None))
        q &= me.Q(shard_id__ne=current_shard_id)

        # Claim some of the documents. Note that we have to iterate the
        # limited cursor, instead of applying a bulk update.
        for doc in schedule_cls.objects(q).limit(max_shard_claims):
            doc.update(shard_id=current_shard_id, shard_update_at=now)
            log.debug('%s claimed %s', current_shard_id, doc.name)

        sleep(manager_interval)


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
        old_schedules = {}
        while True:  # Start main loop
            if kwargs.get('user'):
                log.info('Reloading user schedules')
                if not old_schedules.get('user', None):
                    old_schedules['user'] = []
                old_schedules['user'] = load_schedules_from_db(
                    scheduler,
                    Schedule.objects(deleted=False),
                    first_run=first_run,
                    old_schedule_ids=old_schedules['user']
                )
            if kwargs.get('polling'):
                if first_run is True:
                    current_shard_id = os.getenv('HOSTNAME', '')
                    _start_shard_manager(PollingSchedule, current_shard_id)
                log.info('Reloading polling schedules')
                if not old_schedules.get('polling', None):
                    old_schedules['polling'] = []
                old_schedules['polling'] = load_schedules_from_db(
                    scheduler,
                    PollingSchedule.objects(shard_id=current_shard_id),
                    first_run=first_run,
                    old_schedule_ids=old_schedules['polling']
                )
            if kwargs.get('rules'):
                log.info('Reloading rules')
                if not old_schedules.get('rules', None):
                    old_schedules['rules'] = []
                old_schedules['rules'] = load_schedules_from_db(
                    scheduler,
                    Rule.objects(),
                    old_schedule_ids=old_schedules['rules']
                )
            sleep(RELOAD_INTERVAL)
            first_run = False
    except KeyboardInterrupt:
        import ipdb
        ipdb.set_trace()
        scheduler.shutdown()
