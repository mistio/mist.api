import uuid
import time
import logging
import datetime
import contextlib

import mongoengine as me

from mist.api.exceptions import MistError

log = logging.getLogger(__name__)


class PeriodicTaskThresholdExceeded(Exception):
    pass


class PeriodicTaskTooRecentLastRun(Exception):
    pass


class PeriodicTaskLockTakenError(MistError):
    msg = "Periodic task lock taken"
    http_code = 423


class PeriodicTaskInfo(me.Document):

    class Lock(me.EmbeddedDocument):
        id = me.StringField(default=lambda: uuid.uuid4().hex)
        created = me.DateTimeField(default=lambda: datetime.datetime.now())

    # Unique task identifier.
    key = me.StringField(primary_key=True)

    # Track successes/failures for autodisabling.
    last_success = me.DateTimeField()
    last_failure = me.DateTimeField()
    failures_count = me.IntField(default=0)

    # Lock to prevent concurrent running of the same task.
    lock = me.EmbeddedDocumentField(Lock)

    # Class attributes (NOT FIELDS). This define constants on the class.
    # Subclasses may override by setting attributes, dynamic properties or
    # fields.

    # Task won't be autodisabled if it has failed less times.
    min_failures_count = 50
    # Task won't be autodisabled if it has succeeded in this period.
    min_failures_period = datetime.timedelta(hours=1)
    # Task will be autodisabled if it has failed more times.
    max_failures_count = 100
    # Task will be autodisabled if it hasn't succeeded in this period.
    max_failures_period = datetime.timedelta(days=2)

    # Lock will be broken if it was last acquired more than this time ago.
    break_lock_after = datetime.timedelta(seconds=300)

    # Abort task if previous attempt was in less than this time before.
    min_interval = datetime.timedelta(seconds=5)

    @classmethod
    def get_or_add(cls, key):
        try:
            task = cls.objects.get(key=key)
        except cls.DoesNotExist:
            log.info("PeriodicTaskInfo for '%s' missing, will create.", key)
            task = cls(key=key)
            try:
                task.save()
            except me.NotUniqueError:
                # Work around race condition where document was created since
                # we checked.
                log.warning("PeriodicTaskInfo for '%s' creation race "
                            "condition, will reload.", key)
                task = cls.objects.get(key=key)
        log.debug("Loaded PeriodicTaskInfo for '%s'.", key)
        return task

    def get_last_run(self):
        if self.last_success and self.last_failure:
            return max(self.last_success, self.last_failure)
        return self.last_success or self.last_failure

    def check_failures_threshold_exceeded(self):
        """Raise PeriodicTaskThresholdExceeed if task should be autodisabled"""

        now = datetime.datetime.now()

        # If it hasn't run recently, then allow it to run.
        last_run = self.get_last_run()
        if not last_run or now - last_run > datetime.timedelta(days=1):
            return

        # Not exceeded if it hasn't failed enough times.
        if self.min_failures_count is not None:
            if self.failures_count < self.min_failures_count:
                return

        # Not exceeded if it hasn't failed for long enough.
        if self.min_failures_period is not None:
            if now - self.last_failure < self.min_failures_period:
                return

        # Exceeded if it has failed too many times.
        if self.max_failures_count is not None:
            if self.failures_count > self.max_failures_count:
                raise PeriodicTaskThresholdExceeded()

        # Exceed if it has been failing for too long.
        if self.max_failures_period is not None:
            if now - self.last_failure > self.max_failures_period:
                raise PeriodicTaskThresholdExceeded()

        # None of the conditions matched, so threshold hasn't been exceeded.
        return

    def check_too_soon(self):
        """Raise error if task has been run too recently"""
        now = datetime.datetime.now()
        # Find last run. If too recent, abort.
        if self.min_interval:
            last_run = self.get_last_run()
            if last_run:
                if now - last_run < self.min_interval:
                    raise PeriodicTaskTooRecentLastRun()

    def acquire_lock(self, attempts=1, retry_sleep=1):
        """Acquire run lock"""
        # Is another same task running?
        for i in range(attempts):
            if not self.lock:
                break
            if self.break_lock_after:
                now = datetime.datetime.now()
                if now - self.lock.created > self.break_lock_after:
                    # Has been running for too long or has died. Ignore.
                    log.error("Other task '%s' seems to have started, but "
                              "it's been quite a while, will ignore and run.",
                              self.key)
                    break
            if i < attempts - 1:
                time.sleep(retry_sleep)
                self.reload()
        else:
            log.warning("Lock for task '%s' is taken.", self.key)
            raise PeriodicTaskLockTakenError()
        self.lock = self.Lock()
        self.save()

    def release_lock(self):
        lock_id = self.lock.id
        self.reload()
        if not self.lock or lock_id != self.lock.id:
            log.error("Someone broke our lock for task '%s' since we "
                      "acquired it!", self.key)
            return
        self.lock = None
        self.save()

    @contextlib.contextmanager
    def task_runner(self, persist=False):
        """Context manager to run periodic tasks that update model state

        This is a context manager, so it meant be used in a `with` statement,
        like this:

            with task_runner('unique-task-key'):
                do_something()

        What this does:
        1. Takes care of using locks to prevent concurrent runs of the same
           task.
        2. Tracks last success, last failure, and failure count of this task.

        """

        if not persist:
            self.check_failures_threshold_exceeded()
            self.check_too_soon()
        self.acquire_lock(attempts=60 if persist else 1)

        try:
            yield
        except Exception:
            self.last_failure = datetime.datetime.now()
            self.failures_count += 1
            raise
        else:
            self.last_success = datetime.datetime.now()
            self.failures_count = 0
        finally:
            self.last_attempt_started = None
            self.save()
            self.release_lock()

    def __str__(self):
        return '%s: %s' % (self.__class__.__name__, self.id)
