import datetime

from celery.beat import PersistentScheduler, ScheduleEntry


class RunImmediatelyScheduleEntry(ScheduleEntry):
    def _default_now(self):
        """This function returns the default value for `last_run_at`

        We return a very old date to cause schedule entries to run immediately
        if no `last_run_at` value is present.

        """
        if not self.total_run_count:
            return datetime.datetime(2000, 1, 1)
        return super(RunImmediatelyScheduleEntry, self)._default_now()


class RunImmediatelyPersistentScheduler(PersistentScheduler):
    Entry = RunImmediatelyScheduleEntry
