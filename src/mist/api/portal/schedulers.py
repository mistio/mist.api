import datetime

from celery.beat import PersistentScheduler, ScheduleEntry


class RunImmediatelyScheduleEntry(ScheduleEntry):
    def _default_now(self):
        """This function returns the default value for `last_run_at`

        We return a very old date to cause schedule entries to run immediately
        if no `last_run_at` value is present.

        """
        return datetime.datetime(2000, 1, 1)


class RunImmediatelyPersistentScheduler(PersistentScheduler):
    Entry = RunImmediatelyScheduleEntry
