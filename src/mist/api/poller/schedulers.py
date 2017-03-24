from celerybeatmongo.schedulers import MongoScheduler

from mist.api.poller.models import PollingSchedule


class PollingScheduler(MongoScheduler):
    Model = PollingSchedule
