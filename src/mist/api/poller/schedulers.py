from celerybeatmongo.schedulers import MongoScheduler

from mist.api.poller.models import PollingSchedule

import datetime


class PollingScheduler(MongoScheduler):
    Model = PollingSchedule
    UPDATE_INTERVAL = datetime.timedelta(seconds=20)
