from celerybeatmongo.schedulers import MongoScheduler

from mist.api.rules.models import Rule

import datetime


class RuleScheduler(MongoScheduler):
    Model = Rule
    UPDATE_INTERVAL = datetime.timedelta(seconds=20)
