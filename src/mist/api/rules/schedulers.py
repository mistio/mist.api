from celerybeatmongo.schedulers import MongoScheduler

from mist.api.rules.models import Rule


class RuleScheduler(MongoScheduler):
    Model = Rule
