from celerybeatmongo.schedulers import MongoScheduler

from mist.api.sharding.mixins import ShardManagerMixin

from mist.api.poller.models import PollingSchedule
from mist.api.poller.models import OwnerPollingSchedule
from mist.api.poller.models import CloudPollingSchedule
from mist.api.poller.models import MachinePollingSchedule

import datetime


class PollingScheduler(MongoScheduler):
    Model = PollingSchedule
    UPDATE_INTERVAL = datetime.timedelta(seconds=20)


class OwnerPollingScheduler(MongoScheduler):
    Model = OwnerPollingSchedule
    UPDATE_INTERVAL = datetime.timedelta(seconds=20)


class CloudPollingScheduler(MongoScheduler):
    Model = CloudPollingSchedule
    UPDATE_INTERVAL = datetime.timedelta(seconds=20)


class MachinePollingScheduler(MongoScheduler):
    Model = MachinePollingSchedule
    UPDATE_INTERVAL = datetime.timedelta(seconds=20)


class ShardedOwnerScheduler(ShardManagerMixin, OwnerPollingScheduler):
    pass


class ShardedCloudScheduler(ShardManagerMixin, CloudPollingScheduler):
    pass


class ShardedMachineScheduler(ShardManagerMixin, MachinePollingScheduler):
    pass
