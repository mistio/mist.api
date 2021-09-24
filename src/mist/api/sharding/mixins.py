import os
import time
import logging
import datetime
import threading
import mongoengine as me

import mist.api.config as config


log = logging.getLogger(__name__)


class ShardedScheduleMixin(object):
    """A Mixin class to make a collection shardable.

    This Mixin is required by mongoengine documents, which are loaded by a
    scheduler process that supports sharding. It may provide the necessary
    fields and methods common to all shardable mongo collections.

    """
    shard_id = me.StringField()
    shard_update_at = me.DateTimeField()


class ShardManagerMixin(object):
    """A Mixin class to make a scheduler process scalable.

    Any subclass of `celerybeatmongo.schedulers.MongoScheduler` can subclass
    this Mixin in order to create a scalable implementation of the scheduler.
    The only requirement is that the corresponding scheduler's `Model` class
    attribute is set to a class that subclasses the `ShardedScheduleMixin`,
    which is defined above and provides the additional fields necessary for
    shards' assignment.

    Each process of the scalable scheduler tries to claim as many documents
    as possible by assigning them his corresponding shard id.

    Documents, which have not been assigned to a specific shard or have not
    been touched within a given timeframe, can be claimed by any process of
    scheduler that is running.

    This Mixin SHOULD be last in the class hierarchy.

    """
    # The current process' shard id. The scheduler will only load documents
    # that are assigned to this specific shard.
    current_shard_id = os.getenv('HOSTNAME', '')

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

    def __init__(self, *args, **kwargs):
        super(ShardManagerMixin, self).__init__(*args, **kwargs)
        self._start_shard_manager()

    def get_from_database(self):
        """Load the schedules belonging to the current shard."""
        self.sync()
        return {doc.name: self.Entry(doc) for
                doc in self.Model.objects(shard_id=self.current_shard_id)}

    def _start_shard_manager(self):
        """Perform validation and start the sharding process."""
        assert self.current_shard_id
        assert self.manager_interval < self.max_shard_period
        assert self.manager_interval < self.UPDATE_INTERVAL.total_seconds()

        # Perform the sharding in a separate thread.
        t = threading.Thread(target=self._do_sharding)
        t.daemon = True
        t.start()

    def _do_sharding(self):
        """Shard the schedules' collection.

        This method is executed in a separate thread and is responsible for
        sharding the respective collection. Documents, whose shard identifier
        has not been set or renewed within a given timeframe, may be assigned
        to another shard.

        Each running thread attempts to claim as many documents as possible,
        until all documents have been assigned to a specific shard.

        Every time a new sharding thread starts, all shard identifiers reset
        and re-sharding occurs.

        """
        self.Model.objects.update(shard_id=None, shard_update_at=None)

        while True:
            now = datetime.datetime.utcnow()

            # Touch existing documents to renew the sharding period.
            objects = self.Model.objects(shard_id=self.current_shard_id)
            renewed = objects.update(shard_update_at=now)
            log.debug('%s renewed %s docs', self.current_shard_id, renewed)

            # Fetch documents which have either not been claimed or renewed.
            d = now - datetime.timedelta(seconds=self.max_shard_period)
            q = (me.Q(shard_update_at__lt=d) | me.Q(shard_update_at=None))
            q &= me.Q(shard_id__ne=self.current_shard_id)

            # Claim some of the documents. Note that we have to iterate the
            # limited cursor, instead of applying a bulk update.
            for doc in self.Model.objects(q).limit(self.max_shard_claims):
                doc.update(shard_id=self.current_shard_id, shard_update_at=now)
                log.debug('%s claimed %s', self.current_shard_id, doc.name)

            time.sleep(self.manager_interval)
