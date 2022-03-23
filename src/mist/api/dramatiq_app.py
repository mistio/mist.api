import os
import logging
from threading import local
from time import perf_counter

# import mongoengine as me
import dramatiq

from dramatiq.middleware import Middleware
from dramatiq.brokers.rabbitmq import RabbitmqBroker
from dramatiq.results.backends import MemcachedBackend
from dramatiq.results import Results

from mist.api import config
# from mist.api.poller.models import PollingSchedule
# from mist.api.rules.models import Rule
# from mist.api.schedules.models import Schedule

log = logging.getLogger(__name__)


class LoggingMiddleware(Middleware):
    """Logging for tasks processed on the workers."""

    state = local()

    def before_process_message(self, broker, message):
        log.info('Starting task %s %s', message.message_id, message)
        self.state.msg_id = message.message_id
        self.state.start = perf_counter()

    def after_process_message(self, broker, message, *,
                              result=None, exception=None):
        try:
            delta = perf_counter() - self.state.start
            outcome = 'Task failed' if exception else 'Completed task'
            log.info("%s %s - %.02fms elapsed.", outcome,
                     self.state.msg_id, delta * 1000)
            del self.state.start
            del self.state.msg_id
        except AttributeError:
            pass

    after_skip_message = after_process_message


class MongoConnectMiddleware(Middleware):
    """Connect to mongodb on worker boot"""

    def after_worker_boot(self, broker, worker):
        from mist.api import mongo_connect
        mongo_connect()


if (config.SENTRY_CONFIG.get('DRAMATIQ_URL') and
        os.getenv('DRAMATIQ_CONTEXT')):
    import sentry_sdk
    import sentry_dramatiq
    from mist.api.helpers import get_version_string
    sentry_sdk.init(
        config.SENTRY_CONFIG['DRAMATIQ_URL'],
        integrations=[sentry_dramatiq.DramatiqIntegration()],
        environment=config.SENTRY_CONFIG['ENVIRONMENT'],
        release=get_version_string(),
    )

broker = RabbitmqBroker(url=config.BROKER_URL + '?heartbeat=600')
broker.add_middleware(LoggingMiddleware())
broker.add_middleware(MongoConnectMiddleware())
result_backend = MemcachedBackend(servers=config.MEMCACHED_HOST)
broker.add_middleware(Results(backend=result_backend))
dramatiq.set_broker(broker)
