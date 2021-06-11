import logging
from threading import local
from time import perf_counter

import dramatiq
from dramatiq.middleware import Middleware
from dramatiq.brokers.rabbitmq import RabbitmqBroker

from mist.api import config

log = logging.getLogger(__name__)


class LoggingMiddleware(Middleware):
    """Logging for tasks processed on the workers."""

    state = local()

    def before_process_message(self, broker, message):
        msg_id = '{}[{}]'.format(message.actor_name, message.message_id)
        log.info('Starting task:  %s', msg_id)
        self.state.msg_id = msg_id
        self.state.start = perf_counter()

    def after_process_message(self, broker, message, *,
                              result=None, exception=None):
        try:
            delta = perf_counter() - self.state.start
            outcome = 'Task failed' if exception else 'Completed task'
            log.info("%s: %s - %.02fms elapsed.", outcome,
                     self.state.msg_id, delta * 1000)
            del self.state.start
            del self.state.msg_id
        except AttributeError:
            pass

    after_skip_message = after_process_message


broker = RabbitmqBroker(url=config.BROKER_URL)
broker.add_middleware(LoggingMiddleware())
dramatiq.set_broker(broker)
