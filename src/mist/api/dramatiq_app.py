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
        msg_id = '{}: {}{}'.format(
            message.message_id, message.actor_name, str(message.args))
        msg = 'Starting task %s' % msg_id

        # try:
        #     sched = None
        #     if message._message.args:
        #         args = message._message.args
        #         if len(args) > 4:
        #             try:
        #                 sched = Schedule.objects.get(
        #                     name=args[2], owner=args[0], deleted=None)
        #             except Schedule.DoesNotExist:
        #                 pass
        #         if not sched and args:
        #             try:
        #                 sched = PollingSchedule.objects.get(
        #                     id=message._message.args[0])
        #             except me.ValidationError:
        #                 try:
        #                     sched = Rule.objects.get(
        #                         id=message._message.args[0])
        #                 except Rule.DoesNotExist:
        #                     log.warn("args: ", message._message,
        #                              dir(message._message))
        #         if getattr(sched, 'org', None):
        #             msg += "\nOrg: %s" % sched.org.name
        #         elif getattr(sched, 'cloud', None):
        #             msg += "\nCloud: %s\nOrg: %s" % (
        #                 sched.cloud.name, sched.cloud.org.name)
        #         elif getattr(sched, 'machine', None):
        #             msg += "\nMachine: %s\nCloud: %s\nOrg: %s" % (
        #                 sched.machine.name, sched.machine.cloud.name,
        #                 sched.machine.org.name)
        #         elif getattr(sched, 'get_resources', None):
        #             msg += "\nSchedule: %s\nResources: %s" % (
        #                 sched.name, sched.get_resources())
        #         else:
        #             msg += "\n%s - %s" % (
        #                 sched.__class__, getattr(sched, 'task', None)
        # except Exception as exc:
        #     log.error('%r' % exc)
        log.info(msg)
        self.state.msg_id = msg_id
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


broker = RabbitmqBroker(url=config.BROKER_URL + '?heartbeat=600')
broker.add_middleware(LoggingMiddleware())
broker.add_middleware(MongoConnectMiddleware())
result_backend = MemcachedBackend(servers=config.MEMCACHED_HOST)
broker.add_middleware(Results(backend=result_backend))
dramatiq.set_broker(broker)
