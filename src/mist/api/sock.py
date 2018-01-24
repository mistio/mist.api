"""mist.api.socket.

Here we define the sockjs Connection and handlers.

When a user loads mist.io or comes back online, their browser will request a
new socket and the initialize function will be triggered on the server within a
greenlet.

"""

import uuid
import json
import time
import random
import traceback
import datetime

import tornado.gen

from sockjs.tornado import SockJSConnection, SockJSRouter
from mist.api.sockjs_mux import MultiplexConnection

from mist.api.logs.methods import log_event
from mist.api.logs.methods import get_stories

from mist.api.clouds.models import Cloud

from mist.api.auth.methods import auth_context_from_session_id

from mist.api.exceptions import UnauthorizedError, MistError
from mist.api.exceptions import PolicyUnauthorizedError
from mist.api.amqp_tornado import Consumer

from mist.api.clouds.methods import filter_list_clouds
from mist.api.keys.methods import filter_list_keys
from mist.api.machines.methods import filter_list_machines, filter_machine_ids
from mist.api.scripts.methods import filter_list_scripts
from mist.api.schedules.methods import filter_list_schedules
from mist.api.dns.methods import filter_list_zones

from mist.api import tasks
from mist.api.hub.tornado_shell_client import ShellHubClient

from mist.api.notifications.models import InAppNotification

try:
    from mist.core.methods import get_stats, get_load, check_monitoring
    from mist.core.methods import get_user_data, filter_list_tags
    from mist.core.methods import filter_list_vpn_tunnels
    from mist.core.rbac.methods import filter_org
    from mist.core.orchestration.methods import filter_list_templates
    from mist.core.orchestration.methods import filter_list_stacks
except ImportError:
    from mist.api.dummy.methods import get_stats, get_load, check_monitoring
    from mist.api.dummy.methods import filter_list_tags
    from mist.api.dummy.methods import filter_list_vpn_tunnels
    from mist.api.users.methods import filter_org
    from mist.api.dummy.methods import filter_list_templates
    from mist.api.dummy.methods import filter_list_stacks
    from mist.api.users.methods import get_user_data

from mist.api import config

import logging
logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)


# hold all open connections to properly clean them up in case of SIGTERM
CONNECTIONS = set()


def get_conn_info(conn_info):
    real_ip = forwarded_for = user_agent = ''
    for header in conn_info.headers:
        if header.lower() == 'x-real-ip':
            real_ip = conn_info.headers[header]
        elif header.lower() == 'x-forwarded-for':
            forwarded_for = conn_info.headers[header]
        elif header.lower() == 'user-agent':
            user_agent = conn_info.headers[header]
    ip = real_ip or forwarded_for or conn_info.ip
    session_id = ''
    if 'session.id' in conn_info.cookies.keys():
        session_id = conn_info.cookies['session.id'].value
    return ip, user_agent, session_id


class MistConnection(SockJSConnection):
    closed = False

    def on_open(self, conn_info):
        log.info("%s: Initializing", self.__class__.__name__)
        self.ip, self.user_agent, session_id = get_conn_info(conn_info)
        log.info("Got connection info: %s %s %s",
                 self.ip, self.user_agent, session_id)
        try:
            self.auth_context = auth_context_from_session_id(session_id)
            log.info("Got auth context %s for session %s",
                     self.auth_context.owner.id, session_id)
        except UnauthorizedError:
            log.error("%s: Unauthorized session_id", self.__class__.__name__)
            self.send('logout')
            self.close()
            raise
        else:
            self.user = self.auth_context.user
            self.owner = self.auth_context.owner
            self.session_id = uuid.uuid4().hex
            CONNECTIONS.add(self)

    def send(self, msg, data=None):
        super(MistConnection, self).send(json.dumps({msg: data}))

    def on_close(self, stale=False):
        if not self.closed:
            log.info("%s: on_close event handler", self.__class__.__name__)
            if stale:
                log.warning("stale conn removed")
            CONNECTIONS.remove(self)
            self.closed = True
        else:
            log.warning("%s: called on_close AGAIN!", self.__class__.__name__)
            traceback.print_stack()

    def get_dict(self):
        return {
            'name': self.session.name,
            'last_rcv': self.session.base.last_rcv,
            'user': self.user.email,
            'ip': self.ip,
            'user_agent': self.user_agent,
            'closed': self.is_closed,
            'session_id': self.session_id,
        }

    def __repr__(self):
        conn_dict = self.get_dict()
        parts = []
        dt_last_rcv = datetime.datetime.fromtimestamp(conn_dict['last_rcv'])
        conn_dict['last_rcv'] = dt_last_rcv
        for key in ('name', 'last_rcv', 'user', 'ip', 'user_agent', 'closed',
                    'session_id'):
            if key in conn_dict:
                parts.append(conn_dict.pop(key))
        parts.extend(conn_dict.values())
        return ' - '.join(map(str, parts))


class ShellConnection(MistConnection):
    def on_open(self, conn_info):
        super(ShellConnection, self).on_open(conn_info)
        self.hub_client = None
        self.ssh_info = {}

    def on_shell_open(self, data):
        if self.ssh_info:
            self.close()
        try:
            if not data.get('job_id'):
                self.auth_context.check_perm(
                    'machine', 'open_shell', data['machine_id']
                )
        except PolicyUnauthorizedError as err:
            self.emit_shell_data('%s' % err)
            self.close()
            return

        self.ssh_info = {
            'job_id': data.get('job_id', ''),
            'cloud_id': data.get('cloud_id', ''),
            'machine_id': data.get('machine_id', ''),
            'host': data.get('host'),
            'columns': data['cols'],
            'rows': data['rows'],
            'ip': self.ip,
            'user_agent': self.user_agent,
            'owner_id': self.auth_context.owner.id,
            'user_id': self.user.id,
            'provider': data.get('provider', '')
        }
        self.hub_client = ShellHubClient(worker_kwargs=self.ssh_info)
        self.hub_client.on_data = self.emit_shell_data
        self.hub_client.start()
        log.info('on_shell_open finished')

    def on_shell_data(self, data):
        self.hub_client.send_data(data)

    def on_shell_resize(self, columns, rows):
        self.hub_client.resize(columns, rows)

    def emit_shell_data(self, data):
        self.send('shell_data', data)

    def on_close(self, stale=False):
        if self.hub_client:
            self.hub_client.stop()
        super(ShellConnection, self).on_close(stale=stale)


class OwnerUpdatesConsumer(Consumer):
    def __init__(self, main_sockjs_conn,
                 amqp_url=config.BROKER_URL):
        self.sockjs_conn = main_sockjs_conn
        super(OwnerUpdatesConsumer, self).__init__(
            amqp_url=amqp_url,
            exchange='owner_%s' % self.sockjs_conn.owner.id,
            queue='mist-socket-%d' % random.randrange(2 ** 20),
            exchange_type='fanout',
            exchange_kwargs={'auto_delete': True},
            queue_kwargs={'auto_delete': True, 'exclusive': True},
        )

    def on_message(self, unused_channel, basic_deliver, properties, body):
        super(OwnerUpdatesConsumer, self).on_message(
            unused_channel, basic_deliver, properties, body
        )
        self.sockjs_conn.process_update(
            unused_channel, basic_deliver, properties, body
        )

    def start_consuming(self):
        super(OwnerUpdatesConsumer, self).start_consuming()
        self.sockjs_conn.start()


class LogsConsumer(Consumer):

    def __init__(self, owner_id, callback, amqp_url=config.BROKER_URL):
        super(LogsConsumer, self).__init__(
            amqp_url=amqp_url,
            exchange='events',
            queue='mist-logs-%d' % random.randrange(2 ** 20),
            exchange_type='topic',
            routing_key='%s.*.*.*' % owner_id,
            exchange_kwargs={'auto_delete': False},
            queue_kwargs={'auto_delete': True, 'exclusive': True},
        )
        self.callback = callback

    def on_message(self, unused_channel, basic_deliver, properties, body):
        super(LogsConsumer, self).on_message(
            unused_channel, basic_deliver, properties, body
        )
        self.callback(json.loads(body))


class MainConnection(MistConnection):

    def on_open(self, conn_info):
        log.info("************** Open!")
        super(MainConnection, self).on_open(conn_info)
        self.running_machines = set()
        self.consumer = None
        self.log_kwargs = {
            'ip': self.ip,
            'user_agent': self.user_agent,
            'session_id': self.session_id,
            'user_id': self.auth_context.user.id,
            'owner_id': self.auth_context.owner.id,
            'event_type': 'session'
        }
        if self.auth_context.token.su:
            self.log_kwargs['su'] = self.auth_context.token.su
        log.info('About to log open event %s', self.auth_context.owner.id)
        log_event(action='connect', **self.log_kwargs)
        log.info('Done %s', self.auth_context.owner.id)

    def on_ready(self):
        log.info("************** Ready to go! %s", self.auth_context.owner.id)
        if self.consumer is None:
            self.consumer = OwnerUpdatesConsumer(self)
            self.consumer.run()
        else:
            log.error("It seems we have received 'on_ready' more than once.")

    def start(self):
        self.update_user()
        self.update_org()
        self.list_tags()
        self.list_keys()
        self.list_scripts()
        self.list_schedules()
        self.list_templates()
        self.list_stacks()
        self.list_tunnels()
        self.list_clouds()
        self.update_notifications()
        self.check_monitoring()
        self.periodic_update_poller()

    @tornado.gen.coroutine
    def periodic_update_poller(self):
        while True:
            if self.closed:
                break
            self.update_poller()
            yield tornado.gen.sleep(100)

    def update_poller(self):
        """Increase polling frequency for all clouds"""
        tasks.update_poller.delay(self.owner.id)

    def update_user(self):
        self.send('user', get_user_data(self.auth_context))

    def update_org(self):
        try:
            org = filter_org(self.auth_context)
        except:  # Forbidden
            org = None

        if org:
            self.send('org', org)

    def list_tags(self):
        self.send('list_tags', filter_list_tags(self.auth_context))

    def list_keys(self):
        self.send('list_keys', filter_list_keys(self.auth_context))

    def list_scripts(self):
        self.send('list_scripts', filter_list_scripts(self.auth_context))

    def list_schedules(self):
        self.send('list_schedules', filter_list_schedules(self.auth_context))

    def list_templates(self):
        self.send('list_templates', filter_list_templates(self.auth_context))

    def list_stacks(self):
        self.send('list_stacks', filter_list_stacks(self.auth_context))

    def list_tunnels(self):
        self.send('list_tunnels', filter_list_vpn_tunnels(self.auth_context))

    def list_clouds(self):
        self.update_poller()
        self.send('list_clouds', filter_list_clouds(self.auth_context))
        clouds = Cloud.objects(owner=self.owner, enabled=True, deleted=None)
        log.info(clouds)
        periodic_tasks = []
        for cloud in clouds:
            machines = cloud.ctl.compute.list_cached_machines()
            machines = filter_list_machines(
                self.auth_context, cloud_id=cloud.id,
                machines=[machine.as_dict() for machine in machines]
            )
            log.info("Emitting list_machines from poller's cache.")
            self.send('list_machines',
                      {'cloud_id': cloud.id, 'machines': machines})

            cached_locations = cloud.ctl.compute.list_cached_locations()
            locations = [location.as_dict() for location in cached_locations]
            log.info("Emitting list_locations from poller's cache.")
            self.send('list_locations',
                      {'cloud_id': cloud.id, 'locations': locations})

            cached_zones = cloud.ctl.dns.list_cached_zones()
            zones = [zone.as_dict() for zone in cached_zones]
            log.info("Emitting list_zones from poller's cache.")
            self.send('list_zones',
                      {'cloud_id': cloud.id, 'zones': zones})

        periodic_tasks.extend([('list_images', tasks.ListImages()),
                               ('list_sizes', tasks.ListSizes()),
                               ('list_networks', tasks.ListNetworks()),
                               ('list_resource_groups',
                                tasks.ListResourceGroups()),
                               ('list_storage_accounts',
                                tasks.ListStorageAccounts()),
                               ('list_projects', tasks.ListProjects())])
        for key, task in periodic_tasks:
            for cloud in clouds:
                cached = task.smart_delay(self.owner.id, cloud.id)
                if cached is not None:
                    log.info("Emitting %s from cache", key)
                    if key == 'list_machines':
                        cached['machines'] = filter_list_machines(
                            self.auth_context, **cached
                        )
                        if cached['machines'] is None:
                            continue
                    elif key == 'list_zones':
                        cached = filter_list_zones(
                            self.auth_context, cloud.id, cached['zones']
                        )
                        if cached is None:
                            continue
                    self.send(key, cached)

    def update_notifications(self):
        user = self.auth_context.user
        org = self.auth_context.org
        notifications_json = InAppNotification.objects(
            user=user, organization=org, dismissed=False).to_json()
        log.info("Emitting notifications list")
        self.send('notifications', notifications_json)

    def check_monitoring(self):
        func = check_monitoring
        try:
            self.send('monitoring', func(self.owner))
        except Exception as exc:
            log.warning("Check monitoring failed with: %r", exc)

    def on_stats(self, cloud_id, machine_id, start, stop, step, request_id,
                 metrics):

        def callback(data, error=False):
            ret = {
                'cloud_id': cloud_id,
                'machine_id': machine_id,
                'start': start,
                'stop': stop,
                'request_id': request_id,
                'metrics': data,
            }
            if error:
                ret['error'] = error
                log.error(ret)
            self.send('stats', ret)

        try:
            if not cloud_id and not machine_id and (
                not metrics or metrics == ['load.shortterm']
            ):
                get_load(self.owner, start, stop, step,
                         tornado_callback=callback)
            else:
                get_stats(self.owner, cloud_id, machine_id, start, stop, step,
                          metrics=metrics, callback=callback,
                          tornado_async=True)
        except MistError as exc:
            callback([], str(exc))
        except Exception as exc:
            log.error("Exception in get_stats: %r", exc)

    def process_update(self, ch, method, properties, body):
        routing_key = method.routing_key
        try:
            result = json.loads(body)
        except:
            result = body
        log.info("Got %s", routing_key)
        if routing_key in set(['notify', 'probe', 'list_sizes', 'list_images',
                               'list_networks', 'list_machines', 'list_zones',
                               'list_locations', 'list_projects', 'ping',
                               'list_resource_groups',
                               'list_storage_accounts']):
            if routing_key == 'list_machines':
                # probe newly discovered running machines
                machines = result['machines']
                cloud_id = result['cloud_id']
                filtered_machines = filter_list_machines(
                    self.auth_context, cloud_id, machines
                )
                if filtered_machines is not None:
                    self.send(routing_key, {'cloud_id': cloud_id,
                                            'machines': filtered_machines})
                # update cloud machine count in multi-user setups
                cloud = Cloud.objects.get(owner=self.owner, id=cloud_id,
                                          deleted=None)
                for machine in machines:
                    bmid = (cloud_id, machine['machine_id'])
                    if bmid in self.running_machines:
                        # machine was running
                        if machine['state'] != 'running':
                            # machine no longer running
                            self.running_machines.remove(bmid)
                        continue
                    if machine['state'] != 'running':
                        # machine not running
                        continue
                    # machine just started running
                    self.running_machines.add(bmid)

                    ips = filter(lambda ip: ':' not in ip,
                                 machine.get('public_ips', []))
                    if not ips:
                        # if not public IPs, search for private IPs, otherwise
                        # continue iterating over the list of machines
                        ips = filter(lambda ip: ':' not in ip,
                                     machine.get('private_ips', []))
                        if not ips:
                            continue

            elif routing_key == 'list_zones':
                zones = result['zones']
                cloud_id = result['cloud_id']
                filtered_zones = filter_list_zones(
                    self.auth_context, cloud_id, zones
                )
                self.send(routing_key, filtered_zones)
            else:
                self.send(routing_key, result)

        elif routing_key == 'update':
            self.owner.reload()
            sections = result
            if 'clouds' in sections:
                self.list_clouds()
            if 'keys' in sections:
                self.list_keys()
            if 'scripts' in sections:
                self.list_scripts()
            if 'schedules' in sections:
                self.list_schedules()
            if 'zones' in sections:
                task = tasks.ListZones()
                clouds = Cloud.objects(owner=self.owner,
                                       enabled=True,
                                       deleted=None)
                for cloud in clouds:
                    if cloud.dns_enabled:
                        task.smart_delay(self.owner.id, cloud.id)
            if 'templates' in sections:
                self.list_templates()
            if 'stacks' in sections:
                self.list_stacks()
            if 'tags' in sections:
                self.list_tags()
            if 'tunnels' in sections:
                self.list_tunnels()
            if 'notifications' in sections:
                self.update_notifications()
            if 'monitoring' in sections:
                self.check_monitoring()
            if 'user' in sections:
                self.auth_context.user.reload()
                self.update_user()
            if 'org' in sections:
                self.auth_context.org.reload()
                self.update_org()

        elif routing_key == 'patch_notifications':
            if json.loads(result).get('user') == self.user.id:
                self.send('patch_notifications', result)

        elif routing_key == 'patch_machines':
            cloud_id = result['cloud_id']
            patch = result['patch']
            machine_ids = []
            for line in patch:
                machine_id, line['path'] = line['path'][1:].split('-', 1)
                machine_ids.append(machine_id)
            if not self.auth_context.is_owner():
                allowed_machine_ids = filter_machine_ids(self.auth_context,
                                                         cloud_id, machine_ids)
            else:
                allowed_machine_ids = machine_ids
            patch = [line for line, m_id in zip(patch, machine_ids)
                     if m_id in allowed_machine_ids]
            for line in patch:
                line['path'] = '/clouds/%s/machines/%s' % (cloud_id,
                                                           line['path'])
            if patch:
                self.send('patch_model', patch)

    def on_close(self, stale=False):
        if not self.closed:
            kwargs = {}
            if stale:
                kwargs['stale'] = True
            kwargs.update(self.log_kwargs)
            log_event(action='disconnect', **kwargs)
        if self.consumer is not None:
            try:
                self.consumer.stop()
            except Exception as exc:
                log.error("Error closing pika consumer: %r", exc)
        super(MainConnection, self).on_close(stale=stale)


class LogsConnection(MistConnection):

    def on_open(self, conn_info):
        """Open a new connection bound to the current Organization."""
        super(LogsConnection, self).on_open(conn_info)
        self.enabled = True
        self.consumer = None
        self.enforce_logs_for = self.auth_context.org.id

    def on_ready(self):
        """Initiate the RabbitMQ Consumer."""
        if not self.enabled:
            for stype in ('incident', 'job', 'shell', 'session'):
                self.send('open_' + stype + 's', [])
            return
        if self.consumer is None:
            self.consumer = LogsConsumer(self.enforce_logs_for or '*',
                                         self.emit_event)
            self.consumer.run()
        else:
            log.error("It seems we have received 'on_ready' more than once.")
        for stype in ('incident', 'job', 'shell', 'session'):
            self.send_stories(stype)

    def emit_event(self, event):
        """Emit a new event consumed from RabbitMQ."""
        log.info('Received event from amqp')
        event.pop('_id', None)
        try:
            for key, value in json.loads(event.pop('extra')).iteritems():
                event[key] = value
        except:
            pass
        for stype in set([stype for _, stype, _ in event.get('stories', [])]):
            self.send_stories(stype)
        if self.filter_log(event):
            self.send('event', self.parse_log(event))

    def send_stories(self, stype):
        """Send open stories of the specified type."""

        def callback(stories, pending=False):
            email = self.auth_context.user.email
            ename = '%s_%ss' % ('open' if pending else 'closed', stype)
            log.info('Will emit %d %s for %s', len(stories), ename, email)
            self.send(ename, stories)

        # Only send incidents for non-Owners.
        if not self.auth_context.is_owner() and stype != 'incident':
            self.send('open_%ss' % stype, [])
            return

        # Fetch the latest open stories.
        kwargs = {
            'story_type': stype,
            'pending': True,
            'range': {
                '@timestamp': {
                    'gte': int((time.time() - 7 * 24 * 60 * 60) * 1000)
                }
            }
        }

        if self.enforce_logs_for is not None:
            kwargs['owner_id'] = self.enforce_logs_for

        get_stories(tornado_async=True, tornado_callback=callback, **kwargs)

        # Fetch also the latest, closed incidents.
        if stype == 'incident':
            kwargs.update({'limit': 10, 'pending': False})
            get_stories(tornado_async=True,
                        tornado_callback=callback, **kwargs)

    def parse_log(self, event):
        """Parse a single log.

        This method may be used to perform custom parsing/editting of logs.

        Override this method in order to add/remove fields to/from a log entry.

        """
        for param in ('@version', 'stories', 'tags', '_traceback', '_exc', ):
            event.pop(param, None)
        return event

    def filter_log(self, event):
        """Filter logs on the fly.

        This method may be used to perform custom filtering of logs on the fly.
        Override this method in order to filter single logs, if necessary. By
        default, the log entry is returned as is.

        """
        return event

    def on_close(self, stale=False):
        """Stop the Consumer and close the WebSocket."""
        if self.consumer is not None:
            try:
                self.consumer.stop()
            except Exception as exc:
                log.error("Error closing pika consumer: %r", exc)
        super(LogsConnection, self).on_close(stale=stale)


def make_router():
    return SockJSRouter(
        MultiplexConnection.get(
            main=MainConnection,
            logs=LogsConnection,
            shell=ShellConnection,
        ),
        '/socket'
    )
