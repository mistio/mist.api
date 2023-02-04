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
import logging
import datetime
import traceback

import tornado.gen
import tornado.httpclient

from sockjs.tornado import SockJSConnection, SockJSRouter
from mist.api.helpers import es_client
from mist.api.sockjs_mux import MultiplexConnection

from mist.api.logs.methods import log_event
from mist.api.logs.methods import get_stories
from mist.api.logs.methods import create_stories_patch

from mist.api.machines.models import Machine

from mist.api.auth.methods import auth_context_from_session_id

from mist.api.helpers import filter_resource_ids

from mist.api.exceptions import UnauthorizedError, MistError
from mist.api.exceptions import PolicyUnauthorizedError
from mist.api.amqp_tornado import Consumer

from mist.api.clouds.methods import filter_list_clouds

from mist.api import tasks
from mist.api.hub.tornado_shell_client import ShellHubClient

from mist.api.notifications.models import InAppNotification

from mist.api.monitoring.methods import check_monitoring

from mist.api.users.methods import filter_org
from mist.api.users.methods import get_user_data

from mist.api.portal.models import Portal

from mist.api import config

if config.HAS_RBAC:
    from mist.rbac.methods import filter_log_event


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
    if 'session.id' in list(conn_info.cookies.keys()):
        session_id = conn_info.cookies['session.id'].value
    return ip, user_agent, session_id


class MistConnection(SockJSConnection):
    closed = False

    def on_open(self, conn_info):
        log.info("%s: Initializing", self.__class__.__name__)
        self.ip, self.user_agent, self.cookie_session_id = get_conn_info(
            conn_info)
        try:
            self.auth_context = auth_context_from_session_id(
                self.cookie_session_id)
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

    @tornado.gen.coroutine
    def internal_request(self, path, params=None, callback=None):
        if path.startswith('/'):
            path = path[1:]
        if isinstance(params, dict):
            params = list(params.items())
        if params:
            path += '?' + '&'.join('%s=%s' % item
                                   for item in params)

        def response_callback(resp):
            if resp.code == 200:
                data = json.loads(resp.body)
                if callback is None:
                    print(data)
                else:
                    callback(data)
            else:
                log.error("Error requesting %s from internal API: (%s) %s",
                          path, resp.code, resp.body)

        headers = {'Authorization': 'internal %s %s' % (
            Portal.get_singleton().internal_api_key, self.cookie_session_id)}
        client = tornado.httpclient.AsyncHTTPClient(
            force_instance=True, max_clients=100)
        response = yield client.fetch(
            '%s/%s' % (config.INTERNAL_API_URL, path),
            headers=headers,
            connect_timeout=600, request_timeout=600,
        )
        response_callback(response)

    def __repr__(self):
        conn_dict = self.get_dict()
        parts = []
        dt_last_rcv = datetime.datetime.fromtimestamp(conn_dict['last_rcv'])
        conn_dict['last_rcv'] = dt_last_rcv
        for key in ('name', 'last_rcv', 'user', 'ip', 'user_agent', 'closed',
                    'session_id'):
            if key in conn_dict:
                parts.append(conn_dict.pop(key))
        parts.extend(list(conn_dict.values()))
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
                m = Machine.objects.get(id=data['machine_id'])
                self.auth_context.check_perm('machine', 'open_shell', m.id)
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
        self.batch = []
        self.log_kwargs = {
            'ip': self.ip,
            'user_agent': self.user_agent,
            'sockjs_session_id': self.session_id,
            'session_id': str(self.auth_context.token.id),
            'user_id': self.auth_context.user.id,
            'owner_id': self.auth_context.owner.id,
            'event_type': 'session'
        }
        if self.auth_context.token.su:
            self.log_kwargs['su'] = self.auth_context.token.su
        log_event(action='connect', **self.log_kwargs)

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
        self.send_batch_update()

    @tornado.gen.coroutine
    def send_batch_update(self):
        """Send model patches in batches."""
        while True:
            if self.closed:
                break
            if self.batch:
                self.send('patch_model', self.batch)
                self.batch = []
            yield tornado.gen.sleep(5)

    @tornado.gen.coroutine
    def periodic_update_poller(self):
        while True:
            if self.closed:
                break
            self.update_poller()
            yield tornado.gen.sleep(100)

    def update_poller(self):
        """Increase polling frequency for all clouds"""
        tasks.update_poller.send(self.owner.id)

    def update_user(self):
        self.send('user', get_user_data(self.auth_context))

    def update_org(self):
        try:
            org = filter_org(self.auth_context)
        except Exception as e:  # Forbidden
            org = None
            log.error('Failed to filter org %s: %r' % (
                self.auth_context.org, e))

        if org:
            self.send('org', org)

    def list_keys(self):
        self.internal_request(
            'api/v1/keys',
            callback=lambda keys: self.send('list_keys', keys),
        )

    def list_scripts(self):
        self.internal_request(
            'api/v1/scripts',
            callback=lambda scripts: self.send('list_scripts', scripts),
        )

    def list_schedules(self):
        self.internal_request(
            'api/v1/schedules',
            callback=lambda schedules: self.send('list_schedules', schedules),
        )

    def list_templates(self):
        if not config.HAS_ORCHESTRATION:
            return
        self.internal_request(
            'api/v1/templates',
            callback=lambda templates: self.send('list_templates', templates),
        )

    def list_stacks(self):
        if not config.HAS_ORCHESTRATION:
            return
        self.internal_request(
            'api/v1/stacks',
            callback=lambda stacks: self.send('list_stacks', stacks),
        )

    def list_tunnels(self):
        if not config.HAS_VPN:
            return
        self.internal_request(
            'api/v1/tunnels',
            callback=lambda tunnels: self.send('list_tunnels', tunnels),
        )

    def list_images(self):
        clouds = filter_list_clouds(self.auth_context, as_dict=False)
        for cloud in clouds:
            if not cloud.enabled:
                continue
            if cloud.ctl.ComputeController:
                self.internal_request(
                    'api/v1/clouds/%s/images' % cloud.id,
                    params={'cached': True},
                    callback=lambda images, cloud_id=cloud.id: self.send(
                        'list_images',
                        {'cloud_id': cloud_id, 'images': images}
                    ),
                )

    def list_clouds(self):
        self.update_poller()
        clouds = filter_list_clouds(self.auth_context, as_dict=False)
        self.send('list_clouds', [c.as_dict() for c in clouds])
        for cloud in clouds:
            if not cloud.enabled:
                continue
            if cloud.ctl.ComputeController:
                self.internal_request(
                    'api/v1/clouds/%s/machines' % cloud.id,
                    params={'cached': True},
                    callback=lambda machines, cloud_id=cloud.id: self.send(
                        'list_machines',
                        {'cloud_id': cloud_id, 'machines': machines}
                    ),
                )
                self.internal_request(
                    'api/v1/clouds/%s/clusters' % cloud.id,
                    params={'cached': True},
                    callback=lambda clusters, cloud_id=cloud.id: self.send(
                        'list_clusters',
                        {'cloud_id': cloud_id, 'clusters': clusters}
                    ),
                )
                self.internal_request(
                    'api/v1/clouds/%s/locations' % cloud.id,
                    params={
                        'cached': True,
                        'extra': False,
                    },
                    callback=lambda locations, cloud_id=cloud.id: self.send(
                        'list_locations',
                        {'cloud_id': cloud_id, 'locations': locations}
                    ),
                )
                self.internal_request(
                    'api/v1/clouds/%s/sizes' % cloud.id,
                    params={
                        'cached': True,
                        'extra': False,
                    },
                    callback=lambda sizes, cloud_id=cloud.id: self.send(
                        'list_sizes',
                        {'cloud_id': cloud_id, 'sizes': sizes}
                    ),
                )
                self.internal_request(
                    'api/v1/clouds/%s/images' % cloud.id,
                    params={
                        'cached': True,
                        'extra': False,
                    },
                    callback=lambda images, cloud_id=cloud.id: self.send(
                        'list_images',
                        {'cloud_id': cloud_id, 'images': images}
                    ),
                )
            if cloud.ctl.NetworkController:
                self.internal_request(
                    'api/v1/clouds/%s/networks' % cloud.id,
                    params={'cached': True},
                    callback=lambda networks, cloud_id=cloud.id: self.send(
                        'list_networks',
                        {'cloud_id': cloud_id, 'networks': networks}
                    ),
                )
            if cloud.ctl.DnsController:
                self.internal_request(
                    'api/v1/clouds/%s/zones' % cloud.id,
                    params={'cached': True},
                    callback=lambda zones, cloud_id=cloud.id: self.send(
                        'list_zones',
                        {'cloud_id': cloud_id, 'zones': zones}
                    ),
                )
            if cloud.ctl.StorageController:
                self.internal_request(
                    'api/v1/clouds/%s/volumes' % cloud.id,
                    params={'cached': True},
                    callback=lambda volumes, cloud_id=cloud.id: self.send(
                        'list_volumes',
                        {'cloud_id': cloud_id, 'volumes': volumes}
                    ),
                )
            if cloud.ctl.ObjectStorageController:
                self.internal_request(
                    'api/v1/clouds/%s/buckets' % cloud.id,
                    params={'cached': True},
                    callback=lambda buckets, cloud_id=cloud.id:
                        self.send(
                            'list_buckets', {
                                'cloud_id': cloud_id,
                                'buckets': buckets
                            }),
                )

    def update_notifications(self):
        notifications = [ntf.as_dict() for ntf in InAppNotification.objects(
                         owner=self.auth_context.org,
                         dismissed_by__ne=self.auth_context.user.id)]
        log.info("Emitting notifications list")
        self.send('notifications', notifications)

    def check_monitoring(self):
        try:
            self.send('monitoring', check_monitoring(self.owner))
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
            params = [(name, val)
                      for name, val in (('start', start), ('stop', stop),
                                        ('step', step)) if val]
            if not cloud_id and not machine_id and (
                not metrics or metrics == ['load.shortterm']
            ):
                self.internal_request(
                    'api/v1/machines/stats/load',
                    params=params, callback=callback,
                )
            else:
                for metric in metrics or []:
                    params.append(('metrics', metric))
                self.internal_request(
                    'api/v1/clouds/%s/machines/%s/stats' % (cloud_id,
                                                            machine_id),
                    params=params, callback=callback,
                )
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
        # TODO: list_locations, list_sizes and list_images can be removed...?
        if routing_key in set(['notify', 'probe', 'list_sizes', 'list_images',
                               'list_locations', 'list_projects', 'ping']):
            self.send(routing_key, result)

        elif routing_key == 'update':
            self.owner.reload()
            sections = result
            if 'clouds' in sections:
                self.list_clouds()
            if 'images' in sections:
                self.list_images()
            if 'keys' in sections:
                self.list_keys()
            if 'scripts' in sections:
                self.list_scripts()
            if 'schedules' in sections:
                self.list_schedules()
            if 'templates' in sections:
                self.list_templates()
            if 'stacks' in sections:
                self.list_stacks()
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
            if result.get('user') == self.user.id:
                self.send('patch_notifications', result)

        elif routing_key in ['patch_machines', 'patch_networks',
                             'patch_volumes', 'patch_zones',
                             'patch_buckets', 'patch_clusters']:
            cloud_id = result['cloud_id']
            patch = result['patch']
            rtype = routing_key.replace('patch_', '')
            resource_ids = []
            for line in patch:
                if '-' in line['path']:
                    resource_id, line['path'] = line['path'][1:].split('-', 1)
                else:
                    line['path'] = line['path'][1:]
                    resource_id = line['path'].split('/', 1)[0]
                resource_ids.append(resource_id)
            if not self.auth_context.is_owner():
                allowed_resource_ids = filter_resource_ids(self.auth_context,
                                                           cloud_id, rtype,
                                                           resource_ids)
            else:
                allowed_resource_ids = resource_ids
            patch = [line for line, r_id in zip(patch, resource_ids)
                     if r_id in allowed_resource_ids]
            for line in patch:
                line['path'] = '/clouds/%s/%s/%s' % (cloud_id, rtype,
                                                     line['path'])
            if patch:
                self.batch.extend(patch)
        # TODO: transfer patch_locations to above `elif`,
        # locations need filtering
        elif routing_key in ['patch_locations', 'patch_sizes', 'patch_images']:
            cloud_id = result['cloud_id']
            patch = result['patch']
            for line in patch:
                _id = line['path'][1:]
                if routing_key == 'patch_locations':
                    line['path'] = '/clouds/%s/locations/%s' % (cloud_id, _id)
                elif routing_key == 'patch_sizes':
                    line['path'] = '/clouds/%s/sizes/%s' % (cloud_id, _id)
                elif routing_key == 'patch_images':
                    line['path'] = '/clouds/%s/images/%s' % (cloud_id, _id)
            if patch:
                self.batch.extend(patch)

    def on_close(self, stale=False):
        if not self.closed:
            kwargs = {}
            if stale:
                kwargs['stale'] = True
            if self.log_kwargs:
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
        self.es_client = es_client(asynchronous=True)

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
            for key, value in json.loads(event.pop('extra')).items():
                event[key] = value
        except:
            pass
        if self.filter_log(event):
            self.send('event', self.parse_log(event))
        self.patch_stories(event)

    @tornado.gen.coroutine
    def send_stories(self, stype):
        """Send stories of the specified type."""

        def callback(stories):
            email = self.auth_context.user.email
            ename = '%ss' % stype
            log.info('Will emit %d %s for %s', len(stories), ename, email)
            self.send(ename, stories)

        # Only send incidents for non-Owners.
        if not self.auth_context.is_owner() and stype != 'incident':
            return callback([])

        # Fetch the latest stories.
        kwargs = {
            'story_type': stype,
            'range': {
                '@timestamp': {
                    'gte': int((time.time() - 7 * 24 * 60 * 60) * 1000)
                }
            }
        }
        if self.enforce_logs_for is not None:
            kwargs['owner_id'] = self.enforce_logs_for

        yield get_stories(es_async=self.es_client,
                          callback=callback,
                          limit=100,
                          **kwargs)

    def patch_stories(self, event):
        """Send a stories patch.

        Push an update of stories by creating a patch based on the `stories`
        included in `event`, which describes the diff that should be applied
        on existing stories.

        Each patch is meant to either push newly created stories or update
        existing ones simply based on a log entry's metadata.

        """
        patch = create_stories_patch(self.auth_context, event)
        if patch:
            cls, email = self.__class__.__name__, self.auth_context.user.email
            log.info('%s emitting %d patch(es) for %s', cls, len(patch), email)
            self.send('patch_stories', patch)

    def parse_log(self, event):
        """Parse a single log.

        This method may be used to perform custom parsing/editing of logs.

        Override this method in order to add/remove fields to/from a log entry.

        """
        for param in ('@version', 'tags', '_traceback', '_exc', ):
            event.pop(param, None)
        return event

    def filter_log(self, event):
        """Filter logs on the fly.

        This method may be used to perform custom filtering of logs on the fly.
        Override this method in order to filter single logs, if necessary. By
        default, the log entry is returned as is.

        """
        if event.get('su') and not self.auth_context.user.role == 'Admin':
            return None
        if config.HAS_RBAC:
            return filter_log_event(self.auth_context, event)
        return event

    @tornado.gen.coroutine
    def on_close(self, stale=False):
        """Stop the Consumer and close the WebSocket."""
        yield self.es_client.close()
        if self.consumer is not None:
            try:
                self.consumer.stop()
            except Exception as exc:
                log.error("Error closing pika consumer: %r", exc)
        super(LogsConnection, self).on_close(stale=stale)


def make_router():
    conns = {
        'main': MainConnection,
        'logs': LogsConnection,
        'shell': ShellConnection,
    }
    if config.HAS_MANAGE:
        from mist.manage.sock import ManageLogsConnection
        conns['manage_logs'] = ManageLogsConnection

    return SockJSRouter(MultiplexConnection.get(**conns), '/socket',
                        user_settings={'verify_ip': False})
