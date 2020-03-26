"""Definition of base classes for Clouds

This currently contains only BaseController. It includes basic functionality
for a given cloud (including libcloud calls, fetching and storing information
to db etc. Cloud specific controllers are in `mist.api.clouds.controllers`.

"""

import ssl
import json
import copy
import socket
import logging
import datetime
import calendar
import requests
import re

import jsonpatch

import mongoengine as me

from libcloud.common.types import InvalidCredsError
from libcloud.compute.types import NodeState
from libcloud.compute.base import NodeLocation, Node, NodeSize, NodeImage
from libcloud.common.exceptions import BaseHTTPError
from mist.api.clouds.utils import LibcloudExceptionHandler

from mist.api import config

from mist.api.exceptions import MistError
from mist.api.exceptions import ConflictError
from mist.api.exceptions import ForbiddenError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import InternalServerError
from mist.api.exceptions import MachineNotFoundError
from mist.api.exceptions import CloudUnavailableError
from mist.api.exceptions import CloudUnauthorizedError
from mist.api.exceptions import SSLError
from mist.api.exceptions import MistNotImplementedError

from mist.api.helpers import get_datetime
from mist.api.helpers import amqp_publish
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening

from mist.api.concurrency.models import PeriodicTaskInfo
from mist.api.concurrency.models import PeriodicTaskThresholdExceeded

from mist.api.clouds.controllers.base import BaseController
from mist.api.tag.models import Tag

if config.HAS_VPN:
    from mist.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat


def _update_machine_from_node_in_process_pool(params):
    from libcloud.compute.providers import get_driver
    from mist.api import mongo_connect
    from mist.api.clouds.models import Cloud

    cloud_id = params['cloud_id']
    now = params['now']
    locations_map = params['locations_map']
    sizes_map = params['sizes_map']
    nodedict = json.loads(params['node'])

    driver = get_driver(nodedict['provider'])
    size = None
    if nodedict['size']:
        size = NodeSize(
            id=nodedict['size']['id'],
            name=nodedict['size']['name'],
            ram=nodedict['size']['ram'],
            disk=nodedict['size']['disk'],
            bandwidth=nodedict['size']['bandwidth'],
            price=nodedict['size']['price'],
            extra=nodedict['size']['extra'],
            driver=driver
        )

    node = Node(
        id=nodedict['id'],
        name=nodedict['name'],
        image=nodedict['image'],
        size=size,
        state=nodedict['state'],
        public_ips=nodedict['public_ips'],
        private_ips=nodedict['private_ips'],
        extra=nodedict['extra'],
        created_at=nodedict['created_at'],
        driver=driver
    )

    mongo_connect()
    cloud = Cloud.objects.get(id=cloud_id)

    return cloud.ctl.compute._update_machine_from_node(
        node, locations_map, sizes_map, now)


log = logging.getLogger(__name__)

__all__ = [
    "BaseComputeController",
]


def _decide_machine_cost(machine, tags=None, cost=(0, 0)):
    """Decide what the monthly and hourly machine cost is

    Params:
    machine:    Machine model instance
    tags:       Optional machine tags dict, if not provided it will be queried.
    cost:       Optional two-tuple of hourly/monthly cost, such as that
                returned by cloud provider.

    Any cost-specific tags take precedence.
    """

    def parse_num(num):
        try:
            return float(num or 0)
        except (ValueError, TypeError):
            log.warning("Can't parse %r as float.", num)
            return 0

    now = datetime.datetime.utcnow()
    month_days = calendar.monthrange(now.year, now.month)[1]

    # Get machine tags from db
    tags = tags or {tag.key: tag.value for tag in Tag.objects(
        resource_id=machine.id, resource_type='machine'
    )}

    try:
        cph = parse_num(tags.get('cost_per_hour'))
        cpm = parse_num(tags.get('cost_per_month'))
        if not (cph or cpm) or cph > 100 or cpm > 100 * 24 * 31:
            log.debug("Invalid cost tags for machine %s", machine)
            cph, cpm = list(map(parse_num, cost))
        if not cph:
            cph = float(cpm) / month_days / 24
        elif not cpm:
            cpm = cph * 24 * month_days
    except Exception:
        log.exception("Error while deciding cost for machine %s", machine)

    return cph, cpm


class BaseComputeController(BaseController):
    """Abstract base class for every cloud/provider controller

    This base controller factors out all the steps common to all or most
    clouds into a base class, and defines an interface for provider or
    technology specific cloud controllers.

    Subclasses are meant to extend or override methods of this base class to
    account for differences between different cloud types.

    Care should be taken when considering to add new methods to a subclass.
    All controllers should have the same interface, to the degree this is
    feasible. That is to say, don't add a new method to a subclass unless
    there is a very good reason to do so.

    The following convention is followed:

    Any methods and attributes that don't start with an underscore are the
    controller's public API.

    In the `BaseComputeController`, these public methods will in most cases
    contain a basic implementation that works for most clouds, along with the
    proper logging and error handling. In almost all cases, subclasses SHOULD
    NOT override or extend the public methods of `BaseComputeController`. To
    account for cloud/subclass specific behaviour, one is expected to override
    the internal/private methods of `BaseComputeController`.

    Any methods and attributes that start with an underscore are the
    controller's internal/private API.

    To account for cloud/subclass specific behaviour, the public methods of
    `BaseComputeController` call a number of private methods. These methods
    will always start with an underscore, such as `self._connect`. When an
    internal method is only ever used in the process of one public method, it
    is prefixed as such to make identification and purpose more obvious. For
    example, method `self._list_machines__postparse_machine` is called in the
    process of `self.list_machines` to postparse a machine and inject or modify
    its attributes.

    This `BaseComputeController` defines a strict interface to controlling
    clouds.  For each different cloud type, a subclass needs to be defined. The
    subclass must at least define a proper `self._connect` method. For simple
    clouds, this may be enough. To provide cloud specific processing, hook the
    code on the appropriate private method. Each method defined here documents
    its intended purpose and use.

    """

    def check_connection(self):
        """Raise exception if we can't connect to cloud provider

        In case of error, an instance of `CloudUnavailableError` or
        `CloudUnauthorizedError` should be raised.

        For most cloud providers, who use an HTTP API, calling `connect`
        doesn't really establish a connection, so we also have to attempt to
        make an actual call such as `list_machines` to verify that the
        connection actually works.

        If a subclass's `connect` not raising errors is enough to make sure
        that establishing a connection works, then these subclasses should
        override this method and only call `connect`.

        In most cases, subclasses SHOULD NOT override or extend this method.

        """
        super(BaseComputeController, self).check_connection()
        self._list_machines()

    def list_cached_machines(self, timedelta=datetime.timedelta(days=1)):
        """Return list of machines from database

        Only returns machines that existed last time we check and we've seen
        during the last `timedelta`.

        """
        from mist.api.machines.models import Machine
        return Machine.objects(
            cloud=self.cloud,
            missing_since=None,
            last_seen__gt=datetime.datetime.utcnow() - timedelta,
        )

    def list_machines(self, persist=True):
        """Return list of machines for cloud

        A list of nodes is fetched from libcloud, the data is processed, stored
        on machine models, and a list of machine models is returned.

        Subclasses SHOULD NOT override or extend this method.

        This method wraps `_list_machines` which contains the core
        implementation.

        """
        task_key = 'cloud:list_machines:%s' % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        first_run = False if task.last_success else True
        try:
            with task.task_runner(persist=persist):
                cached_machines = [m.as_dict()
                                   for m in self.list_cached_machines()]
                machines = self._list_machines()
        except PeriodicTaskThresholdExceeded:
            self.cloud.ctl.disable()
            raise

        self.produce_and_publish_patch(cached_machines, machines, first_run)

        # Push historic information for inventory and cost reporting.
        for machine in machines:
            data = {'owner_id': self.cloud.owner.id,
                    'machine_id': machine.id,
                    'cost_per_month': machine.cost.monthly}
            amqp_publish(exchange='machines_inventory', routing_key='',
                         auto_delete=False, data=data)

        return machines

    def produce_and_publish_patch(self, cached_machines, fresh_machines,
                                  first_run=False):
        old_machines = {'%s-%s' % (m['id'], m['machine_id']): m
                        for m in cached_machines}
        new_machines = {'%s-%s' % (m.id, m.machine_id): m.as_dict()
                        for m in fresh_machines}
        # Exclude last seen and probe fields from patch.
        for md in old_machines, new_machines:
            for m in list(md.values()):
                m.pop('last_seen')
                m.pop('probe')
                if m.get('extra') and m['extra'].get('ports'):
                    m['extra']['ports'] = sorted(
                        m['extra']['ports'],
                        key=lambda x: x.get('PublicPort', 0) * 100000 + x.get(
                            'PrivatePort', 0))
        patch = jsonpatch.JsonPatch.from_diff(old_machines,
                                              new_machines).patch
        if patch:  # Publish patches to rabbitmq.
            if not first_run and self.cloud.observation_logs_enabled:
                from mist.api.logs.methods import log_observations
                log_observations(self.cloud.owner.id, self.cloud.id,
                                 'machine', patch, old_machines, new_machines)
            if amqp_owner_listening(self.cloud.owner.id):
                amqp_publish_user(self.cloud.owner.id,
                                  routing_key='patch_machines',
                                  data={'cloud_id': self.cloud.id,
                                        'patch': patch})

    def _list_machines(self):
        """Core logic of list_machines method
        A list of nodes is fetched from libcloud, the data is processed, stored
        on machine models, and a list of machine models is returned.

        Subclasses SHOULD NOT override or extend this method.

        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specific of
        their cloud type. These methods currently are:

            `self._list_machines__fetch_machines`
            `self._list_machines__machine_actions`
            `self._list_machines__postparse_machine`
            `self._list_machines__cost_machine`
            `self._list_machines__fetch_generic_machines`

        Subclasses that require special handling should override these, by
        default, dummy methods.

        """
        # Try to query list of machines from provider API.
        try:
            nodes = self._list_machines__fetch_machines()
            log.info("List nodes returned %d results for %s.",
                     len(nodes), self.cloud)
        except InvalidCredsError as exc:
            log.warning("Invalid creds on running list_nodes on %s: %s",
                        self.cloud, exc)
            raise CloudUnauthorizedError(msg=str(exc))
        except (requests.exceptions.SSLError, ssl.SSLError) as exc:
            log.error("SSLError on running list_nodes on %s: %s",
                      self.cloud, exc)
            raise SSLError(exc=exc)
        except Exception as exc:
            log.exception("Error while running list_nodes on %s", self.cloud)
            raise CloudUnavailableError(exc=exc)

        machines = []
        now = datetime.datetime.utcnow()

        # FIXME Imported here due to circular dependency issues. Perhaps one
        # way to solve this would be to move CloudLocation under its own dir.
        from mist.api.clouds.models import CloudLocation

        # This is a map of locations' external IDs and names to CloudLocation
        # mongoengine objects. It is used to lookup cached locations based on
        # a node's metadata in order to associate VM instances to their region.
        locations_map = {}
        for location in CloudLocation.objects(cloud=self.cloud):
            locations_map[location.external_id] = location
            locations_map[location.name] = location

        # FIXME Imported here due to circular dependency issues. Perhaps one
        # way to solve this would be to move CloudSize under its own dir.
        from mist.api.clouds.models import CloudSize

        # This is a map of sizes' external IDs and names to CloudSize
        # mongoengine objects. It is used to lookup cached sizes based on
        # a node's metadata in order to associate VM instances to their size.
        sizes_map = {}
        for size in CloudSize.objects(cloud=self.cloud):
            sizes_map[size.external_id] = size
            sizes_map[size.name] = size

        from mist.api.machines.models import Machine
        # Process each machine in returned list.
        # Store previously unseen machines separately.
        new_machines = []
        if config.PROCESS_POOL_WORKERS:
            from concurrent.futures import ProcessPoolExecutor
            cloud_id = self.cloud.id
            from json import JSONEncoder

            class NodeEncoder(JSONEncoder):
                def default(self, o):
                    size = o.size
                    if isinstance(size, NodeSize):
                        size = {
                            'id': size.id,
                            'name': size.name,
                            'ram': size.ram,
                            'disk': size.disk,
                            'bandwidth': size.bandwidth,
                            'price': size.price,
                            'extra': size.extra
                        }
                    return {
                        'id': o.id,
                        'name': o.name,
                        'state': o.state,
                        'image': o.image,
                        'size': size,
                        'public_ips': o.public_ips,
                        'private_ips': o.private_ips,
                        'extra': o.extra,
                        'created_at': o.created_at,
                        'provider': o.driver.type
                    }

            choices = map(
                lambda x: {
                    'node': json.dumps(x, cls=NodeEncoder),
                    'cloud_id': cloud_id,
                    'locations_map': locations_map,
                    'sizes_map': sizes_map,
                    'now': now,
                },
                nodes)

            with ProcessPoolExecutor(
                    max_workers=config.PROCESS_POOL_WORKERS) as executor:
                res = executor.map(_update_machine_from_node_in_process_pool,
                                   choices)
            for machine, is_new in list(res):
                if not machine:
                    continue
                if is_new:
                    new_machines.append(machine)
                machines.append(machine)
        else:
            for node in nodes:
                machine, is_new = self._update_machine_from_node(
                    node, locations_map, sizes_map, now)
                if not machine:
                    continue
                if is_new:
                    new_machines.append(machine)
                machines.append(machine)

        # Append generic-type machines, which aren't handled by libcloud.
        for machine in self._list_machines__fetch_generic_machines():
            machine.last_seen = now
            self._list_machines__update_generic_machine_state(machine)
            self._list_machines__generic_machine_actions(machine)

            # Set machine hostname
            if not machine.hostname:
                ips = machine.public_ips + machine.private_ips
                if not ips:
                    ips = []
                for ip in ips:
                    if ip and ':' not in ip:
                        machine.hostname = ip
                        break

            # Parse cost from tags
            cph, cpm = _decide_machine_cost(machine)
            machine.cost.hourly = cph
            machine.cost.monthly = cpm

            # Save machine
            machine.save()
            machines.append(machine)

        # Set missing_since on machine models we didn't see for the first time.
        Machine.objects(cloud=self.cloud,
                        id__nin=[m.id for m in machines],
                        missing_since=None).update(missing_since=now)
        # Set last_seen on machine models we just saw
        Machine.objects(cloud=self.cloud,
                        id__in=[m.id for m in machines],
                        missing_since=None).update(last_seen=now)

        # Update RBAC Mappings given the list of nodes seen for the first time.
        self.cloud.owner.mapper.update(new_machines, asynchronous=False)

        # Update machine counts on cloud and org.
        # FIXME: resolve circular import issues
        from mist.api.clouds.models import Cloud
        self.cloud.machine_count = len(machines)
        self.cloud.save()
        self.cloud.owner.total_machine_count = sum(
            cloud.machine_count for cloud in Cloud.objects(
                owner=self.cloud.owner, deleted=None
            )
        )
        self.cloud.owner.save()

        # Close libcloud connection
        try:
            self.disconnect()
        except Exception as exc:
            log.warning("Error while closing connection: %r", exc)
        return machines

    def _update_machine_from_node(self, node, locations_map, sizes_map, now):
        is_new = False
        updated = False
        # Fetch machine mongoengine model from db, or initialize one.
        from mist.api.machines.models import Machine
        try:
            machine = Machine.objects.get(cloud=self.cloud,
                                          machine_id=node.id)
        except Machine.DoesNotExist:
            try:
                machine = Machine(
                    cloud=self.cloud, machine_id=node.id).save()
                is_new = True
            except me.ValidationError as exc:
                log.warn("Validation error when saving new machine: %r" %
                         exc)
                return None, is_new

        # Discover location of machine.
        try:
            location_id = self._list_machines__get_location(node)
        except Exception as exc:
            log.error("Error getting location of %s: %r", machine, exc)
        else:
            if machine.location != locations_map.get(location_id):
                machine.location = locations_map.get(location_id)
                updated = True

        # Get misc libcloud metadata.
        image_id = ''
        if isinstance(node.image, NodeImage) and node.image.id != 'None':
            image_id = node.image.id
        elif isinstance(node.extra.get('image'), dict):
            image_id = str(node.extra.get('image').get('id'))

        if not image_id:
            image_id = node.image or node.extra.get('imageId') \
                or node.extra.get('image_id') or node.extra.get('image')
        if not image_id:
            if isinstance(node.extra.get('operating_system', {}), dict):
                image_id = node.extra.get('operating_system', {}).get(
                    'name', '')
            else:
                image_id = node.extra.get('operating_system') or ''

        if image_id and machine.image_id != image_id:
            machine.image_id = image_id
            updated = True

        # Attempt to map machine's size to a CloudSize object. If not
        # successful, try to discover custom size.
        try:
            size = self._list_machines__get_size(node)
            if size:
                size = sizes_map.get(size)
            else:
                size = self._list_machines__get_custom_size(node)
            if machine.size != size:
                machine.size = size
                updated = True
        except Exception as exc:
            log.error("Error getting size of %s: %r", machine, exc)

        if machine.name != node.name:
            machine.name = node.name
            updated = True

        if machine.state != config.STATES[node.state]:
            machine.state = config.STATES[node.state]
            updated = True

        new_private_ips = list(set(node.private_ips))
        new_public_ips = list(set(node.public_ips))
        new_private_ips.sort()
        new_public_ips.sort()

        old_private_ips = machine.private_ips
        old_public_ips = machine.public_ips
        new_private_ips.sort()
        new_public_ips.sort()

        if json.dumps(old_private_ips) != json.dumps(new_private_ips):
            machine.private_ips = new_private_ips
            updated = True
        if json.dumps(old_public_ips) != json.dumps(new_public_ips):
            machine.public_ips = new_public_ips
            updated = True

        # Set machine extra dict.
        # Make sure we don't meet any surprises when we try to json encode
        # later on in the HTTP response.
        extra = self._list_machines__get_machine_extra(machine, node)

        for key, val in list(extra.items()):
            try:
                json.dumps(val)
            except TypeError:
                extra[key] = str(val)

        # save extra.tags as dict
        if extra.get('tags') and isinstance(
                extra.get('tags'), list):
            extra['tags'] = dict.fromkeys(extra['tags'], '')
        # perform tag validation to prevent ValidationError
        # on machine.save()
        if extra.get('tags') and isinstance(
                extra.get('tags'), dict):
            validated_tags = {}
            for tag in extra['tags']:
                if not (('.' in tag) or ('$' in tag)):
                    validated_tags[tag] = extra['tags'][tag]
            extra['tags'] = validated_tags

        # Set machine hostname
        if extra.get('dns_name') and machine.hostname != extra['dns_name']:
            machine.hostname = extra['dns_name']
            updated = True
        else:
            ips = machine.public_ips + machine.private_ips
            if not ips:
                ips = []
            for ip in ips:
                if ip and ':' not in ip and machine.hostname != ip:
                    machine.hostname = ip
                    updated = True
                    break

        if json.dumps(machine.extra) != json.dumps(extra):
            machine.extra = extra
            updated = True

        # Get machine creation date.
        try:
            created = self._list_machines__machine_creation_date(machine,
                                                                 node)
            if created:
                created = get_datetime(created)
                if machine.created != created:
                    machine.created = created
                    updated = True
        except Exception as exc:
            log.exception("Error finding creation date for %s in %s.\n%r",
                          self.cloud, machine, exc)
        # TODO: Consider if we should fall back to using current date.
        # if not machine_model.created and is_new:
        #     machine_model.created = datetime.datetime.utcnow()

        # Update with available machine actions.
        try:
            from copy import deepcopy
            actions_backup = deepcopy(machine.actions)
            self._list_machines__machine_actions(machine, node)
            if actions_backup != machine.actions:
                updated = True
        except Exception as exc:
            log.exception("Error while finding machine actions "
                          "for machine %s:%s for %s \n %r",
                          machine.id, node.name, self.cloud, exc)

        # Apply any cloud/provider specific post processing.
        try:
            updated = self._list_machines__postparse_machine(machine, node) \
                or updated
        except Exception as exc:
            log.exception("Error while post parsing machine %s:%s for %s\n%r",
                          machine.id, node.name, self.cloud, exc)

        # Apply any cloud/provider cost reporting.
        try:
            cph, cpm = _decide_machine_cost(
                machine,
                cost=self._list_machines__cost_machine(machine, node),
            )
            if machine.cost.hourly != cph or machine.cost.monthly != cpm:
                machine.cost.hourly = cph
                machine.cost.monthly = cpm
                updated = True
        except Exception as exc:
            log.exception("Error while calculating cost "
                          "for machine %s:%s for %s \n%r",
                          machine.id, node.name, self.cloud, exc)
        if node.state.lower() == 'terminated':
            if machine.cost.hourly or machine.cost.monthly:
                machine.cost.hourly = 0
                machine.cost.monthly = 0
                updated = True

        # Save all changes to machine model on the database.
        if is_new or updated:
            try:
                machine.save()
            except me.ValidationError as exc:
                log.error("Error adding %s: %s", machine.name, exc.to_dict())
                raise BadRequestError({"msg": str(exc),
                                       "errors": exc.to_dict()})
            except me.NotUniqueError as exc:
                log.error("Machine %s not unique error: %s", machine.name, exc)
                raise ConflictError("Machine with this name already exists")
        else:
            log.warn("Not saving machine %s (%s) %s" % (
                machine.name, machine.id, is_new))

        return machine, is_new

    def _list_machines__update_generic_machine_state(self, machine):
        """Helper method to update the machine state

        This is only overriden by the OtherServer Controller.
        It applies only to generic machines.
        """
        machine.state = config.STATES[NodeState.UNKNOWN]

    def _list_machines__generic_machine_actions(self, machine):
        """Helper method to update available generic machine's actions

        This is currently only overriden by the OtherServer Controller
        """
        for action in ('start', 'stop', 'reboot', 'destroy', 'rename',
                       'resume', 'suspend', 'undefine', 'remove'):
            setattr(machine.actions, action, False)
        from mist.api.machines.models import KeyMachineAssociation
        if KeyMachineAssociation.objects(machine=machine).count():
            machine.actions.reboot = True
        machine.actions.tag = True

    def _list_machines__get_size(self, node):
        """Return key of size_map dict for a specific node

        Subclasses MAY override this method.
        """
        return node.size

    def _list_machines__get_custom_size(self, node):
        """Return size metadata for node"""
        return

    def _list_machines__fetch_machines(self):
        """Perform the actual libcloud call to get list of nodes"""
        return self.connection.list_nodes()

    def _list_machines__get_machine_extra(self, machine, machine_libcloud):
        """Return extra dict for libcloud node

        Subclasses can override/extend this method if they wish to filter or
        inject extra metadata.
        """
        return copy.copy(machine_libcloud.extra)

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        return machine_libcloud.created_at

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        """Add metadata on the machine dict on the allowed actions

        Any subclass that wishes to specially handle its allowed actions, can
        implement this internal method.

        machine: A machine mongoengine model. The model may not have yet
            been saved in the database.
        machine_libcloud: An instance of a libcloud compute node, as
            returned by libcloud's list_nodes.
        This method is expected to edit `machine` in place and not return
        anything.

        Subclasses MAY extend this method.

        """
        # Defaults for running state and common clouds.
        machine.actions.start = False
        machine.actions.stop = True
        machine.actions.reboot = True
        machine.actions.destroy = True
        machine.actions.rename = False  # Most providers do not support this
        machine.actions.tag = True   # Always True now that we store tags in db

        # Actions resume, suspend and undefine are states related to KVM.
        machine.actions.resume = False
        machine.actions.suspend = False
        machine.actions.undefine = False

        # Default actions for other states.
        if machine_libcloud.state in (NodeState.REBOOTING, NodeState.PENDING):
            machine.actions.start = False
            machine.actions.stop = False
            machine.actions.reboot = False
        elif machine_libcloud.state in (NodeState.STOPPED, NodeState.UNKNOWN):
            # We assume unknown state means stopped.
            machine.actions.start = True
            machine.actions.stop = False
            machine.actions.reboot = False
        elif machine_libcloud.state in (NodeState.TERMINATED, ):
            machine.actions.start = False
            machine.actions.stop = False
            machine.actions.reboot = False
            machine.actions.destroy = False
            machine.actions.rename = False

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        """Post parse a machine before returning it in list_machines

        Any subclass that wishes to specially handle its cloud's tags and
        metadata, can implement this internal method.

        machine: A machine mongoengine model. The model may not have yet
            been saved in the database.
        machine_libcloud: An instance of a libcloud compute node,
            as returned by libcloud's list_nodes.

        This method is expected to edit its arguments in place and return
        True if any updates have been made.

        Subclasses MAY override this method.

        """
        updated = False
        return updated

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        """Perform cost calculations for a machine

        Any subclass that wishes to handle its cloud's pricing, can implement
        this internal method.

       machine: A machine mongoengine model. The model may not have yet
            been saved in the database.
       machine_libcloud: An instance of a libcloud compute node, as returned by
            libcloud's list_nodes.

       This method is expected to return a tuple of two values:
            (cost_per_hour, cost_per_month)

        Subclasses MAY override this method.

        """
        return 0, 0

    def _list_machines__fetch_generic_machines(self):
        """Return list of machine models that aren't handled by libcloud"""
        return []

    def check_if_machine_accessible(self, machine):
        """Attempt to port knock and ping the machine"""
        assert machine.cloud.id == self.cloud.id
        hostname = machine.hostname or (
            machine.private_ips[0] if machine.private_ips else '')
        if not hostname:
            return False
        ports_list = [22, 80, 443, 3389]
        for port in (machine.ssh_port, machine.rdp_port):
            if port and port not in ports_list:
                ports_list.insert(0, port)
        socket_timeout = 3
        # add timeout for socket
        for port in ports_list:
            log.info("Attempting to connect to %s:%d", hostname, port)
            try:
                s = socket.create_connection(
                    dnat(self.cloud.owner, hostname, port),
                    socket_timeout
                )
                s.shutdown(2)
            except:
                log.info("Failed to connect to %s:%d", hostname, port)
                continue
            log.info("Connected to %s:%d", hostname, port)
            return True
        try:
            log.info("Pinging %s", hostname)
            from mist.api.methods import ping
            ping_res = ping(owner=self.cloud.owner, host=hostname, pkts=1)
            if int(ping_res.get('packets_rx', 0)) > 0:
                log.info("Successfully pinged %s", hostname)
                return True
        except:
            log.info("Failed to ping %s", hostname)
            pass
        return False

    @LibcloudExceptionHandler(CloudUnavailableError)
    def list_images(self, search=None):
        """Return list of images for cloud

        This returns the results obtained from libcloud, after some processing,
        formatting and injection of extra information in a sane format.

        Subclasses SHOULD NOT override or extend this method.

        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specific of
        their cloud type. These methods currently are:

            `self._list_images__fetch_images`

        Subclasses that require special handling should override these, by
        default, dummy methods.

        """

        # Fetch images list, usually from libcloud connection.
        images = self._list_images__fetch_images(search=search)
        if not isinstance(images, list):
            images = list(images)

        # Filter out duplicate images, if any.
        seen_ids = set()
        for i in reversed(range(len(images))):
            image = images[i]
            if image.id in seen_ids:
                images.pop(i)
            else:
                seen_ids.add(image.id)

        # Filter images based on search term.
        if search:
            search = str(search).lower()
            images = [img for img in images
                      if search in img.id.lower() or
                      search in img.name.lower()]

        # Filter out invalid images.
        images = [img for img in images
                  if img.name and img.id[:3] not in ('aki', 'ari')]

        # Turn images to dict to return and star them.
        images = [{'id': img.id,
                   'name': img.name,
                   'extra': img.extra,
                   'star': self.image_is_starred(img.id)}
                  for img in images]

        # Sort images: Starred first, then alphabetically.
        images.sort(key=lambda image: (not image['star'], image['name']))

        return images

    def _list_images__fetch_images(self, search=None):
        """Fetch image listing in a libcloud compatible format

        This is to be called exclusively by `self.list_images`.

        Most subclasses that use a simple libcloud connection, shouldn't need
        to override or extend this method.

        Subclasses MAY override this method.

        """
        return self.connection.list_images()

    def image_is_starred(self, image_id):
        starred = image_id in self.cloud.starred
        unstarred = image_id in self.cloud.unstarred
        default = self.image_is_default(image_id)
        return starred or (default and not unstarred)

    def image_is_default(self, image_id):
        return True

    def list_sizes(self, persist=True):
        """Return list of sizes for cloud

        A list of sizes is fetched from libcloud, data is processed, stored
        on size models, and a list of size models is returned in a sane
        format.

        Subclasses SHOULD NOT override or extend this method.

        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specific of
        their cloud type. These methods currently are:

            `self._list_sizes`

        Subclasses that require special handling should override these, by
        default, dummy methods.

        """
        task_key = 'cloud:list_sizes:%s' % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        with task.task_runner(persist=persist):
            cached_sizes = {s.id: s.as_dict()
                            for s in self.list_cached_sizes()}
            sizes = self._list_sizes()

        if amqp_owner_listening(self.cloud.owner.id):
            if cached_sizes and sizes:
                # Publish patches to rabbitmq.
                new_sizes = {s.id: s.as_dict() for s in sizes}
                patch = jsonpatch.JsonPatch.from_diff(cached_sizes,
                                                      new_sizes).patch
                if patch:
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_sizes',
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})

            else:
                # TODO: remove this block, once location patches
                # are implemented in the UI
                amqp_publish_user(self.cloud.owner.id,
                                  routing_key='list_sizes',
                                  data={'cloud_id': self.cloud.id,
                                        'sizes': [s.as_dict() for s in sizes]})
        return sizes

    def _list_sizes(self):
        """Fetch size listing in a libcloud compatible format

        This is to be called exclusively by `self.list_sizes`.

        Subclasses MAY override this method.

        """
        try:
            fetched_sizes = self._list_sizes__fetch_sizes()
            log.info("List sizes returned %d results for %s.",
                     len(fetched_sizes), self.cloud)
        except InvalidCredsError as exc:
            log.warning("Invalid creds on running list_sizes on %s: %s",
                        self.cloud, exc)
            raise CloudUnauthorizedError(msg=str(exc))
        except (requests.exceptions.SSLError, ssl.SSLError) as exc:
            log.error("SSLError on running list_sizes on %s: %s",
                      self.cloud, exc)
            raise SSLError(exc=exc)
        except Exception as exc:
            log.exception("Error while running list_sizes on %s", self.cloud)
            raise CloudUnavailableError(exc=exc)

        sizes = []

        # FIXME: resolve circular import issues
        from mist.api.clouds.models import CloudSize

        for size in fetched_sizes:
            # create the object in db if it does not exist
            try:
                _size = CloudSize.objects.get(cloud=self.cloud,
                                              external_id=size.id)
            except CloudSize.DoesNotExist:
                _size = CloudSize(cloud=self.cloud, external_id=size.id)

            _size.name = self._list_sizes__get_name(size)
            _size.disk = size.disk
            _size.bandwidth = size.bandwidth
            _size.missing_since = None
            _size.extra = self._list_sizes__get_extra(size)
            if size.ram:
                try:
                    _size.ram = int(re.sub("\D", "", str(size.ram)))
                except Exception as exc:
                    log.error(repr(exc))

            try:
                cpus = self._list_sizes__get_cpu(size)
                _size.cpus = int(cpus)
            except Exception as exc:
                log.error(repr(exc))

            try:
                _size.save()
                sizes.append(_size)
            except me.ValidationError as exc:
                log.error("Error adding %s: %s", size.name, exc.to_dict())
                raise BadRequestError({"msg": str(exc),
                                       "errors": exc.to_dict()})

        # Update missing_since for sizes not returned by libcloud
        CloudSize.objects(
            cloud=self.cloud, missing_since=None,
            external_id__nin=[s.external_id for s in sizes]
        ).update(missing_since=datetime.datetime.utcnow())

        return sizes

    def _list_sizes__fetch_sizes(self):
        """Fetch size listing in a libcloud compatible format

        This is to be called exclusively by `self._list_sizes`.

        Most subclasses that use a simple libcloud connection, shouldn't need
        to override or extend this method.

        Subclasses MAY override this method.
        """
        return self.connection.list_sizes()

    def _list_sizes__get_cpu(self, size):
        return int(size.extra.get('cpus') or 1)

    def _list_sizes__get_name(self, size):
        return size.name

    def _list_sizes__get_extra(self, size):
        extra = {}
        if size.extra:
            extra = size.extra
        if size.price:
            extra.update({'price': size.price})
        return extra

    def list_cached_sizes(self):
        """Return list of sizes from database for a specific cloud"""
        # FIXME: resolve circular import issues
        from mist.api.clouds.models import CloudSize
        return CloudSize.objects(cloud=self.cloud, missing_since=None)

    def list_locations(self, persist=True):
        """Return list of locations for cloud

        A list of locations is fetched from libcloud, data is processed, stored
        on location models, and a list of location models is returned.

        Subclasses SHOULD NOT override or extend this method.

        This method wraps `_list_locations` which contains the core
        implementation.

        """
        task_key = 'cloud:list_locations:%s' % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        with task.task_runner(persist=persist):
            cached_locations = {'%s' % l.id: l.as_dict()
                                for l in self.list_cached_locations()}

            locations = self._list_locations()

        if amqp_owner_listening(self.cloud.owner.id):
            locations_dict = [l.as_dict() for l in locations]
            if cached_locations and locations_dict:
                # Publish patches to rabbitmq.
                new_locations = {'%s' % l['id']: l for l in locations_dict}
                patch = jsonpatch.JsonPatch.from_diff(cached_locations,
                                                      new_locations).patch
                if patch:
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_locations',
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})
            else:
                # TODO: remove this block, once location patches
                # are implemented in the UI
                amqp_publish_user(self.cloud.owner.id,
                                  routing_key='list_locations',
                                  data={'cloud_id': self.cloud.id,
                                        'locations': locations_dict})
        return locations

    def _list_locations(self):
        """Return list of available locations for current cloud

        Locations mean different things in each cloud. e.g. EC2 uses it as a
        datacenter in a given availability zone, whereas Linode lists
        availability zones. However all responses share id, name and country
        eventhough in some cases might be empty, e.g. Openstack.

        This returns the results obtained from libcloud, after some processing,
        formatting and injection of extra information in a sane format.

        Subclasses SHOULD NOT override or extend this method.

        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specific of
        their cloud type. These methods currently are:

            `self._list_locations__fetch_locations`

        Subclasses that require special handling should override these, by
        default, dummy methods.

        """
        # FIXME: resolve circular import issues
        from mist.api.clouds.models import CloudLocation

        # Fetch locations, usually from libcloud connection.
        fetched_locations = self._list_locations__fetch_locations()

        log.info("List locations returned %d results for %s.",
                 len(fetched_locations), self.cloud)

        locations = []

        for loc in fetched_locations:
            try:
                _location = CloudLocation.objects.get(cloud=self.cloud,
                                                      external_id=loc.id)
            except CloudLocation.DoesNotExist:
                _location = CloudLocation(cloud=self.cloud,
                                          external_id=loc.id)
            _location.country = loc.country
            _location.name = loc.name
            _location.extra = loc.extra
            _location.missing_since = None

            try:
                _location.save()
            except me.ValidationError as exc:
                log.error("Error adding %s: %s", loc.name, exc.to_dict())
                raise BadRequestError({"msg": str(exc),
                                       "errors": exc.to_dict()})
            locations.append(_location)

        # update missing_since for locations not returned by libcloud
        CloudLocation.objects(cloud=self.cloud,
                              missing_since=None,
                              external_id__nin=[l.external_id
                                                for l in locations]).update(
                                                    missing_since=datetime.
                                                    datetime.utcnow())
        return locations

    def _list_locations__fetch_locations(self):
        """Fetch location listing in a libcloud compatible format

        This is to be called exclusively by `self.list_locations`.

        Most subclasses that use a simple libcloud connection, shouldn't need
        to override or extend this method.

        Subclasses MAY override this method.

        """
        try:
            return self.connection.list_locations()
        except:
            return [NodeLocation('', name='default', country='',
                                 driver=self.connection)]

    def list_cached_locations(self):
        """Return list of locations from database for a specific cloud"""
        # FIXME Imported here due to circular dependency issues. Perhaps one
        # way to solve this would be to move CloudLocation under its own dir.
        from mist.api.clouds.models import CloudLocation
        return CloudLocation.objects(cloud=self.cloud, missing_since=None)

    def _list_machines__get_location(self, node):
        """Find location code name/identifier from libcloud data

        This is to be called exclusively by `self._list_machines`.

        Subclasses MAY override this method.

        """
        return ''

    def _get_machine_libcloud(self, machine, no_fail=False):
        """Return an instance of a libcloud node

        This is a private method, used mainly by machine action methods.
        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        for node in self.connection.list_nodes():
            if node.id == machine.machine_id:
                return node
        if no_fail:
            return Node(machine.machine_id, name=machine.machine_id,
                        state=0, public_ips=[], private_ips=[],
                        driver=self.connection)
        raise MachineNotFoundError(
            "Machine with machine_id '%s'." % machine.machine_id
        )

    def start_machine(self, machine):
        """Start machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to start a machine would be to run

            machine.ctl.start()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are started, it should override `_start_machine` method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.start:
            raise ForbiddenError("Machine doesn't support start.")
        log.debug("Starting machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            return self._start_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not start machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(str(exc))

    def _start_machine(self, machine, machine_libcloud):
        """Private method to start a given machine

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `start_machine`.
        """
        return self.connection.ex_start_node(machine_libcloud)

    def stop_machine(self, machine):
        """Stop machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to stop a machine would be to run

            machine.ctl.stop()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are stoped, it should override `_stop_machine` method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.stop:
            raise ForbiddenError("Machine doesn't support stop.")
        log.debug("Stopping machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            return self._stop_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not stop machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

    def _stop_machine(self, machine, machine_libcloud):
        """Private method to stop a given machine

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `stop_machine`.
        """
        return self.connection.ex_stop_node(machine_libcloud)

    def reboot_machine(self, machine):
        """Reboot machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to reboot a machine would be to run

            machine.ctl.reboot()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are rebooted, it should override `_reboot_machine` method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.reboot:
            raise ForbiddenError("Machine doesn't support reboot.")
        log.debug("Rebooting machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            return self._reboot_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not reboot machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(exc=exc)

    def _reboot_machine(self, machine, machine_libcloud):
        """Private method to reboot a given machine

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `reboot_machine`.
        """
        return machine_libcloud.reboot()

    def reboot_machine_ssh(self, machine):
        """Reboot machine by running command over SSH"""
        assert self.cloud == machine.cloud
        log.debug("Rebooting (SSH) machine %s", machine)
        try:
            if machine.public_ips:
                hostname = machine.public_ips[0]
            else:
                hostname = machine.private_ips[0]
            command = '$(command -v sudo) shutdown -r now'
            # TODO move it up
            from mist.api.methods import ssh_command
            return ssh_command(self.cloud.owner, self.cloud.id,
                               machine.machine_id, hostname, command)
        except MistError as exc:
            log.error("Could not reboot machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

    def destroy_machine(self, machine):
        """Destroy machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to destroy a machine would be to run

            machine.ctl.destroy()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are destroyed, it should override `_destroy_machine` method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.destroy:
            raise ForbiddenError("Machine doesn't support destroy.")
        log.debug("Destroying machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            ret = self._destroy_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not destroy machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

        from mist.api.machines.models import KeyMachineAssociation
        KeyMachineAssociation.objects(machine=machine).delete()

        machine.state = 'terminated'
        machine.save()
        return ret

    def _destroy_machine(self, machine, machine_libcloud):
        """Private method to destroy a given machine

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `destroy_machine`.
        """
        try:
            return machine_libcloud.destroy()
        except BaseHTTPError:
            raise ForbiddenError("Cannot destroy machine. Check the "
                                 "termination protection setting on your "
                                 "cloud provider.")

    def remove_machine(self, machine):
        raise BadRequestError("Machines on public clouds can't be removed."
                              "This is only supported in Bare Metal clouds.")

    def resize_machine(self, machine, size_id, kwargs):
        """Resize machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to resize a machine would be to run

            machine.ctl.resize(size_id)

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are resizeed, it should override `_resize_machine` method instead.

        """
        assert self.cloud == machine.cloud
        if not machine.actions.resize:
            raise ForbiddenError("Machine doesn't support resize.")
        log.debug("Resizing machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            from mist.api.clouds.models import CloudSize
            size = CloudSize.objects.get(id=size_id)
            node_size = NodeSize(size.external_id, name=size.name,
                                 ram=size.ram, disk=size.disk,
                                 bandwidth=size.bandwidth,
                                 price=size.extra['price'],
                                 driver=self.connection)
            self._resize_machine(machine, machine_libcloud, node_size, kwargs)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)
        try:
            # TODO: For better separation of concerns, maybe trigger below
            # using an event?
            from mist.api.notifications.methods import (
                dismiss_scale_notifications)
            # TODO: Make sure user feedback is positive below!
            dismiss_scale_notifications(machine, feedback='POSITIVE')
        except Exception as exc:
            log.exception("Failed to dismiss scale recommendation: %r", exc)

    def _resize_machine(self, machine, machine_libcloud, node_size, kwargs):
        """Private method to resize a given machine

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `resize_machine`.
        """
        self.connection.ex_resize_node(machine_libcloud, node_size)

    def rename_machine(self, machine, name):
        """Rename machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to rename a machine would be to run

            machine.ctl.rename(name)

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are renameed, it should override `_rename_machine` method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.rename:
            raise ForbiddenError("Machine doesn't support rename.")
        log.debug("Renaming machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            self._rename_machine(machine, machine_libcloud, name)
        except MistError as exc:
            log.error("Could not rename machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(str(exc))

    def _rename_machine(self, machine, machine_libcloud, name):
        """Private method to rename a given machine

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `rename_machine`.
        """
        self.connection.ex_rename_node(machine_libcloud, name)

    def resume_machine(self, machine):
        """Resume machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to resume a machine would be to run

            machine.ctl.resume()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are resumed, it should override `_resume_machine` method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.resume:
            raise ForbiddenError("Machine doesn't support resume.")
        log.debug("Resuming machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            self._resume_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not resume machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

    def _resume_machine(self, machine, machine_libcloud):
        """Private method to resume a given machine

        Only LibvirtComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `resume_machine`.
        """
        raise MistNotImplementedError()

    def suspend_machine(self, machine):
        """Suspend machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to suspend a machine would be to run

            machine.ctl.suspend()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are suspended, it should override `_suspend_machine` method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.suspend:
            raise ForbiddenError("Machine doesn't support suspend.")
        log.debug("Suspending machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            return self._suspend_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not suspend machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(str(exc))

    def _suspend_machine(self, machine, machine_libcloud):
        """Private method to suspend a given machine

        Only LibvirtComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `suspend_machine`.
        """
        raise MistNotImplementedError()

    def undefine_machine(self, machine):
        """Undefine machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to undefine a machine would be to run

            machine.ctl.undefine()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are undefineed, it should override `_undefine_machine` method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.undefine:
            raise ForbiddenError("Machine doesn't support undefine.")
        log.debug("Undefining machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            return self._undefine_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not undefine machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(str(exc))

    def _undefine_machine(self, machine, machine_libcloud):
        """Private method to undefine a given machine

        Only LibvirtComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Different cloud controllers should override this private method, which
        is called by the public method `undefine_machine`.
        """
        raise MistNotImplementedError()

    def create_machine_snapshot(self, machine, snapshot_name, description='',
                                dump_memory=False, quiesce=False):
        """Create a snapshot for machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to undefine a machine would be to run

            machine.ctl.create_snapshot()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        snapshots are created, it should override `_create_machine_snapshot`
        method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.create_snapshot:
            raise ForbiddenError("Machine doesn't support creating snapshots.")
        log.debug("Creating snapshot for machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            return self._create_machine_snapshot(
                machine, machine_libcloud, snapshot_name,
                description=description, dump_memory=dump_memory,
                quiesce=quiesce)
        except MistError as exc:
            log.error("Could not create snapshot for machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(str(exc))

    def _create_machine_snapshot(self, machine, machine_libcloud,
                                 snapshot_name, description='',
                                 dump_memory=False, quiesce=False):
        """Private method to create a snapshot for a given machine

        Only VSphereComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node
            snapshot_name: name of the snapshot to create
            description: description of the snapshot
            dump_memory: also dump the machine's memory
            quiesce: quiesce guest file system

        Different cloud controllers should override this private method, which
        is called by the public method `create_machine_snapshot`.
        """
        raise MistNotImplementedError()

    def remove_machine_snapshot(self, machine, snapshot_name=None):
        """Remove a snapshot of a machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to undefine a machine would be to run

            machine.ctl.remove_snapshot()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        snapshots are created, it should override `_create_machine_snapshot`
        method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.remove_snapshot:
            raise ForbiddenError("Machine doesn't support removing snapshots.")
        log.debug("Removing snapshot for machine %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            return self._remove_machine_snapshot(machine, machine_libcloud,
                                                 snapshot_name)
        except MistError as exc:
            log.error("Could not remove snapshot of machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(str(exc))

    def _remove_machine_snapshot(self, machine, machine_libcloud,
                                 snapshot_name=None):
        """Private method to remove a snapshot for a given machine

        Only VSphereComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node
            snapshot_name: snapshot to remove, if None pick the last one

        Different cloud controllers should override this private method, which
        is called by the public method `remove_machine_snapshot`.
        """
        raise MistNotImplementedError()

    def revert_machine_to_snapshot(self, machine, snapshot_name=None):
        """Revert machine to selected snapshot

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to undefine a machine would be to run

            machine.ctl.revert_to_snapshot()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        snapshots are created, it should override `_revert_machine_to_snapshot`
        method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.revert_to_snapshot:
            raise ForbiddenError(
                "Machine doesn't support reverting to snapshot.")
        log.debug("Reverting machines %s to snapshot", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            return self._revert_machine_to_snapshot(machine, machine_libcloud,
                                                    snapshot_name)
        except MistError as exc:
            log.error("Could not revert machine %s to snapshot", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(str(exc))

    def _revert_machine_to_snapshot(self, machine, machine_libcloud,
                                    snapshot_name=None):
        """Private method to revert a given machine to a previous snapshot

        Only VSphereComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node
            snapshot_name: snapshot to remove, if None pick the last one

        Different cloud controllers should override this private method, which
        is called by the public method `revert_machine_to_snapshot`.
        """
        raise MistNotImplementedError()

    def list_machine_snapshots(self, machine):
        """List snapshots of a machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to undefine a machine would be to run

            machine.ctl.list_snapshots()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        snapshots are created, it should override `_list_machine_snapshots`
        method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        log.debug("Reverting machines %s to snapshot", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            return self._list_machine_snapshots(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not list snapshots for machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(str(exc))

    def _list_machine_snapshots(self, machine, machine_libcloud):
        """Private method to list a given machine's snapshots

        Only VSphereComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Different cloud controllers should override this private method, which
        is called by the public method `list_machine_snapshots`.
        """
        raise MistNotImplementedError()

    def clone_machine(self, machine, name=None, resume=False):
        """Clone machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to undefine a machine would be to run

            machine.ctl.clone()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are undefineed, it should override `_clone_machine` method instead.

        """
        assert self.cloud == machine.cloud
        if not machine.actions.clone:
            raise ForbiddenError("Machine doesn't support clone.")

        log.debug("Cloning %s", machine)

        machine_libcloud = self._get_machine_libcloud(machine)
        try:
            self._clone_machine(machine, machine_libcloud, name, resume)
        except MistError as exc:
            log.error("Failed to clone %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

    def _clone_machine(self, machine, machine_libcloud, name=None,
                       resume=False):
        """Private method to clone a given machine

        Only LibvirtComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node
            name: the clone's unique name
            resume: denotes whether to resume the original node

        Differnent cloud controllers should override this private method,
        which is called by the public method `clone_machine`.

        """
        raise MistNotImplementedError()
