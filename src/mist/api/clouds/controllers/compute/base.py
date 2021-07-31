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
from typing import Dict, List
import requests
import re

from bson import json_util

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
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import MachineCreationError
from mist.api.exceptions import PolicyUnauthorizedError

from mist.api.helpers import get_datetime
from mist.api.helpers import amqp_publish
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening
from mist.api.helpers import node_to_dict

from mist.api.concurrency.models import PeriodicTaskInfo
from mist.api.concurrency.models import PeriodicTaskThresholdExceeded

from mist.api.clouds.controllers.base import BaseController
from mist.api.tag.models import Tag

if config.HAS_VPN:
    from mist.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat

if config.HAS_PRICING:
    from mist.pricing.methods import get_cost_from_price_catalog
else:
    from mist.api.dummy.methods import get_cost_from_price_catalog


log = logging.getLogger(__name__)

__all__ = [
    "BaseComputeController",
]


def _update_machine_from_node_in_process_pool(params):
    from mist.api.clouds.models import Cloud

    cloud_id = params['cloud_id']
    now = params['now']
    locations_map = params['locations_map']
    sizes_map = params['sizes_map']
    images_map = params['images_map']
    node_dict = params['node']
    cloud = Cloud.objects.get(id=cloud_id)

    return cloud.ctl.compute._update_machine_from_node(
        node_dict, locations_map, sizes_map, images_map, now)


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
    percentage = 1
    try:
        cph = parse_num(tags.get('cost_per_hour'))
        cpm = parse_num(tags.get('cost_per_month'))
        catalog_cph, catalog_cpm, percentage = get_cost_from_price_catalog(
            machine)
        if catalog_cph or catalog_cpm:
            return (catalog_cph, catalog_cpm)
        if not (cph or cpm) or cph > 100 or cpm > 100 * 24 * 31:
            log.debug("Invalid cost tags for machine %s", machine)
            cph, cpm = list(map(parse_num, cost))
        if not cph:
            cph = float(cpm) / month_days / 24
        elif not cpm:
            cpm = cph * 24 * month_days
    except Exception:
        log.exception("Error while deciding cost for machine %s", machine)

    return (percentage * cph, percentage * cpm)


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

        if config.ENABLE_METERING:
            self._update_metering_data(cached_machines, machines)

        return machines

    def produce_and_publish_patch(self, cached_machines, fresh_machines,
                                  first_run=False):
        old_machines = {'%s-%s' % (m['id'], m['machine_id']): copy.copy(m)
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
            `self._list_machines__machine_creation_date`

        Subclasses that require special handling should override these, by
        default, dummy methods.

        """
        # Try to query list of machines from provider API.
        try:
            from time import time
            start = time()
            nodes = self._list_machines__fetch_machines()
            log.info("List nodes returned %d results for %s in %d.",
                     len(nodes), self.cloud, time() - start)
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

        # This is a map of locations' external IDs and names to CloudLocation
        # mongoengine objects. It is used to lookup cached locations based on
        # a node's metadata in order to associate VM instances to their region.
        from mist.api.clouds.models import CloudLocation
        locations_map = {}
        for location in CloudLocation.objects(cloud=self.cloud):
            locations_map[location.external_id] = location
            locations_map[location.name] = location

        # This is a map of sizes' external IDs and names to CloudSize
        # mongoengine objects. It is used to lookup cached sizes based on
        # a node's metadata in order to associate VM instances to their size.
        from mist.api.clouds.models import CloudSize
        sizes_map = {}
        for size in CloudSize.objects(cloud=self.cloud):
            sizes_map[size.external_id] = size
            sizes_map[size.name] = size

        # This is a map of images' external IDs and names to CloudImage
        # mongoengine objects. It is used to lookup cached images based on
        # a node's metadata in order to associate VM instances to their image.
        from mist.api.images.models import CloudImage
        images_map = {}
        for image in CloudImage.objects(cloud=self.cloud):
            images_map[image.external_id] = image
            images_map[image.name] = image

        from mist.api.machines.models import Machine
        # Process each machine in returned list.
        # Store previously unseen machines separately.
        new_machines = []
        if config.PROCESS_POOL_WORKERS:
            from concurrent.futures import ProcessPoolExecutor
            cloud_id = self.cloud.id

            choices = map(
                lambda node: {
                    'node': node,
                    'cloud_id': cloud_id,
                    'locations_map': locations_map,
                    'sizes_map': sizes_map,
                    'images_map': images_map,
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
                    node, locations_map, sizes_map, images_map, now)
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
        # Set last_seen, unset missing_since on machine models we just saw
        Machine.objects(cloud=self.cloud,
                        id__in=[m.id for m in machines]).update(
                            last_seen=now, missing_since=None)

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

    def _update_machine_image(self, node, machine, images_map):
        updated = False
        try:
            image = images_map.get(self._list_machines__get_image(node)) or \
                self._list_machines__get_custom_image(node)
            if machine.image != image:
                machine.image = image
                updated = True
        except Exception as exc:
            log.error("Error getting image of %s: %r", machine, exc)
        return updated

    def _update_machine_size(self, node, machine, sizes_map):
        updated = False
        try:
            size = sizes_map.get(self._list_machines__get_size(node)) or \
                self._list_machines__get_custom_size(node)
            if machine.size != size:
                machine.size = size
                updated = True
        except Exception as exc:
            log.error("Error getting size of %s: %r", machine, exc)
        return updated

    def _update_machine_from_node(self, node, locations_map, sizes_map,
                                  images_map, now):
        is_new = False
        updated = False
        # Fetch machine mongoengine model from db, or initialize one.
        from mist.api.machines.models import Machine
        try:
            machine = Machine.objects.get(cloud=self.cloud,
                                          machine_id=node['id'])
        except Machine.DoesNotExist:
            try:
                machine = Machine(
                    cloud=self.cloud, machine_id=node['id']).save()
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

        updated = self._update_machine_image(
            node, machine, images_map) or updated

        updated = self._update_machine_size(
            node, machine, sizes_map) or updated

        # set machine's os_type from image's os_type, but if
        # info of os_type can be obtained from libcloud node, then
        # machine.os_type will be overwritten in `postparse_machine`
        if machine.image:
            machine.os_type = machine.image.os_type

        if machine.name != node['name']:
            machine.name = node['name']
            updated = True

        node_state = node.get('state')
        config_state = config.STATES.get(node_state)
        if node_state and config_state and machine.state != config_state:
            machine.state = config_state
            updated = True

        new_private_ips = list(set(node['private_ips']))
        new_public_ips = list(set(node['public_ips']))
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
        if extra.get('dns_name'):
            if machine.hostname != extra['dns_name']:
                machine.hostname = extra['dns_name']
                updated = True
        else:
            ips = machine.public_ips + machine.private_ips
            if not ips:
                ips = []
            if not machine.hostname or (machine.public_ips and machine.hostname
                                        not in machine.public_ips):
                for ip in ips:
                    if ip and ':' not in ip:
                        machine.hostname = ip
                        updated = True
                        break
        if json.dumps(machine.extra, default=json_util.default) != json.dumps(
                extra, default=json_util.default):
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
                          machine.id, node['name'], self.cloud, exc)

        # Apply any cloud/provider specific post processing.
        try:
            updated = self._list_machines__postparse_machine(machine, node) \
                or updated
        except Exception as exc:
            log.exception("Error while post parsing machine %s:%s for %s\n%r",
                          machine.id, node['name'], self.cloud, exc)

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
                          machine.id, node['name'], self.cloud, exc)

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
            log.debug("Not saving machine %s (%s) %s" % (
                machine.name, machine.id, is_new))

        machine.last_seen = now

        return machine, is_new

    def _list_machines__update_generic_machine_state(self, machine):
        """Helper method to update the machine state

        This is only overriden by the OtherServer Controller.
        It applies only to generic machines.
        """
        machine.state = config.STATES[NodeState.UNKNOWN.value]

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

    def _list_machines__get_image(self, node):
        """Return key of images_map dict for a specific node

        Subclasses MAY override this method.
        """
        image_id = ''
        if isinstance(node.get('image'), dict) and node['image'].get('id'):
            image_id = node['image']['id']
        elif node.get('image'):
            image_id = node.get('image')
        elif isinstance(node.get('extra', {}).get('image'), dict):
            image_id = str(node['extra'].get('image').get('id'))
        if not image_id:
            image_id = str(node.get('image') or node.get(
                           'extra', {}).get('imageId') or
                           node.get('extra', {}).get('image_id') or
                           node.get('extra', {}).get('image'))
        if not image_id:
            image_id = node.get('extra', {}).get('operating_system')
            if isinstance(image_id, dict):
                image_id = image_id.get('name')
        return image_id

    def _list_machines__get_custom_image(self, node):
        """Return image metadata for node"""
        return None

    def _list_machines__get_size(self, node):
        """Return key of size_map dict for a specific node

        Subclasses MAY override this method.
        """
        return node.get('size')

    def _list_machines__get_custom_size(self, node):
        """Return size metadata for node"""
        return

    def _list_machines__fetch_machines(self):
        """Perform the actual libcloud call to get list of nodes"""
        return [node_to_dict(node) for node in self.connection.list_nodes()]

    def _list_machines__get_machine_extra(self, machine, node_dict):
        """Return extra dict for libcloud node

        Subclasses can override/extend this method if they wish to filter or
        inject extra metadata.
        """
        return copy.copy(node_dict['extra'])

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict.get('created_at')

    def _list_machines__machine_actions(self, machine, node_dict):
        """Add metadata on the machine dict on the allowed actions

        Any subclass that wishes to specially handle its allowed actions, can
        implement this internal method.

        machine: A machine mongoengine model. The model may not have yet
            been saved in the database.
        node_dict: An instance of a libcloud compute node, as
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
        machine.actions.expose = False

        # Actions resume, suspend and undefine are states related to KVM.
        machine.actions.resume = False
        machine.actions.suspend = False
        machine.actions.undefine = False

        # Action power_cycle, is related to DigitalOcean
        machine.actions.power_cycle = False

        # Default actions for other states.
        if node_dict['state'] in (NodeState.REBOOTING,
                                  NodeState.PENDING):
            machine.actions.start = False
            machine.actions.stop = False
            machine.actions.reboot = False
        elif node_dict['state'] in (NodeState.STOPPED,
                                    NodeState.UNKNOWN):
            # We assume unknown state means stopped.
            machine.actions.start = True
            machine.actions.stop = False
            machine.actions.reboot = False
        elif node_dict['state'] in (NodeState.TERMINATED, ):
            machine.actions.start = False
            machine.actions.stop = False
            machine.actions.reboot = False
            machine.actions.destroy = False
            machine.actions.rename = False

    def _list_machines__postparse_machine(self, machine, node_dict):
        """Post parse a machine before returning it in list_machines

        Any subclass that wishes to specially handle its cloud's tags and
        metadata, can implement this internal method.

        machine: A machine mongoengine model. The model may not have yet
            been saved in the database.
        node_dict: A libcloud compute node converted to dict,
            using helpers.node_to_dict

        This method is expected to edit its arguments in place and return
        True if any updates have been made.

        Subclasses MAY override this method.

        """
        updated = False
        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        """Perform cost calculations for a machine

        Any subclass that wishes to handle its cloud's pricing, can implement
        this internal method.

        machine: A machine mongoengine model. The model may not have yet
            been saved in the database.
        node_dict: A libcloud compute node converted to dict,
            using helpers.node_to_dict

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
    def list_images(self, persist=True, search=None):
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
        task_key = 'cloud:list_images:%s' % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        with task.task_runner(persist=persist):
            cached_images = {'%s' % im.id: im.as_dict()
                             for im in self.list_cached_images()}
            images = self._list_images(search=search)

        new_image_objects = [image for image in images
                             if image.id not in cached_images.keys()]

        if amqp_owner_listening(self.cloud.owner.id):
            images_dict = [img.as_dict() for img in images]
            if cached_images and images_dict:
                # Publish patches to rabbitmq.
                new_images = {'%s' % im['id']: im for im in images_dict}
                patch = jsonpatch.JsonPatch.from_diff(cached_images,
                                                      new_images).patch
                if search:
                    # do not remove images that were not returned from
                    # libcloud, since there was a search
                    patch = [i for i in patch
                             if not (i.get('op') in ['remove'])]

                if patch:
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_images',
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})
            else:
                # TODO: is this really needed? same for sizes and locations
                # TODO: remove this block, once image patches
                # are implemented in the UI
                amqp_publish_user(self.cloud.owner.id,
                                  routing_key='list_images',
                                  data={'cloud_id': self.cloud.id,
                                        'images': images_dict})

        # Update RBAC Mappings given the list of new images.
        self.cloud.owner.mapper.update(new_image_objects, asynchronous=False)
        return images

    def _list_images(self, search=None):
        """Fetch image listing in a libcloud compatible format

        This is to be called exclusively by `self.list_images`.

        Most subclasses that use a simple libcloud connection, shouldn't need
        to override or extend this method.

        Subclasses MAY override this method.

        """
        from mist.api.images.models import CloudImage
        # Fetch images, usually from libcloud connection.
        libcloud_images = self._list_images__fetch_images(search=search)

        log.info("List images returned %d results for %s.",
                 len(libcloud_images), self.cloud)

        images = []

        for img in libcloud_images:
            try:
                _image = CloudImage.objects.get(cloud=self.cloud,
                                                external_id=img.id)
            except CloudImage.DoesNotExist:
                _image = CloudImage(cloud=self.cloud,
                                    external_id=img.id)
            _image.name = img.name
            _image.extra = copy.deepcopy(img.extra)
            _image.missing_since = None
            _image.os_type = self._list_images__get_os_type(img)
            _image.os_distro = self._list_images__get_os_distro(img)
            _image.min_disk_size = self._list_images__get_min_disk_size(img)
            _image.min_memory_size = self._list_images__get_min_memory_size(img)  # noqa
            _image.architecture = self._list_images__get_architecture(img)
            _image.origin = self._list_images__get_origin(img)

            try:
                self._list_images__postparse_image(_image, img)
            except Exception as exc:
                log.exception("Error while post parsing image %s:%s for \
                              %s\n%r", _image.id, img.name, self.cloud, exc)

            if search:
                _image.stored_after_search = True
            try:
                _image.save()
            except me.ValidationError as exc:
                log.error("Error adding %s: %s", _image.name, exc.to_dict())
                raise BadRequestError({"msg": exc.message,
                                       "errors": exc.to_dict()})
            try:
                self._list_images__get_available_locations(_image)
            except Exception as exc:
                log.error('Error adding image-location constraint: %s'
                          % repr(exc))
            try:
                self._list_images__get_allowed_sizes(_image)
            except Exception as exc:
                log.error('Error adding image-size constraint: %s'
                          % repr(exc))

            images.append(_image)

        # update missing_since for images not returned by libcloud
        if not search:
            CloudImage.objects(cloud=self.cloud,
                               missing_since=None,
                               stored_after_search=False,
                               external_id__nin=[i.external_id
                                                 for i in images]).update(
                                                     missing_since=datetime.
                                                     datetime.utcnow())
        if not search:
            # return images stored in database, because there are also
            # images stored after search, or imported from external repo
            all_images = CloudImage.objects(cloud=self.cloud,
                                            missing_since=None)
            images = [img for img in all_images]

        # Sort images: Starred first, then alphabetically.
        images.sort(key=lambda image: (not image.starred, image.name))

        return images

    def _list_images__fetch_images(self, search=None):
        """Fetch image listing in a libcloud compatible format

        This is to be called exclusively by `self._list_images`.

        Most subclasses that use a simple libcloud connection, shouldn't
        need to override or extend this method.

        Subclasses MAY override this method.
        """
        return self.connection.list_images()

    def _list_images__postparse_image(self, image, image_libcloud):
        """Post parse an image before returning it in list_images

        Any subclass that wishes to specially handle its cloud's tags and
        metadata, can implement this internal method.

        Subclasses MAY override this method.

        """
        return

    def list_cached_images(self):
        """Return list of images from database for a specific cloud"""
        from mist.api.images.models import CloudImage
        return CloudImage.objects(cloud=self.cloud, missing_since=None)

    def _list_images__get_os_type(self, image):
        if 'windows' in image.name.lower():
            return 'windows'
        elif 'vyatta' in image.name.lower():
            return 'vyatta'
        else:
            return 'linux'

    def _list_images__get_available_locations(self, mist_image):
        """Find available locations for CloudImage.

        This method along with `_list_locations__get_available_images`
        are used to find the constraints between locations and images and
        save them in CloudLocation's availabe_images list field.

        Providers that return information about these constraints on images,
        should override this method.
        """
        return

    def _list_images__get_allowed_sizes(self, mist_image):
        """Find allowed sizes for CloudImage.

        This method along with `_list_sizes__get_allowed_images`
        are used to find the constraints between sizes and images and
        save them in CloudSize's allowed_images list field.

        Providers that return information about these constraints on images,
        should override this method.
        """
        return

    def _list_images__get_os_distro(self, image):
        """Get image distro from libcloud image

        Subclasses MAY override this method.

        Providers that return information about image distro should
        override this method.
        """
        if 'ubuntu' in image.name.lower():
            return 'ubuntu'
        elif 'centos' in image.name.lower():
            return 'centos'
        elif 'fedora' in image.name.lower():
            return 'fedora'
        elif 'debian' in image.name.lower():
            return 'debian'
        elif 'suse' in image.name.lower():
            return 'suse'
        elif 'rhel' in image.name.lower() or \
             'red hat enterprise linux' in image.name.lower():
            return 'rhel'
        elif 'windows' in image.name.lower():
            return 'windows'
        elif 'amazon linux' in image.name.lower():
            return 'amazon_linux'
        elif 'cloudlinux' in image.name.lower():
            return 'cloud_linux'
        elif 'freebsd' in image.name.lower():
            return 'freebsd'
        else:
            return 'other'

    def _list_images__get_min_disk_size(self, image):
        """Get the minimum disk size the image can be deployed in GBs.

        Subclasses MAY override this method.
        """
        return

    def _list_images__get_min_memory_size(self, image):
        """Get the minimum RAM size in MBs required by the image.

        Subclasses MAY override this method.
        """
        return

    def _list_images__get_architecture(self, image):
        """Get cpu architecture  from NodeImage.
        Return a list of strings containing'x86' and/or 'arm'
        as EquinixMetal has images that can be deployed on both architectures.

        Subclasses MAY override this method.
        """
        if 'arm' in image.name.lower():
            return ['arm']
        return ['x86']

    def _list_images__get_origin(self, image):
        """
        Return one of the following values: 'system', 'marketplace', 'custom'.

        'custom' for images made by the user
        'marketplace' for  marketplace images
        'system' for the standard images returned by provider
        """
        return 'system'

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
                # TODO: remove this block, once size patches
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
            # FIXME: Parse unit prefix w/ si-prefix, cast to int e.g 1k to 1000
            _size.disk = size.disk
            _size.bandwidth = size.bandwidth
            _size.missing_since = None
            _size.extra = self._list_sizes__get_extra(size)
            _size.architecture = self._list_sizes__get_architecture(size)

            try:
                allowed_images = self._list_sizes__get_allowed_images(size)  # noqa
            except Exception as exc:
                log.error('Error adding size-image constraint: %s'
                          % repr(exc))
            if allowed_images:
                _size.allowed_images = allowed_images

            if size.ram:
                try:
                    _size.ram = int(float(re.sub("[^\d.]+", "",
                                                 str(size.ram))))
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
            try:
                self._list_sizes__get_available_locations(_size)
            except Exception as exc:
                log.error("Error adding size-location constraint: %s"
                          % repr(exc))
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

    def _list_sizes__get_available_locations(self, mist_size):
        """Find available locations for CloudSize.

        This method along with `_list_locations__get_available_sizes`
        are used to find the constraints between locations and sizes and
        save them in CloudLocation availabe_sizes list field.

        Providers that return information about these constraints on sizes,
        should override this method.
        """
        return

    def _list_sizes__get_allowed_images(self, size):
        """Find available images for the specified NodeSize.
        Return a list of CloudImage objects

        This method along with `_list_images__get_allowed_sizes`
        are used to find the constraints between images and sizes and
        save them in CloudSize allowed_images list field.

        Providers that return information about these constraints on sizes,
        should override this method.
        """
        return

    def _list_sizes__get_architecture(self, size):
        """Get cpu architecture  from NodeSize.
        Valid return values are 'x86' or 'arm'.

        Subclasses MAY override this method.
        """
        if 'arm' in size.name.lower():
            return 'arm'
        return 'x86'

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

        new_location_objects = [location for location in locations
                                if location.id not in cached_locations.keys()]

        if amqp_owner_listening(self.cloud.owner.id):
            locations_dict = [l.as_dict() for l in locations]
            if cached_locations and locations_dict:
                new_locations = {'%s' % l['id']: l for l in locations_dict}
                # Pop extra to prevent weird patches
                for loc in cached_locations:
                    cached_locations[loc].pop('extra')
                for loc in new_locations:
                    new_locations[loc].pop('extra')
                # Publish patches to rabbitmq.

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

        # Update RBAC Mappings given the list of new locations.
        self.cloud.owner.mapper.update(new_location_objects,
                                       asynchronous=False)
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
                                          owner=self.cloud.owner,
                                          external_id=loc.id)
            _location.country = loc.country
            _location.name = loc.name
            _location.extra = copy.deepcopy(loc.extra)
            _location.missing_since = None

            try:
                available_sizes = self._list_locations__get_available_sizes(loc)  # noqa
            except Exception as exc:
                log.error('Error adding location-size constraint: %s'
                          % repr(exc))
            if available_sizes:
                _location.available_sizes = available_sizes

            try:
                available_images = self._list_locations__get_available_images(loc)  # noqa
            except Exception as exc:
                log.error('Error adding location-image constraint: %s'
                          % repr(exc))
            if available_images:
                _location.available_images = available_images

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

    def _list_locations__get_available_sizes(self, location):
        """Find available sizes for NodeLocation.
        Return a list of CloudSize objects.

        This method along with `_list_sizes__get_available_locations`
        are used to find the constraints between locations and sizes and
        save them in CloudLocation availabe_sizes list field.

        Providers that return information about these constraints on locations,
        should override this method.
        """
        return

    def _list_locations__get_available_images(self, location):
        """Find available images for NodeLocation.
        Return a list of CloudImage objects

        This method along with `_list_images__get_available_locations`
        are used to find the constraints between locations and images and
        save them in CloudLocation's availabe_images list field.

        Providers that return information about these constraints on locations,
        should override this method.
        """
        return

    def list_cached_locations(self):
        """Return list of locations from database for a specific cloud"""
        from mist.api.clouds.models import CloudLocation
        return CloudLocation.objects(cloud=self.cloud, missing_since=None)

    def _list_machines__get_location(self, node):
        """Find location code name/identifier from libcloud data

        This is to be called exclusively by `self._list_machines`.

        Subclasses MAY override this method.

        """
        return ''

    def _get_libcloud_node(self, machine, no_fail=False):
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

        node = self._get_libcloud_node(machine)
        try:
            return self._start_machine(machine, node)
        except MistError as exc:
            log.error("Could not start machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(str(exc))

    def _start_machine(self, machine, node):
        """Private method to start a given machine

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `start_machine`.
        """
        return self.connection.start_node(node)

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

        node = self._get_libcloud_node(machine)
        try:
            return self._stop_machine(machine, node)
        except MistError as exc:
            log.error("Could not stop machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

    def _stop_machine(self, machine, node):
        """Private method to stop a given machine

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `stop_machine`.
        """
        return self.connection.stop_node(node)

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

        node = self._get_libcloud_node(machine)
        try:
            return self._reboot_machine(machine, node)
        except MistError as exc:
            log.error("Could not reboot machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(exc=exc)

    def _reboot_machine(self, machine, node):
        """Private method to reboot a given machine

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `reboot_machine`.
        """
        return node.reboot()

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
                               machine.id, hostname, command)
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

        node = self._get_libcloud_node(machine)
        try:
            ret = self._destroy_machine(machine, node)
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

    def _destroy_machine(self, machine, node):
        """Private method to destroy a given machine

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `destroy_machine`.
        """
        try:
            return node.destroy()
        except BaseHTTPError:
            raise ForbiddenError("Cannot destroy machine. Check the "
                                 "termination protection setting on your "
                                 "cloud provider.")

    def remove_machine(self, machine):
        raise BadRequestError("Machines on public clouds can't be removed."
                              "This is only supported in Bare Metal and "
                              " KVM/Libvirt clouds.")

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

        node = self._get_libcloud_node(machine)
        try:
            from mist.api.clouds.models import CloudSize
            size = CloudSize.objects.get(id=size_id)
            node_size = NodeSize(size.external_id, name=size.name,
                                 ram=size.ram, disk=size.disk,
                                 bandwidth=size.bandwidth,
                                 price=size.extra.get('price'),
                                 driver=self.connection)
            self._resize_machine(machine, node, node_size, kwargs)
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

    def _resize_machine(self, machine, node, node_size, kwargs):
        """Private method to resize a given machine

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `resize_machine`.
        """
        self.connection.ex_resize_node(node, node_size)

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

        try:
            node = self._get_libcloud_node(machine)
        except MachineNotFoundError:
            node = None
        try:
            self._rename_machine(machine, node, name)
        except MistError as exc:
            log.error("Could not rename machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(str(exc))

    def _rename_machine(self, machine, node, name):
        """Private method to rename a given machine

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `rename_machine`.
        """
        self.connection.ex_rename_node(node, name)

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

        node = self._get_libcloud_node(machine)
        try:
            self._resume_machine(machine, node)
        except MistError as exc:
            log.error("Could not resume machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

    def _resume_machine(self, machine, node):
        """Private method to resume a given machine

        Only LibvirtComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

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

        node = self._get_libcloud_node(machine)
        try:
            return self._suspend_machine(machine, node)
        except MistError as exc:
            log.error("Could not suspend machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(str(exc))

    def _suspend_machine(self, machine, node):
        """Private method to suspend a given machine

        Only LibvirtComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `suspend_machine`.
        """
        raise MistNotImplementedError()

    def undefine_machine(self, machine, delete_domain_image=False):
        """Undefine machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to undefine a machine would be to run

            machine.ctl.undefine()

        which would in turn call this method, so that its cloud can customize
        it as needed.

        If a subclass of this controller wishes to override the way machines
        are undefined, it should override `_undefine_machine` method instead.

        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        if not machine.actions.undefine:
            raise ForbiddenError("Machine doesn't support undefine.")
        log.debug("Undefining machine %s", machine)

        node = self._get_libcloud_node(machine)
        try:
            return self._undefine_machine(machine, node, delete_domain_image)
        except MistError as exc:
            log.error("Could not undefine machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(str(exc))

    def _undefine_machine(self, machine, node):
        """Private method to undefine a given machine

        Only LibvirtComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

        Different cloud controllers should override this private method, which
        is called by the public method `undefine_machine`.
        """
        raise MistNotImplementedError()

    def power_cycle_machine(self, machine):
        assert self.cloud == machine.cloud
        if not machine.actions.power_cycle:
            raise ForbiddenError("Machine doesn't support power_cycle.")

        node = self._get_libcloud_node(machine)
        log.debug("Executing power_cycle action on machine %s", machine)

        try:
            return self._power_cycle_machine(node)
        except MistError as exc:
            log.error("Could not execute power_cycle on machine %s", machine)
            raise exc
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(str(exc))

    def _power_cycle_machine(self, node):
        """Private method to perform a `power cycle` action to a machine.

        Only DigitalOceanComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

        Different cloud controllers should override this private method, which
        is called by the public method `power_cycle_machine`.
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

        node = self._get_libcloud_node(machine)
        try:
            return self._create_machine_snapshot(
                machine, node, snapshot_name,
                description=description, dump_memory=dump_memory,
                quiesce=quiesce)
        except MistError as exc:
            log.error("Could not create snapshot for machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(str(exc))

    def _create_machine_snapshot(self, machine, node,
                                 snapshot_name, description='',
                                 dump_memory=False, quiesce=False):
        """Private method to create a snapshot for a given machine

        Only VSphereComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node
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

        node = self._get_libcloud_node(machine)
        try:
            return self._remove_machine_snapshot(machine, node,
                                                 snapshot_name)
        except MistError as exc:
            log.error("Could not remove snapshot of machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(str(exc))

    def _remove_machine_snapshot(self, machine, node,
                                 snapshot_name=None):
        """Private method to remove a snapshot for a given machine

        Only VSphereComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node
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

        node = self._get_libcloud_node(machine)
        try:
            return self._revert_machine_to_snapshot(machine, node,
                                                    snapshot_name)
        except MistError as exc:
            log.error("Could not revert machine %s to snapshot", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise BadRequestError(str(exc))

    def _revert_machine_to_snapshot(self, machine, node,
                                    snapshot_name=None):
        """Private method to revert a given machine to a previous snapshot

        Only VSphereComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node
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

        node = self._get_libcloud_node(machine)
        try:
            return self._list_machine_snapshots(machine, node)
        except MistError as exc:
            log.error("Could not list snapshots for machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(str(exc))

    def _list_machine_snapshots(self, machine, node):
        """Private method to list a given machine's snapshots

        Only VSphereComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node

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

        node = self._get_libcloud_node(machine)
        try:
            clone = self._clone_machine(machine, node, name, resume)
        except MistError as exc:
            log.error("Failed to clone %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)
        ret = {'id': clone.id,
               'name': clone.name,
               'extra': clone.extra
               }
        return ret

    def _clone_machine(self, machine, node, name=None,
                       resume=False):
        """Private method to clone a given machine

        Only LibvirtComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            node: instance of corresponding libcloud node
            name: the clone's unique name
            resume: denotes whether to resume the original node

        Different cloud controllers should override this private method,
        which is called by the public method `clone_machine`.

        """
        raise MistNotImplementedError()

    def list_security_groups(self) -> List[Dict]:
        """List security groups.

        A subclass that wishes to implement this functionality should override
        the `_list_security_groups` method instead.
        """
        return self._list_security_groups()

    def _list_security_groups(self) -> List[Dict]:
        """Fetch security groups.

        This is to be called exclusively by `self.list_security_groups`.

        Subclasses that implement this functionality SHOULD override this
        method
        """
        raise MistNotImplementedError()

    def generate_plan(self, auth_context, plan, name, image,
                      size, location='', key=None,
                      networks=None, volumes=None, disks=None,
                      extra=None, scripts=None, schedules=None, cloudinit='',
                      fqdn='', monitoring=False, request_tags=None,
                      expiration=None, quantity=1):
        """Generate a machine creation plan.

        Subclasses SHOULD NOT override or extend this method

        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specifics of
        their cloud type. These methods are:

            `self._generate_plan__parse_image`
            `self._generate_plan__parse_custom_image`
            `self._generate_plan__parse_location`
            `self._generate_plan__parse_size`
            `self._generate_plan__parse_custom_size`
            `self._generate_plan__get_image_size_location`
            `self._generate_plan__parse_key`
            `self._generate_plan__parse_networks`
            `self._generate_plan__parse_volumes`
            `self._generate_plan__parse_disks`
            `self._generate_plan__parse_extra`
            `self._generate_plan__post_parse_plan`
        """
        from mist.api.machines.methods import machine_name_validator
        from mist.api.helpers import (
            compute_tags,
            check_expiration_constraint,
            check_cost_constraint,
            check_size_constraint,
        )
        plan['machine_name'] = machine_name_validator(self.provider,
                                                      name)

        tags, constraints = auth_context.check_perm('machine', 'create', None)
        constraints = constraints or {}

        tags = compute_tags(auth_context, tags, request_tags)
        if tags:
            plan['tags'] = tags

        expiration = self._generate_plan__parse_expiration(auth_context,
                                                           expiration)
        exp_constraint = constraints.get('expiration', {})
        check_expiration_constraint(expiration, exp_constraint)
        if expiration:
            plan['expiration'] = expiration

        cost_constraint = constraints.get('cost', {})
        check_cost_constraint(auth_context, cost_constraint)

        images, image_extra_attrs = self._generate_plan__parse_image(
            auth_context, image)
        image_extra_attrs = image_extra_attrs or {}

        if self.cloud.ctl.has_feature('location'):
            locations = self._generate_plan__parse_location(auth_context,
                                                            location)
        else:
            # TODO this will not work in combinations
            locations = None

        sizes, size_extra_attrs = self._generate_plan__parse_size(
            auth_context, size)
        size_extra_attrs = size_extra_attrs or {}

        size_constraint = constraints.get('size', {})
        sizes = check_size_constraint(self.cloud.id, size_constraint, sizes)

        comb_list = self._get_allowed_image_size_location_combinations(
            images, locations, sizes, image_extra_attrs, size_extra_attrs)

        image, size, location = self._compute_best_combination(comb_list)

        if location:
            plan['location'] = {'id': location.id, 'name': location.name}
        if size:
            # custom size
            if isinstance(size, dict):
                plan['size'] = size
            else:
                plan['size'] = {'id': size.id, 'name': size.name}
            plan['size'].update(size_extra_attrs)
        if image:
            plan['image'] = {'id': image.id, 'name': image.name}
            plan['image'].update(image_extra_attrs)

        key, key_extra_attrs = self._generate_plan__parse_key(auth_context,
                                                              key)
        key_extra_attrs = key_extra_attrs or {}
        if key:
            plan['key'] = {'id': key.id, 'name': key.name}
            plan['key'].update(key_extra_attrs)

        networks = self._generate_plan__parse_networks(auth_context,
                                                       networks)
        if networks:
            plan['networks'] = networks

        if self.cloud.ctl.has_feature('storage'):
            volumes = self._generate_plan__parse_volumes(auth_context,
                                                         volumes)
            if volumes:
                plan['volumes'] = volumes

        disks = self._generate_plan__parse_disks(auth_context,
                                                 disks)
        if disks:
            plan['disks'] = disks

        scripts = self._generate_plan__parse_scripts(auth_context, scripts)
        if scripts:
            plan['scripts'] = scripts

        extra = extra or {}
        self._generate_plan__parse_extra(extra, plan)

        schedules = self._generate_plan__parse_schedules(auth_context,
                                                         schedules)
        if schedules:
            plan['schedules'] = schedules

        if cloudinit and self.cloud.ctl.has_feature('cloudinit'):
            plan['cloudinit'] = cloudinit

        if fqdn and self.cloud.ctl.has_feature('dns'):
            plan['fqdn'] = fqdn

        plan['monitoring'] = True if monitoring is True else False
        plan['quantity'] = quantity if quantity else 1

        self._generate_plan__post_parse_plan(plan)
        return plan

    def _generate_plan__parse_image(self, auth_context, image_obj):
        """Parse the image parameter from request.

        Returns a tuple of the following items:
        - A list of CloudImage objects
        - A dictionary of items to be added as is to plan's image dictionary
          or by default None

        Subclasses MAY override or extend this method.
        """
        if self.cloud.ctl.has_feature('custom_image'):
            image = self._generate_plan__parse_custom_image(image_obj)
            return [image], None

        from mist.api.methods import list_resources
        if isinstance(image_obj, str):
            image_search = image_obj
        elif isinstance(image_obj, dict):
            image_search = image_obj.get('image')
        else:
            raise BadRequestError('Invalid image type')
        if not image_search:
            raise BadRequestError('Image is required')
        images, count = list_resources(
            auth_context, 'image', search=image_search,
            cloud=self.cloud.id
        )
        if not count:
            raise NotFoundError('Image not found')

        ret_images = []
        for image in images:
            try:
                auth_context.check_perm('image',
                                        'create_resources',
                                        image.id)
            except PolicyUnauthorizedError:
                continue
            else:
                ret_images.append(image)

        return ret_images, None

    def _generate_plan__parse_custom_image(self, image_dict):
        """Get an image that is not saved in mongo.
        This could be a docker image that needs to be pulled.
        """
        pass

    def _generate_plan__parse_location(self, auth_context, location_search):
        """Parse the location string parameter from request

        Returns a list of CloudLocation objects

        Subclasses MAY override or extend this method.
        """
        from mist.api.methods import list_resources
        locations, count = list_resources(
            auth_context, 'location',
            search=location_search,
            cloud=self.cloud.id)
        if not count:
            raise NotFoundError('Location not found')

        ret_locations = []
        for location in locations:
            try:
                auth_context.check_perm('location',
                                        'create_resources',
                                        location.id)
            except PolicyUnauthorizedError:
                continue
            else:
                ret_locations.append(location)

        return ret_locations

    def _generate_plan__parse_size(self, auth_context, size_obj):
        """Parse the size parameter from request.

        Returns a tuple of the following items:
        - A list of CloudSize or dictionary objects in case of custom size
        - A dictionary of items to be added as is to plan's size dictionary
          or None

        Subclasses MAY override or extend this method.
        """
        from mist.api.methods import list_resources
        if isinstance(size_obj, str):
            size_search = size_obj
        elif isinstance(size_obj, dict):
            size_search = size_obj.get('size')
        else:
            raise BadRequestError('Invalid size type')

        if size_search:
            sizes, count = list_resources(
                auth_context, 'size', search=size_search,
                cloud=self.cloud.id
            )
            if not count:
                raise NotFoundError('Size not found')

            return sizes, None
        else:
            sizes = self._generate_plan__parse_custom_size(
                auth_context, size_obj)
            return sizes, None

    def _generate_plan__parse_custom_size(self, auth_context, size_dict):
        """Parse custom size from request.

        In case of providers with custom sizes a list of dictionaries
        will be returned.
        For providers with standard sizes a list of CloudSize objects
        within the range: [(`cpus`, `ram`), [(2*`cpus`, 2*`ram`)]
        will be returned.

        Subclasses MAY override or extend this method.
        """
        try:
            cpus = size_dict['cpus']
            ram = size_dict['ram']
        except (KeyError, TypeError):
            raise BadRequestError('Required parameter missing')

        if self.cloud.ctl.has_feature('custom_size'):
            return [{'cpus': cpus, 'ram': ram}]

        from mist.api.methods import list_resources
        size_search = f'cpus>={cpus} ram>={ram} cpus<={cpus*2} ram<={ram*2}'
        sizes, count = list_resources(
            auth_context, 'size', search=size_search,
            cloud=self.cloud.id
        )
        if not count:
            raise NotFoundError(
                'Size with the given cpu and ram does not exist')

        return sizes

    def _get_allowed_image_size_location_combinations(self, images,
                                                      locations,
                                                      sizes,
                                                      image_extra_attrs,
                                                      size_extra_attrs):
        """ Find all possible combinations of images, locations and sizes
        based on provider restrictions.
        """
        try:
            custom_size = isinstance(sizes[0], dict)
        except IndexError:
            raise NotFoundError('No available plan exists for given size')

        ret_list = []
        for location in locations:
            available_sizes = sizes
            if self.cloud.ctl.has_feature('location-size-restriction'):
                available_sizes = set(location.available_sizes).intersection(set(available_sizes))  # noqa
            for size in available_sizes:
                available_images = images
                if self.cloud.ctl.has_feature('location-image-restriction'):
                    available_images = set(location.available_images).intersection(set(available_images))  # noqa
                if self.cloud.ctl.has_feature('size-image-restriction') \
                        and custom_size is False:
                    available_images = set(size.allowed_images).intersection(set(available_images))  # noqa
                for image in available_images:
                    # Some sizes in azure, ec2, gce and rackspace
                    # support only volumes, so size.disk could be 0,
                    # thus we intentionally skip checking the disk restriction
                    # in these sizes.
                    if custom_size is False \
                            and image.min_disk_size is not None \
                            and size.disk \
                            and image.min_disk_size > size.disk:
                        continue
                    if custom_size is False \
                            and image.min_memory_size is not None \
                            and size.ram is not None \
                            and image.min_memory_size > size.ram:
                        continue
                    if custom_size is False \
                            and size.architecture not in image.architecture:
                        continue
                    ret_list.append((image, size, location))
        return ret_list

    def _generate_plan__parse_scripts(self, auth_context, scripts):
        ret_scripts = []
        from mist.api.methods import list_resources
        for script in scripts:
            if script.get('script'):
                script_search = script.get('script')
                try:
                    [script_obj], _ = list_resources(auth_context, 'script',
                                                     search=script_search,
                                                     limit=1)
                except ValueError:
                    raise NotFoundError('Script does not exist')
                auth_context.check_perm('script', 'run', script_obj.id)
                ret_scripts.append({
                    'id': script_obj.id,
                    'params': script.get('params')
                })
            else:
                # inline script
                if script.get('inline'):
                    ret_scripts.append({
                        'inline': script['inline']
                    })
        return ret_scripts

    def _compute_best_combination(self, combination_list):
        """Find the best combination of image,size,location

        Subclasses that require special handling should override these, by
        default, dummy methods.
        """
        if not combination_list:
            raise NotFoundError('No available plan exists for given '
                                'images, sizes, locations')

        has_price_info = any(size.extra.get('price')
                             for _, size, _ in combination_list)

        def sort_by_price(value):
            image, size, location = value
            price = size.extra.get('price') or float('inf')
            return price, -image.starred, len(image.name)

        def sort_by_size(value):
            image, size, location = value
            cpus = size.cpus or float('inf')
            ram = size.ram or float('inf')
            return cpus, ram, -image.starred, len(image.name)

        if has_price_info:
            return sorted(combination_list, key=sort_by_price)[0]
        return sorted(combination_list, key=sort_by_size)[0]

    def _generate_plan__parse_key(self, auth_context, key_obj):
        """Parse the key parameter from request.

        Returns a tuple of the following items:
        - A Key object or None
        - A dictionary of items to be added as is to plan's key dictionary
          or None

        Subclasses MAY override this method.
        """
        feature = self.cloud.ctl.has_feature('key')
        if feature is False:
            return None, None
        if isinstance(key_obj, str):
            key_search = key_obj
        elif isinstance(key_obj, dict):
            key_search = key_obj.get('key', '')
        else:
            raise BadRequestError('Invalid key type')

        #  key is not required and a key was not given
        if isinstance(feature, dict) \
           and feature.get('required') is False \
           and key_search == '':
            return None, None

        from mist.api.methods import list_resources
        keys, count = list_resources(
            auth_context, 'key', search=key_search, limit=1
        )
        if not count:
            raise NotFoundError('Key not found')
        # try to use the default key
        for key in keys:
            if key.default is True:
                return key, None
        return keys[0], None

    def _generate_plan__parse_expiration(self, auth_context,
                                         expiration):
        if not expiration:
            return {}

        if isinstance(expiration, dict):
            return expiration

        # expiration object
        exp_dict = expiration.to_dict()
        if exp_dict.get('notify'):
            # convert notify object to datetime str
            try:
                value = exp_dict['notify']['value']
                period = exp_dict['notify']['period']
            except KeyError:
                raise BadRequestError('Parameter missing in expiration')
            if period == 'minutes':
                notify = datetime.timedelta(minutes=value)
            elif period == 'hours':
                notify = datetime.timedelta(hours=value)
            else:
                notify = datetime.timedelta(days=value)

            exp_dict['notify'] = (exp_dict['date'] - notify).strftime('%Y-%m-%d %H:%M:%S')  # noqa
        exp_dict['date'] = datetime.datetime.strftime(exp_dict['date'],
                                                      '%Y-%m-%d %H:%M:%S')

        return exp_dict

    def _generate_plan__parse_networks(self, auth_context, networks_dict):
        pass

    def _generate_plan__parse_volumes(self, auth_context, volumes):
        """Returns a list of dictionaries containing either volume IDs,
        volume to be created attributes e.g size, name, filesystem or
        something provider specific.

        Subclasses MAY override this method, even though overriding
        `self._generate_plan__parse_custom_volume` or
        `self._generate_plan__parse_volume_attrs` should be enough for
        most cases
        """
        ret_volumes = []
        from mist.api.methods import list_resources
        for volume in volumes:
            if volume.get('volume'):
                try:
                    [vol], _ = list_resources(
                        auth_context, 'volume', search=volume['volume'],
                        cloud=self.cloud.id
                    )
                except ValueError:
                    raise NotFoundError('Volume does not exist')
                volume_dict = self._generate_plan__parse_volume_attrs(volume,
                                                                      vol)
                ret_volumes.append(volume_dict)
            else:
                vol = self._generate_plan__parse_custom_volume(volume)
                ret_volumes.append(vol)
        return ret_volumes

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        """Create and return a dictionary with all of the provider's
        attributes necessary to attach the already existing volume to a
        machine.

        Subclasses that require special handling SHOULD override this
        by default, dummy method
        """
        return {'id': vol_obj.id, 'name': vol_obj.name}

    def _generate_plan__parse_custom_volume(self, volume_dict):
        """
        Parse non-mist volumes e.g volumes to be created.

        Subclasses that require special handling should override this
        by default, dummy method
        """
        size = volume_dict.get('size')
        return {'size': size}

    def _generate_plan__parse_disks(self, auth_context, disks_dict):
        pass

    def _generate_plan__parse_extra(self, extra, plan):
        """Extract provider specific parameters from extra dictionary
        and add them in place to plan

        Subclasses MAY override this method.
        """
        pass

    def _generate_plan__parse_schedules(self, auth_context, schedules):
        """
        Schedule attributes:
            `schedule_type`: 'one_off', 'interval', 'crontab'
            `action`: 'start' 'stop', 'reboot', 'destroy'
            `script`: dictionary containing:
                    `script`: id or name of the script to run
                    `params`: optional script parameters

            one_off schedule_type parameters:
                `datetime`: when schedule should run,
                            e.g '2020-12-15T22:00:00Z'
            crontab schedule_type parameters:
                `minute`: e.g '*/10',
                `hour`
                `day_of_month`
                `month_of_year`
                `day_of_week`

            interval schedule_type parameters:
                    `every`: int ,
                    `period`: minutes,hours,days

            `expires`: date when schedule should expire,
            e.g '2020-12-15T22:00:00Z'

            `start_after`: date when schedule should start running,
            e.g '2020-12-15T22:00:00Z'

            `max_run_count`: max number of times to run
            description:
        """
        if not schedules:
            return None
        ret_schedules = []
        for schedule in schedules:
            schedule_type = schedule.get('schedule_type')
            if schedule_type not in ['crontab', 'interval', 'one_off']:
                raise BadRequestError('schedule type must be one of '
                                      'these (crontab, interval, one_off)]')

            ret_schedule = {
                'schedule_type': schedule_type,
                'description': schedule.get('description', ''),
                'task_enabled': True,
            }
            action = schedule.get('action')
            script = schedule.get('script')
            if action is None and script is None:
                raise BadRequestError('Schedule action or script not defined')
            if action and script:
                raise BadRequestError(
                    'One of action or script should be defined')
            if action:
                if action not in ['reboot', 'destroy', 'start', 'stop']:
                    raise BadRequestError('Action is not correct')
                ret_schedule['action'] = action
            else:
                from mist.api.methods import list_resources
                script_search = script.get('script')
                if not script_search:
                    raise BadRequestError('script parameter is required')
                try:
                    [script_obj], _ = list_resources(auth_context, 'script',
                                                     search=script_search,
                                                     limit=1)
                except ValueError:
                    raise NotFoundError('Schedule script does not exist')
                auth_context.check_perm('script', 'run', script_obj.id)
                ret_schedule['script_id'] = script_obj.id
                ret_schedule['script_name'] = script_obj.name
                ret_schedule['params'] = script.get('params')
            if schedule_type == 'one_off':
                # convert schedule_entry from ISO format
                # to '%Y-%m-%d %H:%M:%S'
                try:
                    ret_schedule['schedule_entry'] = datetime.datetime.strptime(  # noqa
                        schedule['datetime'], '%Y-%m-%dT%H:%M:%SZ'
                    ).strftime("%Y-%m-%d %H:%M:%S")
                except KeyError:
                    raise BadRequestError(
                        'one_off schedule parameter missing')
                except ValueError:
                    raise BadRequestError(
                        'Schedule parameter datetime does not match'
                        ' format %Y-%m-%dT%H:%M:%SZ')
            elif schedule_type == 'interval':
                try:
                    ret_schedule['schedule_entry'] = {
                        'every': schedule['every'],
                        'period': schedule['period']
                    }
                except KeyError:
                    raise BadRequestError(
                        'interval schedule parameter missing')
            elif schedule_type == 'crontab':
                try:
                    ret_schedule['schedule_entry'] = {
                        'minute': schedule['minute'],
                        'hour': schedule['hour'],
                        'day_of_month': schedule['day_of_month'],
                        'month_of_year': schedule['month_of_year'],
                        'day_of_week': schedule['day_of_week']
                    }
                except KeyError:
                    raise BadRequestError(
                        'crontab schedule parameter missing')

            if schedule_type in ['crontab', 'interval']:
                if schedule.get('start_after'):
                    # convert `start_after` from ISO format
                    # to '%Y-%m-%d %H:%M:%S'
                    try:
                        ret_schedule['start_after'] = datetime.datetime.strptime(  # noqa
                            schedule['start_after'], '%Y-%m-%dT%H:%M:%SZ'
                        ).strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        raise BadRequestError('Parameter `start_after` does '
                                              'not match format '
                                              '%Y-%m-%dT%H:%M:%SZ'
                                              )
                if schedule.get('expires'):
                    # convert `expires` from ISO format
                    # to '%Y-%m-%d %H:%M:%S'
                    try:
                        ret_schedule['expires'] = datetime.datetime.strptime(  # noqa
                            schedule['expires'], '%Y-%m-%dT%H:%M:%SZ'
                        ).strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        raise BadRequestError('Parameter `expires` does not '
                                              'match format %Y-%m-%dT%H:%M:%SZ'
                                              )
                ret_schedule['max_run_count'] = schedule.get('max_run_count',
                                                             '')
            ret_schedules.append(ret_schedule)

        return ret_schedules

    def _generate_plan__post_parse_plan(self, plan):
        """Used to parse whole plan in place, instead of specific parts of it.
        For example a provider could have some parameters from extra and
        networks that need to be processed together.

        Subclasses that require special handling SHOULD override this method.
        """
        pass

    def create_machine(self, plan):
        """Create and return a node

        Subclasses SHOULD NOT override or extend this method.

        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specifics of
        their cloud type. These methods are:

            `self._create_machine__compute_kwargs`
            `self._create_machine__get_image_object`
            `self._create_machine__get_location_object`
            `self._create_machine__get_size_object`
            `self._create_machine__get_key_object`
            `self._create_machine__create_node`
            `self._create_machine__handle_exception`
            `self._create_machine__post_machine_creation_steps`
        """
        kwargs = self._create_machine__compute_kwargs(plan)

        try:
            node = self._create_machine__create_node(kwargs)
        except Exception as exc:
            self._create_machine__handle_exception(exc, kwargs)

        self._create_machine__post_machine_creation_steps(node, kwargs, plan)

        return node

    def _create_machine__compute_kwargs(self, plan):
        """Extract items from plan and prepare kwargs
        that will be passed to `create_node`/`deploy_container`.

        This is to be called exclusively by `self.create_machine`.

        Subclasses MAY override/extend this method.
        """
        kwargs = {
            'name': plan['machine_name']
        }

        if plan['size'].get('id'):
            size = plan['size']['id']
        else:
            # custom size
            size = plan['size']

        image = self._create_machine__get_image_object(
            plan['image'].get('id'))
        location = self._create_machine__get_location_object(
            plan.get('location', {}).get('id'))
        size = self._create_machine__get_size_object(size)
        key = self._create_machine__get_key_object(
            plan.get('key', {}).get('id'))

        if image:
            kwargs['image'] = image

        if size:
            kwargs['size'] = size

        if location:
            kwargs['location'] = location

        if key:
            kwargs['auth'] = key

        return kwargs

    def _create_machine__create_node(self, kwargs):
        """Wrapper method for libcloud's `create_node`/`deploy_container`

        This is to be called exclusively by `self.create_machine`.

        Most subclasses shouldn't need to override or extend this method.

        Subclasses MAY override this method.
        """
        if self.cloud.ctl.has_feature('container'):
            node = self.connection.deploy_container(**kwargs)
        else:
            node = self.connection.create_node(**kwargs)
        return node

    def _create_machine__handle_exception(self, exc, kwargs):
        """Handle exception in `create_node` method

        This is to be called exclusively by `self.create_machine`.

        Subclasses that require special handling SHOULD override this method.
        """
        raise MachineCreationError("%s, got exception %s"
                                   % (self.cloud.name, exc), exc)

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        """Post create machine actions.

        This is to be called exclusively by `self.create_machine`.

        Subclasses that require special handling, e.g attach a volume,
        MAY override this method.
        """
        pass

    def _create_machine__get_key_object(self, key):
        """Retrieve Key object from mongo.

        Subclasses that require special handling MAY override this method.
        """
        if key and self.cloud.ctl.has_feature('key'):
            from mist.api.keys.models import Key
            try:
                key_obj = Key.objects.get(id=key)
            except me.DoesNotExist:
                raise NotFoundError('Key does not exist')
            key_obj.public = key_obj.public.replace('\n', '')
            return key_obj

    def _create_machine__get_image_object(self, image):
        """Retrieve CloudImage object from mongo.

        Subclasses that require special handling MAY override this method.
        """
        if image:
            from mist.api.images.models import CloudImage
            try:
                cloud_image = CloudImage.objects.get(id=image)
            except me.DoesNotExist:
                if self.cloud.ctl.has_feature('custom_image'):
                    return image
                else:
                    raise NotFoundError('Image does not exist')
            image_obj = NodeImage(cloud_image.external_id,
                                  name=cloud_image.name,
                                  extra=cloud_image.extra,
                                  driver=self.connection)
            return image_obj

    def _create_machine__get_location_object(self, location):
        """Retrieve CloudLocation object from mongo.

        Subclasses that require special handling MAY override this method.
        """
        if location and self.cloud.ctl.has_feature('location'):
            from mist.api.clouds.models import CloudLocation
            try:
                cloud_location = CloudLocation.objects.get(id=location)
            except me.DoesNotExist:
                raise NotFoundError('Location does not exist')
            location_οbj = NodeLocation(cloud_location.external_id,
                                        name=cloud_location.name,
                                        country=cloud_location.country,
                                        extra=cloud_location.extra,
                                        driver=self.connection)
            return location_οbj

    def _create_machine__get_size_object(self, size):
        """Retrieve CloudSize object from mongo or in the case
        of custom size return it as is.

        Subclasses that require special handling MAY override this method.
        """
        if self.cloud.ctl.has_feature('custom_size') \
                and isinstance(size, dict):
            return size
        else:
            from mist.api.clouds.models import CloudSize
            try:
                cloud_size = CloudSize.objects.get(id=size)
            except me.DoesNotExist:
                raise NotFoundError('Location does not exist')
            size_obj = NodeSize(cloud_size.external_id,
                                name=cloud_size.name,
                                ram=cloud_size.ram,
                                disk=cloud_size.disk,
                                bandwidth=cloud_size.bandwidth,
                                price=cloud_size.extra.get('price'),
                                extra=cloud_size.extra,
                                driver=self.connection)
            return size_obj

    def _update_metering_data(self, cached_machines, machines):
        machines_map = {machine.id: machine for machine in machines}
        cached_machines_map = {
            machine["id"]: machine for machine in cached_machines}

        read_queries, metering_metrics = self._generate_metering_queries(
            cached_machines_map, machines_map)

        last_metering_data = self._fetch_metering_data(read_queries)

        fresh_metering_data = self._generate_fresh_metering_data(
            cached_machines_map, machines_map, last_metering_data,
            metering_metrics)

        self._send_metering_data(fresh_metering_data)

    def _get_machine_metering_metrics(
            self, machine_id, machines_map, metering_metrics):
        if metering_metrics.get(machines_map[machine_id].owner.id):
            return metering_metrics[machines_map[machine_id].owner.id]
        if metering_metrics.get(machines_map[machine_id].cloud.provider):
            return metering_metrics[machines_map[machine_id].cloud.provider]
        if metering_metrics.get("default"):
            return metering_metrics["default"]
        return {}

    def _update_metering_metrics_map(self, machines_map):
        metering_metrics = {}
        for machine_id, _ in machines_map.items():
            if config.METERING_METRICS.get(
                    machines_map[machine_id].owner.id) and \
                    not metering_metrics.get(
                        machines_map[machine_id].owner.id):
                metering_metrics[machines_map[machine_id].owner.id] = \
                    config.METERING_METRICS.get("default", {})
                metering_metrics[machines_map[
                    machine_id].owner.id].update(
                        config.METERING_METRICS.get(
                            machines_map[machine_id].cloud.provider, {}))
                metering_metrics[machines_map[machine_id].owner.id].update(
                    config.METERING_METRICS.get(machines_map[
                        machine_id].owner.id, {}))
            if config.METERING_METRICS.get(
                machines_map[machine_id].cloud.provider) and \
                    not metering_metrics.get(
                        machines_map[machine_id].cloud.provider):
                metering_metrics[machines_map[
                    machine_id].cloud.provider] = config.METERING_METRICS.get(
                    "default", {})
                metering_metrics[machines_map[
                    machine_id].cloud.provider].update(
                        config.METERING_METRICS.get(
                            machines_map[machine_id].cloud.provider, {}))
            if config.METERING_METRICS.get("default") and \
                    not metering_metrics.get("default"):
                metering_metrics["default"] = config.METERING_METRICS[
                    "default"]
        return metering_metrics

    def _generate_metering_queries(self, cached_machines_map, machines_map):
        # Group the machines based on their last metering timestamp
        last_metering_dt_machines_map = {}
        for machine_id, _ in machines_map.items():
            if not cached_machines_map.get(machine_id):
                continue
            dt = None
            if cached_machines_map[machine_id]["last_seen"]:
                dt = cached_machines_map[machine_id]["last_seen"]
            elif cached_machines_map[machine_id]["missing_since"]:
                dt = cached_machines_map[machine_id]["missing_since"]
            if not dt:
                continue
            if not last_metering_dt_machines_map.get(dt):
                last_metering_dt_machines_map[dt] = []
            last_metering_dt_machines_map[dt].append(machine_id)

        metering_metrics = self._update_metering_metrics_map(machines_map)

        # Create promql queries to fetch metering data (counters) in bulk
        # (One query per unique timestamp across multiple machines)
        read_queries = {}
        machine_metrics_category_map = {}

        for dt, machine_ids in last_metering_dt_machines_map.items():
            for machine_id in machine_ids:
                if config.METERING_METRICS.get(machines_map[
                        machine_id].owner.id):
                    if not machine_metrics_category_map.get(
                            (dt, machines_map[machine_id].owner.id)):
                        machine_metrics_category_map[(
                            dt, machines_map[machine_id].owner.id)] = []
                    machine_metrics_category_map[(dt, machines_map[
                        machine_id].owner.id)].append(
                        machine_id)
                elif config.METERING_METRICS.get(machines_map[
                        machine_id].cloud.provider):
                    if not machine_metrics_category_map.get(
                            (dt, machines_map[machine_id].cloud.provider)):
                        machine_metrics_category_map[(
                            dt, machines_map[machine_id].cloud.provider)] = []
                    machine_metrics_category_map[(dt, machines_map[
                        machine_id].cloud.provider)].append(
                        machine_id)
                elif config.METERING_METRICS.get("default"):
                    if not machine_metrics_category_map.get((dt, "default")):
                        machine_metrics_category_map[(dt, "default")] = []
                    machine_metrics_category_map[(dt, "default")].append(
                        machine_id)

        for key, machine_ids in machine_metrics_category_map.items():
            dt, metrics_category = key
            metering_metrics_list = "|".join(
                metric_name
                for metric_name, properties in metering_metrics[
                    metrics_category].items()
                if properties['type'] == "counter")
            machines_ids_list = "|".join(machine_ids)
            read_queries[(dt, metrics_category)] = (
                f"{{__name__=~\"{metering_metrics_list}\""
                f",org=\"{self.cloud.owner.id}\","
                f"machine_id=~\"{machines_ids_list}\",metering=\"true\"}}")
        return read_queries, metering_metrics

    def _fetch_metering_data(self, read_queries):
        tenant = str(int(self.cloud.owner.id[:8], 16))
        read_uri = config.VICTORIAMETRICS_URI.replace("<org_id>", tenant)
        last_metering_data = {}

        for key, query in read_queries.items():
            dt, _ = key
            dt = int(datetime.datetime.timestamp(
                datetime.datetime.strptime(dt, '%Y-%m-%d %H:%M:%S.%f')))
            data = requests.get(
                f"{read_uri}/api/v1/query"
                f"?query={query}&time={dt}",
                timeout=20)

            if not data.ok:
                log.warning(data.text)

            data = data.json()

            for result in data.get("data", {}).get("result", []):
                metric_name = result["metric"]["__name__"]
                machine_id = result["metric"]["machine_id"]
                value = result["value"][1]
                if not last_metering_data.get(machine_id):
                    last_metering_data[machine_id] = {}
                last_metering_data[machine_id].update({metric_name: value})
        return last_metering_data

    def _find_old_counter_value(self, metric_name, machine_id, properties):
        tenant = str(int(self.cloud.owner.id[:8], 16))
        read_uri = config.VICTORIAMETRICS_URI.replace("<org_id>", tenant)
        query = (
            f"last_over_time("
            f"{metric_name}{{org=\"{self.cloud.owner.id}\""
            f",machine_id=\"{machine_id}\",metering=\"true\""
            f",value_type=\"{properties['type']}\"}}"
            f"[{config.METERING_PROMQL_LOOKBACK}])"
        )
        data = requests.get(
            f"{read_uri}/api/v1/query"
            f"?query={query}",
            timeout=20)

        if not data.ok:
            log.warning(data.text)

        data = data.json()
        results = data.get("data", {}).get("result", [])
        if len(results) > 1:
            log.warning("Returned more series than expected")
        if len(results) == 0:
            return 0
        return results[0]["value"][1]

    def _generate_fresh_metering_data(
            self, cached_machines_map, machines_map,
            last_metering_data, metering_metrics):
        fresh_metering_data = ""
        for machine_id, machine in machines_map.items():
            if not machine.last_seen:
                continue
            new_dt = machine.last_seen
            old_dt = None
            if cached_machines_map.get(machine_id) and \
                    cached_machines_map[machine_id]["last_seen"]:
                old_dt = datetime.datetime.strptime(
                    cached_machines_map[machine_id]["last_seen"],
                    '%Y-%m-%d %H:%M:%S.%f')
            for metric_name, properties in self._get_machine_metering_metrics(
                    machine_id, machines_map, metering_metrics).items():
                current_value = None
                if properties["type"] == "counter":
                    old_value = last_metering_data.get(
                        machine_id, {}).get(metric_name)
                    if old_value:
                        current_value = float(old_value)
                        # Take into account the time range only
                        # if the machine was not missing
                        if old_dt:
                            delta_in_hours = (
                                new_dt - old_dt).total_seconds() / (60 * 60)
                            current_value += properties["value"](
                                machine, delta_in_hours)
                    else:
                        current_value = self._find_old_counter_value(
                            metric_name, machine_id, properties)
                elif properties["type"] == "gauge":
                    current_value = properties["value"](machine)
                else:
                    log.warning(
                        f"Unknown metric type: {properties['type']}"
                        f" on metric: {metric_name}"
                        f" with machine_id: {machine_id}")
                if current_value is not None:
                    fresh_metering_data += (
                        f"{metric_name}{{org=\"{self.cloud.owner.id}\""
                        f",machine_id=\"{machine_id}\",metering=\"true\""
                        f",value_type=\"{properties['type']}\"}}"
                        f" {current_value} "
                        f"{int(datetime.datetime.timestamp(new_dt))}\n")
                else:
                    log.warning(
                        f"None value on metric: "
                        f"{metric_name} with machine_id: {machine_id}")
        return fresh_metering_data

    def _send_metering_data(self, fresh_metering_data):
        tenant = str(int(self.cloud.owner.id[:8], 16))
        result = requests.post(
            config.VICTORIAMETRICS_WRITE_URI.replace(
                "<org_id>", tenant),
            data=fresh_metering_data, timeout=20)
        if not result.ok:
            log.warning(
                f"Error when sending metering data,"
                f" code: {result.status_code} response: {result.text}")
