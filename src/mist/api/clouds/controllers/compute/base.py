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

import jsonpatch

import mongoengine as me

from libcloud.common.types import InvalidCredsError
from libcloud.compute.types import NodeState
from libcloud.compute.base import NodeLocation, Node
from libcloud.common.exceptions import BaseHTTPError

from amqp.connection import Connection

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

from mist.api.helpers import get_datetime
from mist.api.helpers import amqp_publish
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening

from mist.api.concurrency.models import PeriodicTaskInfo
from mist.api.concurrency.models import PeriodicTaskThresholdExceeded

from mist.api.clouds.controllers.base import BaseController
from mist.api.tag.models import Tag
from mist.api.machines.models import Machine
from mist.api.misc.cloud import CloudLocation
from mist.api.misc.cloud import CloudSize

if config.HAS_CORE:
    from mist.core.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat

log = logging.getLogger(__name__)


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
        owner=machine.cloud.owner, resource=machine,
    )}

    try:
        cph = parse_num(tags.get('cost_per_hour'))
        cpm = parse_num(tags.get('cost_per_month'))
        if not (cph or cpm) or cph > 100 or cpm > 100 * 24 * 31:
            log.debug("Invalid cost tags for machine %s", machine)
            cph, cpm = map(parse_num, cost)
        if not cph:
            cph = float(cpm) / month_days / 24
        elif not cpm:
            cpm = cph * 24 * month_days
    except Exception:
        log.exception("Error while deciding cost for machine %s", machine)

    machine.cost.hourly = cph
    machine.cost.monthly = cpm


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
        self.list_machines()

    def list_cached_machines(self, timedelta=datetime.timedelta(days=1)):
        """Return list of machines from database

        Only returns machines that existed last time we check and we've seen
        during the last `timedelta`.

        """
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
        try:
            with task.task_runner(persist=persist):
                old_machines = {'%s-%s' % (m.id, m.machine_id): m.as_dict()
                                for m in self.list_cached_machines()}
                machines = self._list_machines()
        except PeriodicTaskThresholdExceeded:
            self.cloud.disable()
            raise

        # Initialize AMQP connection to reuse for multiple messages.
        amqp_conn = Connection(config.AMQP_URI)

        if amqp_owner_listening(self.cloud.owner.id):
            if not config.MACHINE_PATCHES:
                amqp_publish_user(self.cloud.owner.id,
                                  routing_key='list_machines',
                                  connection=amqp_conn,
                                  data={'cloud_id': self.cloud.id,
                                        'machines': [machine.as_dict()
                                                     for machine in machines]})
            else:
                # Publish patches to rabbitmq.
                new_machines = {'%s-%s' % (m.id, m.machine_id): m.as_dict()
                                for m in machines}
                # Exclude last seen and probe fields from patch.
                for md in old_machines, new_machines:
                    for m in md.values():
                        m.pop('last_seen')
                        m.pop('probe')
                patch = jsonpatch.JsonPatch.from_diff(old_machines,
                                                      new_machines).patch
                if patch:
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_machines',
                                      connection=amqp_conn,
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})

        # Push historic information for inventory and cost reporting.
        for machine in machines:
            data = {'owner_id': self.cloud.owner.id,
                    'machine_id': machine.id,
                    'cost_per_month': machine.cost.monthly}
            amqp_publish(exchange='machines_inventory', routing_key='',
                         auto_delete=False, data=data, connection=amqp_conn)

        return machines

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
            # import ipdb; ipdb.set_trace()
            nodes = self._list_machines__fetch_machines()
            log.info("List nodes returned %d results for %s.",
                     len(nodes), self.cloud)
        except InvalidCredsError as exc:
            log.warning("Invalid creds on running list_nodes on %s: %s",
                        self.cloud, exc)
            raise CloudUnauthorizedError(msg=exc.message)
        except (requests.exceptions.SSLError, ssl.SSLError) as exc:
            log.error("SSLError on running list_nodes on %s: %s",
                      self.cloud, exc)
            raise SSLError(exc=exc)
        except Exception as exc:
            log.exception("Error while running list_nodes on %s", self.cloud)
            raise CloudUnavailableError(exc=exc)

        machines = []
        now = datetime.datetime.utcnow()

        # Process each machine in returned list.
        # Store previously unseen machines separately.
        new_machines = []
        for node in nodes:

            # Fetch machine mongoengine model from db, or initialize one.
            try:
                machine = Machine.objects.get(cloud=self.cloud,
                                              machine_id=node.id)
            except Machine.DoesNotExist:
                machine = Machine(cloud=self.cloud, machine_id=node.id).save()
                new_machines.append(machine)

            # Update machine_model's last_seen fields.
            machine.last_seen = now
            machine.missing_since = None
            # Discover location of machine.
            try:
                loc_id = self._list_machines__get_location(node)
            except Exception as exc:
                log.exception(repr(exc))

            else:
                try:
                    _location = CloudLocation.objects.get(cloud=self.cloud,
                                                          external_id=loc_id)
                    machine.location = _location
                except CloudLocation.DoesNotExist:
                    try:
                        _location = CloudLocation.objects.get(
                            cloud=self.cloud,
                            name=loc_id)
                        machine.location = _location
                    except CloudLocation.DoesNotExist:
                        log.error("Couldn't find Location with id %s "
                                  "for cloud %s", loc_id, self.cloud)

            try:
                location_name = self._list_machines__get_location(node)
            except Exception as exc:
                log.exception(repr(exc))

            if location_name:

                try:
                    _location = CloudLocation.objects.get(cloud=self.cloud,
                                                          name=location_name)
                    machine.location = _location
                except CloudLocation.DoesNotExist:
                    pass

            # Get misc libcloud metadata.
            image_id = str(node.image or node.extra.get('imageId') or
                           node.extra.get('image_id') or
                           node.extra.get('image') or '')
            # import ipdb; ipdb.set_trace()
            try:
                size = self._list_machines__get_size(node)
            except Exception as exc:
                log.exception(repr(exc))

            machine.name = node.name
            machine.image_id = image_id
            # for now!
            # machine.size = size
            machine.state = config.STATES[node.state]
            machine.private_ips = list(set(node.private_ips))
            machine.public_ips = list(set(node.public_ips))

            # Set machine extra dict.
            # Make sure we don't meet any surprises when we try to json encode
            # later on in the HTTP response.
            extra = self._list_machines__get_machine_extra(machine, node)

            for key, val in extra.items():
                try:
                    json.dumps(val)
                except TypeError:
                    extra[key] = str(val)
            machine.extra = extra

            # save extra.tags as dict
            if machine.extra.get('tags') and isinstance(
                    machine.extra.get('tags'), list):
                machine.extra['tags'] = dict.fromkeys(machine.extra['tags'],
                                                      '')
            # perform tag validation to prevent ValidationError
            # on machine.save()
            if machine.extra.get('tags') and isinstance(
                    machine.extra.get('tags'), dict):
                validated_tags = {}
                for tag in machine.extra['tags']:
                    if not (('.' in tag) or ('$' in tag)):
                        validated_tags[tag] = machine.extra['tags'][tag]
                machine.extra['tags'] = validated_tags

            # Set machine hostname
            if machine.extra.get('dns_name'):
                machine.hostname = machine.extra['dns_name']
            else:
                ips = machine.public_ips + machine.private_ips
                if not ips:
                    ips = []
                for ip in ips:
                    if ip and ':' not in ip:
                        machine.hostname = ip
                        break

            # Get machine creation date.
            try:
                created = self._list_machines__machine_creation_date(machine,
                                                                     node)
                if created:
                    machine.created = get_datetime(created)
            except Exception as exc:
                log.exception("Error finding creation date for %s in %s.",
                              self.cloud, machine)
            # TODO: Consider if we should fall back to using current date.
            # if not machine_model.created:
            #     machine_model.created = datetime.datetime.utcnow()

            # Update with available machine actions.
            try:
                self._list_machines__machine_actions(machine, node)
            except Exception as exc:
                log.exception("Error while finding machine actions "
                              "for machine %s:%s for %s",
                              machine.id, node.name, self.cloud)

            # Apply any cloud/provider specific post processing.
            try:
                self._list_machines__postparse_machine(machine, node)
            except Exception as exc:
                log.exception("Error while post parsing machine %s:%s for %s",
                              machine.id, node.name, self.cloud)

            # Apply any cloud/provider cost reporting.
            try:
                _decide_machine_cost(
                    machine,
                    cost=self._list_machines__cost_machine(machine, node),
                )
            except Exception as exc:
                log.exception("Error while calculating cost "
                              "for machine %s:%s for %s",
                              machine.id, node.name, self.cloud)
            if node.state.lower() == 'terminated':
                machine.cost.hourly = 0
                machine.cost.monthly = 0

            # Save all changes to machine model on the database.
            try:
                machine.save()
            except me.ValidationError as exc:
                log.error("Error adding %s: %s", machine.name, exc.to_dict())
                raise BadRequestError({"msg": exc.message,
                                       "errors": exc.to_dict()})
            except me.NotUniqueError as exc:
                log.error("Machine %s not unique error: %s", machine.name, exc)
                raise ConflictError("Machine with this name already exists")

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
            _decide_machine_cost(machine)

            # Save machine
            machine.save()
            machines.append(machine)

        # Set last_seen on machine models we didn't see for the first time now.
        Machine.objects(cloud=self.cloud,
                        id__nin=[m.id for m in machines],
                        missing_since=None).update(missing_since=now)

        # Update RBAC Mappings given the list of nodes seen for the first time.
        self.cloud.owner.mapper.update(new_machines, async=False)

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
        if machine.key_associations:
            machine.actions.reboot = True
        machine.actions.tag = True

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
        return

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

        This method is expected to edit its arguments in place and not return
        anything.

        Subclasses MAY override this method.

        """
        return

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
        for i in reversed(xrange(len(images))):
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

            `self._list_sizes__fetch_sizes`

        Subclasses that require special handling should override these, by
        default, dummy methods.

        """
        task_key = 'cloud:list_sizes:%s' % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        # import ipdb; ipdb.set_trace()
        try:
            with task.task_runner(persist=persist):
                cached_sizes = {'%s' % s.id: s.as_dict()
                                for s in self.list_cached_sizes()}
                sizes = [s.as_dict() for s in self._list_sizes__fetch_sizes()]
        except PeriodicTaskThresholdExceeded:
            self.cloud.disable()
            raise

        # Initialize AMQP connection to reuse for multiple messages.
        amqp_conn = Connection(config.AMQP_URI)
        if amqp_owner_listening(self.cloud.owner.id):

            if cached_sizes and sizes:
                # Publish patches to rabbitmq.
                new_sizes = {'%s' % s['id']: s for s in sizes}
                patch = jsonpatch.JsonPatch.from_diff(cached_sizes,
                                                      new_sizes).patch
                if patch:
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_sizes',
                                      connection=amqp_conn,
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})

            else:
                amqp_publish_user(self.cloud.owner.id,
                                  routing_key='list_sizes',
                                  connection=amqp_conn,
                                  data={'cloud_id': self.cloud.id,
                                        'sizes': sizes})

                # Format size information.
        # return [size.as_dict() for size in sizes]
        return sizes

    def _list_sizes__fetch_sizes(self):
        """Fetch size listing in a libcloud compatible format

        This is to be called exclusively by `self.list_sizes`.

        Subclasses MAY override this method.

        """
        fetched_sizes = self.connection.list_sizes()

        log.info("List sizes returned %d results for %s.",
                 len(fetched_sizes), self.cloud)
        sizes = []
        # import ipdb; ipdb.set_trace()

        for size in fetched_sizes:

            # create the object in db if it does not exist
            try:
                _size = CloudSize.objects.get(cloud=self.cloud,
                                              external_id=size.id)
            except CloudSize.DoesNotExist:
                _size = CloudSize(cloud=self.cloud,
                                  name=size.name, disk=size.disk,
                                  ram=size.ram, external_id=size.id,
                                  bandwidth=size.bandwidth
                                  )
            try:
                cpus = self._list_sizes_get_cpu(size)
            except Exception as exc:
                log.exception(repr(exc))

            if isinstance(size.price, float):
                _size.price = size.price
            _size.cpus = cpus
            _size.provider = self.provider
            _size.description = self._list_sizes_set_description(size,
                                                                 cpus)
            try:
                _size.save()
                sizes.append(_size)
            except me.ValidationError as exc:
                log.error("Error adding %s: %s", size.name, exc.to_dict())
                raise BadRequestError({"msg": exc.message,
                                       "errors": exc.to_dict()})

        return sizes

    def _list_sizes_get_cpu(self, size):
        return size.extra.get('cpus')

    def _list_sizes_set_description(self, size, cpu):
        """Sets description for size, as it will be
        shown to the end user
        """
        return size.name

    def list_cached_sizes(self):
        """Return list of sizes from database
        for a specific cloud
        """
        return CloudSize.objects(cloud=self.cloud)

    def _list_machines__get_size(self, node):
        """Return size from database for a
        specific node

        Subclasses MAY override this method.
        """
        try:
            size = CloudSize.objects.get(cloud=self.cloud,
                                         name=node.size)
        except CloudSize.DoesNotExist:
            size = ''
        return size

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
        try:
            with task.task_runner(persist=persist):
                cached_locations = {'%s' % l.id: l.as_dict()
                                    for l in self.list_cached_locations()}

                locations = [l.as_dict() for l in self._list_locations()]
        except PeriodicTaskThresholdExceeded:
            self.cloud.disable()
            raise

        # Initialize AMQP connection to reuse for multiple messages.
        amqp_conn = Connection(config.AMQP_URI)
        if amqp_owner_listening(self.cloud.owner.id):
            if cached_locations and locations:
                # Publish patches to rabbitmq.
                new_locations = {'%s' % l['id']: l for l in locations}
                patch = jsonpatch.JsonPatch.from_diff(cached_locations,
                                                      new_locations).patch
                if patch:
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_locations',
                                      connection=amqp_conn,
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})
            else:
                amqp_publish_user(self.cloud.owner.id,
                                  routing_key='list_locations',
                                  connection=amqp_conn,
                                  data={'cloud_id': self.cloud.id,
                                        'locations': locations})
        return locations

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
        try:
            with task.task_runner(persist=persist):
                cached_locations = {'%s' % l.id: l.as_dict()
                                    for l in self.list_cached_locations()}

                locations = self._list_locations()
        except PeriodicTaskThresholdExceeded:
            raise

        # Initialize AMQP connection to reuse for multiple messages.
        amqp_conn = Connection(config.AMQP_URI)
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
                                      connection=amqp_conn,
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})
            else:
                # TODO: remove this block, once location patches
                # are implemented in the UI
                amqp_publish_user(self.cloud.owner.id,
                                  routing_key='list_locations',
                                  connection=amqp_conn,
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

            try:
                _location.save()
            except me.ValidationError as exc:
                log.error("Error adding %s: %s", loc.name, exc.to_dict())
                raise BadRequestError({"msg": exc.message,
                                       "errors": exc.to_dict()})
            locations.append(_location)

        return locations

    def list_cached_locations(self):
        """Return list of locations from database
        for a specific cloud
        """
        return CloudLocation.objects(cloud=self.cloud,
                                     missing_since=None)

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
            self._start_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not start machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

    def _start_machine(self, machine, machine_libcloud):
        """Private method to start a given machine

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `start_machine`.
        """
        self.connection.ex_start_node(machine_libcloud)

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
            self._stop_machine(machine, machine_libcloud)
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
        self.connection.ex_stop_node(machine_libcloud)
        return True

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
            self._reboot_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not reboot machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

    def _reboot_machine(self, machine, machine_libcloud):
        """Private method to reboot a given machine

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `reboot_machine`.
        """
        machine_libcloud.reboot()

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
            ssh_command(self.cloud.owner, self.cloud.id,
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
            self._destroy_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not destroy machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

        while machine.key_associations:
            machine.key_associations.pop()
        machine.state = 'terminated'
        machine.save()

    def _destroy_machine(self, machine, machine_libcloud):
        """Private method to destroy a given machine

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `destroy_machine`.
        """
        try:
            machine_libcloud.destroy()
        except BaseHTTPError:
            raise ForbiddenError("Cannot destroy machine. Check the "
                                 "termination protection setting on your "
                                 "cloud provider.")

    def remove_machine(self, machine):
        raise BadRequestError("Machines on public clouds can't be removed."
                              "This is only supported in Bare Metal clouds.")

    def resize_machine(self, machine, plan_id, kwargs):
        """Resize machine

        The param `machine` must be an instance of a machine model of this
        cloud.

        Not that the usual way to resize a machine would be to run

            machine.ctl.resize(plan_id)

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
            self._resize_machine(machine, machine_libcloud, plan_id, kwargs)
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

    def _resize_machine(self, machine, machine_libcloud, plan_id, kwargs):
        """Private method to resize a given machine

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `resize_machine`.
        """
        self.connection.ex_resize_node(machine_libcloud, plan_id)

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
            raise InternalServerError(exc=exc)

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
        raise NotImplementedError()

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
            self._suspend_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not suspend machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

    def _suspend_machine(self, machine, machine_libcloud):
        """Private method to suspend a given machine

        Only LibvirtComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `suspend_machine`.
        """
        raise NotImplementedError()

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
            self._undefine_machine(machine, machine_libcloud)
        except MistError as exc:
            log.error("Could not undefine machine %s", machine)
            raise
        except Exception as exc:
            log.exception(exc)
            raise InternalServerError(exc=exc)

    def _undefine_machine(self, machine, machine_libcloud):
        """Private method to undefine a given machine

        Only LibvirtComputeController subclass implements this method.

        Params:
            machine: instance of machine model of this cloud
            machine_libcloud: instance of corresponding libcloud node

        Differnent cloud controllers should override this private method, which
        is called by the public method `undefine_machine`.
        """
        raise NotImplementedError()
