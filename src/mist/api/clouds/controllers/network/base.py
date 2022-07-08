"""Definition of base network subcontroller classes.

This currently contains only BaseNetworkController.

It contains all functionality concerning the management of networks and related
objects that is common among all cloud providers. Cloud specific subcontrollers
are in `mist.api.clouds.controllers.network.controllers`.

"""

import asyncio
import json
import copy
import logging
import time
import datetime
import mongoengine.errors

import jsonpatch
from requests import ConnectionError

import mist.api.exceptions

from mist.api.clouds.utils import LibcloudExceptionHandler
from mist.api.clouds.controllers.base import BaseController

from mist.api.concurrency.models import PeriodicTaskInfo

from mist.api.helpers import get_datetime
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening

log = logging.getLogger(__name__)


class BaseNetworkController(BaseController):
    """Abstract base class for networking-specific subcontrollers.

    This base controller factors out all the steps common to all or most
    clouds into a base class, and defines an interface for provider
    or technology specific cloud controllers.

    Subclasses are meant to extend or override methods of this base class to
    account for differences between different cloud types.

    Care should be taken when considering to add new methods to a subclass.
    All controllers should have the same interface, to the degree this is
    feasible. That is to say, don't add a new method to a subclass unless
    there is a very good reason to do so.

    The following convention is followed:

    Any methods and attributes that don't start with an underscore are the
    controller's public API.

    In the `BaseNetworkController`, these public methods will contain all steps
    for network object management which are common to all cloud types.In almost
    all cases, subclasses SHOULD NOT override or extend the public methods of
    `BaseNetworkController`. To account for cloud/subclass specific behaviour,
    one is expected to override the internal/private methods of the
    `BaseNetworkController`.

    Any methods and attributes that start with an underscore are the
    controller's internal/private API.

    To account for cloud/subclass specific behaviour, the public methods of
    `BaseNetworkController` call a number of private methods. These methods
    will always start with an underscore. When an internal method is only ever
    used in the process of one public method, it is prefixed as such to make
    identification and purpose more obvious.

    For example, method `self._create_network__parse_args` is called in the
    process of `self.create_network` to parse the arguments given into the
    format required by libcloud.

    For each different cloud type, a subclass needs to be defined. To provide
    cloud specific processing, hook the code on the appropriate private method.
    Each method defined here documents its intended purpose and use.
    """

    @LibcloudExceptionHandler(mist.api.exceptions.NetworkCreationError)
    def create_network(self, network, **kwargs):
        """Create a new Network.

        This method receives a Network mongoengine object, parses the arguments
        provided and populates all cloud-specific fields, performs early field
        validation using the constraints specified in the corresponding Network
        subclass, performs the necessary libcloud call, and, finally, saves the
        Network objects to the database.

        Subclasses SHOULD NOT override or extend this method.

        Instead, there is a private method that is called from this method, to
        allow subclasses to modify the data according to the specific of their
        cloud type. This method currently is:

            `self._create_network__prepare_args`

        Subclasses that require special handling should override this, by
        default, dummy method. More private methods may be added in the future.

        :param network: A Network mongoengine model. The model may not have yet
                        been saved in the database.
        :param kwargs:  A dict of parameters required for network creation.
        """
        for key, value in kwargs.items():
            if key not in network._network_specific_fields:
                raise mist.api.exceptions.BadRequestError(key)
            setattr(network, key, value)

        # Perform early validation.
        try:
            network.validate(clean=True)
        except mongoengine.errors.ValidationError as err:
            raise mist.api.exceptions.BadRequestError(err)

        if network.cidr:
            kwargs['cidr'] = network.cidr
        if network.location:
            kwargs['location'] = network.location
        kwargs['name'] = network.name or ''

        # Cloud-specific kwargs pre-processing.
        self._create_network__prepare_args(kwargs)

        # Create the network.
        libcloud_net = self.cloud.ctl.compute.connection.ex_create_network(
            **kwargs)

        # Invoke `self.list_networks` to update the UI and return the Network
        # object at the API. Try 3 times before failing
        for _ in range(5):
            for net in self.list_networks():
                if net.external_id == libcloud_net.id:
                    return net
            time.sleep(1)
        raise mist.api.exceptions.NetworkListingError()

    def _create_network__prepare_args(self, kwargs):
        """Parses keyword arguments on behalf of `self.create_network`.

        Creates the parameter structure required by the libcloud method
        that handles network creation.

        Subclasses MAY override this method.
        """
        return

    @LibcloudExceptionHandler(mist.api.exceptions.SubnetCreationError)
    def create_subnet(self, subnet, **kwargs):
        """Create a new Subnet.

        This method receives a Subnet mongoengine object, parses the arguments
        provided and populates all cloud-specific fields, performs early field
        validation using the constraints specified in the corresponding Subnet
        subclass, performs the necessary libcloud call, and, finally, saves the
        Subnet objects to the database.

        Subclasses SHOULD NOT override or extend this method.

        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specific of
        their cloud type. These methods currently are:

            `self._create_subnet`
            `self._create_subnet__prepare_args`

        Subclasses that require special handling should override these, by
        default, dummy methods.

        :param subnet: A Subnet mongoengine model. The model may not have yet
                       been saved in the database.
        :param kwargs: A dict of parameters required for subnet creation.
        """
        for key, value in kwargs.items():
            if key not in subnet._subnet_specific_fields:
                raise mist.api.exceptions.BadRequestError(key)
            setattr(subnet, key, value)

        # Perform early validation.
        try:
            subnet.validate(clean=True)
        except mongoengine.errors.ValidationError as err:
            raise mist.api.exceptions.BadRequestError(err)

        kwargs['cidr'] = subnet.cidr
        kwargs['name'] = subnet.name or ''

        # Cloud-specific kwargs processing.
        self._create_subnet__prepare_args(subnet, kwargs)

        # Increase network polling frequency
        from mist.api.poller.models import ListNetworksPollingSchedule
        ListNetworksPollingSchedule.add(cloud=self.cloud, interval=10, ttl=120)

        # Create the subnet.
        libcloud_subnet = self._create_subnet(kwargs)

        # Invoke `self.list_networks` to update the UI and return the Network
        # object at the API. Try 3 times before failing
        from mist.api.networks.models import Subnet
        for _ in range(3):
            for n in self.list_networks():
                if n.external_id == subnet.network.external_id:
                    for s in Subnet.objects(network=n, missing_since=None):
                        if s.external_id == libcloud_subnet.id:
                            return s
            time.sleep(1)
        raise mist.api.exceptions.SubnetListingError()

    def _create_subnet(self, kwargs):
        """Performs the libcloud call that handles subnet creation.

        This method is meant to be called internally by `self.create_subnet`.

        Unless naming conventions change or specialized parsing of the libcloud
        response is needed, subclasses SHOULD NOT need to override this method.

        Subclasses MAY override this method.
        """
        return self.cloud.ctl.compute.connection.ex_create_subnet(**kwargs)

    def _create_subnet__prepare_args(self, subnet, kwargs):
        """Parses keyword arguments on behalf of `self.create_subnet`.

        Creates the parameter structure required by the libcloud method
        that handles network creation.

        Subclasses MAY override this method.
        """
        return

    def list_networks(self, persist=True):
        """Return list of networks for cloud

        A list of networks is fetched from libcloud, data is processed, stored
        on network models, and a list of network models is returned.

        Subclasses SHOULD NOT override or extend this method.

        This method wraps `_list_networks` which contains the core
        implementation.

        """
        task_key = 'cloud:list_networks:%s' % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        first_run = False if task.last_success else True

        async def _list_subnets_async(networks):
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                asyncio.set_event_loop(asyncio.new_event_loop())
                loop = asyncio.get_event_loop()
            subnets = [
                loop.run_in_executor(None, network.ctl.list_subnets)
                for network in networks
            ]
            return await asyncio.gather(*subnets)

        with task.task_runner(persist=persist):
            # Get cached networks as dict
            cached_networks = {'%s-%s' % (n.id, n.external_id): n.as_dict()
                               for n in self.list_cached_networks()}
            networks = self._list_networks()
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    raise RuntimeError('loop is closed')
            except RuntimeError:
                asyncio.set_event_loop(asyncio.new_event_loop())
                loop = asyncio.get_event_loop()
            loop.run_until_complete(_list_subnets_async(networks))

        # Publish patches to rabbitmq.
        new_networks = {'%s-%s' % (n.id, n.external_id): n.as_dict()
                        for n in networks}
        # Exclude last seen and probe field
        if cached_networks or new_networks:
            # Publish patches to rabbitmq.
            patch = jsonpatch.JsonPatch.from_diff(cached_networks,
                                                  new_networks).patch
            if patch:
                if not first_run and self.cloud.observation_logs_enabled:
                    from mist.api.logs.methods import log_observations
                    log_observations(self.cloud.owner.id, self.cloud.id,
                                     'network', patch, cached_networks,
                                     new_networks)
                if amqp_owner_listening(self.cloud.owner.id):
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_networks',
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})
        return networks

    @LibcloudExceptionHandler(mist.api.exceptions.NetworkListingError)
    def _list_networks(self):
        """Lists all Networks present on the Cloud.

        Fetches all Networks via libcloud, applies cloud-specific processing,
        and syncs the state of the database with the state of the Cloud.

        Subclasses SHOULD NOT override or extend this method.

        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specific of
        their cloud type. These methods currently are:

            `self._list_networks__cidr_range`
            `self._list_networks__postparse_network`

        More private methods may be added in the future. Subclasses that
        require special handling should override this, by default, dummy
        method.
        """
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.networks.models import Network, NETWORKS

        try:
            libcloud_nets = self._list_networks__fetch_networks()
        except ConnectionError as e:
            raise mist.api.exceptions.CloudUnavailableError(e)

        # in case of ARM, we need to attach the network to a resource group
        if self.cloud.ctl.provider in ['azure_arm']:
            connection = self.cloud.ctl.compute.connection
            r_groups = connection.ex_list_resource_groups()
        else:
            r_groups = []
        # List of Network mongoengine objects to be returned to the API.
        networks, new_networks = [], []
        for net in libcloud_nets:
            try:
                network = Network.objects.get(cloud=self.cloud,
                                              external_id=net.id)
            except Network.DoesNotExist:
                network = NETWORKS[self.provider](cloud=self.cloud,
                                                  external_id=net.id)
                network.first_seen = datetime.datetime.utcnow()
                new_networks.append(network)

            network.name = net.name
            network.extra = copy.copy(net.extra)
            network.missing_since = None
            try:
                created = self._list_networks__network_creation_date(net)
                if created:
                    created = get_datetime(created)
                    if network.created != created:
                        network.created = created
            except Exception as exc:
                log.exception("Error finding creation date for %s in %s.\n%r",
                              self.cloud, network, exc)
            # Get the Network's CIDR.
            try:
                network.cidr = self._list_networks__cidr_range(network, net)
            except Exception as exc:
                log.exception('Failed to get CIDR of %s: %s', network, exc)

            # Apply cloud-specific processing.
            try:
                self._list_networks__postparse_network(network, net, r_groups)
            except Exception as exc:
                log.exception('Error post-parsing %s: %s', network, exc)

            # Ensure JSON-encoding.
            for key, value in network.extra.items():
                try:
                    json.dumps(value)
                except TypeError:
                    network.extra[key] = str(value)

            try:
                network.save()
            except mongoengine.errors.ValidationError as exc:
                log.error("Error updating %s: %s", network, exc.to_dict())
                raise mist.api.exceptions.BadRequestError(
                    {"msg": str(exc), "errors": exc.to_dict()}
                )
            except mongoengine.errors.NotUniqueError as exc:
                log.error("Network %s is not unique: %s", network.name, exc)
                raise mist.api.exceptions.NetworkExistsError()
            networks.append(network)
        now = datetime.datetime.utcnow()
        # Set missing_since for networks not returned by libcloud.
        Network.objects(
            cloud=self.cloud, id__nin=[n.id for n in networks],
            missing_since=None
        ).update(missing_since=now)
        Network.objects(cloud=self.cloud, id__in=[
                        n.id for n in networks]).update(
            last_seen=now, missing_since=None)

        # Update RBAC Mappings given the list of new networks.
        if new_networks:
            self.cloud.owner.mapper.update(new_networks, asynchronous=False)

        return networks

    def list_cached_networks(self):
        """Returns networks stored in database for a specific cloud"""
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.networks.models import Network
        return Network.objects(cloud=self.cloud, missing_since=None)

    def _list_networks__fetch_networks(self):
        """Return the original list of libcloud Network objects"""
        return self.cloud.ctl.compute.connection.ex_list_networks()

    def _list_networks__cidr_range(self, network, libcloud_network):
        """Returns the network's IP range in CIDR notation.

        This method is meant to be called internally by `self.list_networks`
        in order to return the network's CIDR, if exists.

        Subclasses MAY override this method.

        :param network: A network mongoengine model. The model may not have yet
                        been saved in the database.
        :param libcloud_network: A libcloud network object.
        """
        return

    def _list_networks__postparse_network(self, network, libcloud_network,
                                          r_groups=[]):
        """Parses a libcloud network object on behalf of `self.list_networks`.

        Any subclass that needs to perform custom parsing of a network object
        returned by libcloud SHOULD override this private method.

        This method is expected to edit the network objects in place and not
        return anything.

        Subclasses MAY override this method.

        :param network: A network mongoengine model. The model may not have yet
                        been saved in the database.
        :param libcloud_network: A libcloud network object.
        """
        return

    def _list_networks__network_creation_date(self, libcloud_network):
        return libcloud_network.extra.get('created_at')

    @LibcloudExceptionHandler(mist.api.exceptions.SubnetListingError)
    def list_subnets(self, network, **kwargs):
        """Lists all Subnets attached to a Network present on the Cloud.

        Currently EC2, Openstack and GCE clouds are supported.
        For other providers this returns an empty list.

        Fetches all Subnets via libcloud, applies cloud-specific processing,
        and syncs the state of the database with the state of the Cloud.

        Subclasses SHOULD NOT override or extend this method.

        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specific of
        their cloud type. These methods currently are:

            `self._list_subnets__fetch_subnets`
            `self._list_subnets__cidr_range`
            `self._list_subnets__postparse_subnet`

        More private methods may be added in the future. Subclasses that
        require special handling should override this, by default, dummy
        method.
        """
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.networks.models import Subnet, SUBNETS

        libcloud_subnets = self._list_subnets__fetch_subnets(network)

        # List of Subnet mongoengine objects to be returned to the API.
        subnets = []
        for libcloud_subnet in libcloud_subnets:
            try:
                subnet = Subnet.objects.get(network=network,
                                            external_id=libcloud_subnet.id)
            except Subnet.DoesNotExist:
                subnet = SUBNETS[self.provider](network=network,
                                                external_id=libcloud_subnet.id)
                subnet.first_seen = datetime.datetime.utcnow()

            subnet.name = libcloud_subnet.name
            subnet.extra = copy.copy(libcloud_subnet.extra)
            subnet.missing_since = None
            try:
                created = self._list_subnets__subnet_creation_date(
                    libcloud_subnet)
                if created:
                    created = get_datetime(created)
                    if subnet.created != created:
                        subnet.created = created
            except Exception as exc:
                log.exception("Error finding creation date for %s in %s.\n%r",
                              self.cloud, subnet, exc)
            # Get the Subnet's CIDR.
            try:
                subnet.cidr = self._list_subnets__cidr_range(subnet,
                                                             libcloud_subnet)
            except Exception as exc:
                log.exception('Failed to get the CIDR of %s: %s', subnet, exc)

            # Apply cloud-specific processing.
            try:
                self._list_subnets__postparse_subnet(subnet, libcloud_subnet)
            except Exception as exc:
                log.exception('Error while post-parsing %s: %s', subnet, exc)

            # Ensure JSON-encoding.
            for key, value in subnet.extra.items():
                try:
                    json.dumps(value)
                except TypeError:
                    subnet.extra[key] = str(value)

            try:
                subnet.save()
            except mongoengine.errors.ValidationError as exc:
                log.error("Error updating %s: %s", subnet, exc.to_dict())
                raise mist.api.exceptions.BadRequestError(
                    {"msg": str(exc), "errors": exc.to_dict()}
                )
            except mongoengine.errors.NotUniqueError as exc:
                log.error("Subnet %s not unique error: %s", subnet.name, exc)
                raise mist.api.exceptions.SubnetExistsError()

            subnets.append(subnet)
        now = datetime.datetime.utcnow()
        # Set missing_since for subnets not returned by libcloud.
        Subnet.objects(
            network=network, id__nin=[s.id for s in subnets],
            missing_since=None
        ).update(missing_since=now)
        # Set last_seen, unset missing_since for subnets we just saw
        Subnet.objects(network=network, id__in=[
                       s.id for s in subnets]).update(
            last_seen=now, missing_since=None)
        return subnets

    def list_cached_subnets(self, network):
        """Returns subnets stored in database
        for a specific network
        """
        assert self.cloud == network.cloud
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.networks.models import Subnet
        return Subnet.objects(network=network, missing_since=None)

    def _list_subnets__fetch_subnets(self, network):
        """Fetches a list of subnets.

        Performs the actual libcloud call that returns a subnet listing.

        This method is meant to be called internally by `self.list_subnets`.

        Due to inconsistent naming conventions and cloud-specific filtering,
        this method is not implemented in `BaseNetworkController`.

        Subclasses MUST override this method.
        """
        raise NotImplementedError('The BaseNetworkController CANNOT perform '
                                  'subnet listings due to cloud-specific '
                                  'filtering needs.')

    def _list_subnets__cidr_range(self, subnet, libcloud_subnet):
        """Returns the subnet's IP range in CIDR notation.

        This method is meant to be called internally by `self.list_subnets` in
        order to return the subnet's CIDR.

        Subclasses MAY override this method.

        :param subnet: A subnet mongoengine model. The model may not have yet
                       been saved in the database.
        :param libcloud_subnet: A libcloud subnet object.
        """
        return libcloud_subnet.cidr

    def _list_subnets__postparse_subnet(self, subnet, libcloud_subnet):
        """Parses a libcloud network object on behalf of `self.list_subnets`.

        Any subclass that needs to perform custom parsing of a subnet object
        returned by libcloud SHOULD override this private method.

        This method is expected to edit the subnet objects in place and not
        return anything.

        Subclasses MAY override this method.

        :param subnet: A subnet mongoengine model. The model may not have yet
                       been saved in the database.
        :param libcloud_subnet: A libcloud subnet object.
        """
        return

    def _list_subnets__subnet_creation_date(self, libcloud_subnet):
        return libcloud_subnet.extra.get('created_at')

    def rename_network(self, network, name):
        """Renames a network.

        Subclasses SHOULD NOT override or extend this method.

        If a subclass needs to override the way volumes are renamed, it
        should override the private method `_rename_network` instead.
        """
        assert network.cloud == self.cloud
        libcloud_network = self._get_libcloud_network(network)
        self._rename_network(libcloud_network, name)
        self.list_networks()

    def _rename_network(self, libcloud_network, name):
        pass

    def rename_subnet(self, subnet, name):
        """Renames a subnet.

        Subclasses SHOULD NOT override or extend this method.

        If a subclass needs to override the way volumes are renamed, it
        should override the private method `_rename_subnet` instead.
        """
        assert subnet.network.cloud == self.cloud
        libcloud_subnet = self._get_libcloud_subnet(subnet)
        self._rename_subnet(libcloud_subnet, name)

    def _rename_subnet(self, libcloud_subnet, name):
        pass

    @LibcloudExceptionHandler(mist.api.exceptions.NetworkDeletionError)
    def delete_network(self, network):
        """Deletes a network.

        Subclasses SHOULD NOT override or extend this method.

        If a subclass needs to override the way networks are deleted, it
        should override the private method `_delete_network` instead.
        """
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.networks.models import Subnet

        assert network.cloud == self.cloud

        for subnet in Subnet.objects(network=network, missing_since=None):
            subnet.ctl.delete()
        libcloud_network = self._get_libcloud_network(network)
        try:
            self._delete_network(network, libcloud_network)
        except mist.api.exceptions.MistError as exc:
            log.error("Could not delete network %s", network)
            raise

        self.list_networks()
        from mist.api.poller.models import ListNetworksPollingSchedule
        ListNetworksPollingSchedule.add(cloud=self.cloud, interval=10, ttl=120)

    def _delete_network(self, network, libcloud_network):
        """Performs the libcloud call that handles network deletion.

        This method is meant to be called internally by `self.delete_network`.

        Unless naming conventions change or specialized parsing of the libcloud
        response is needed, subclasses SHOULD NOT need to override this method.

        Subclasses MAY override this method.
        """
        # TODO: Currently, this is supported only by GCE, but it is trivial to
        # implement a similar method for the rest of the providers in order to
        # create a more uniform, high-level interface.
        libcloud_network.destroy()

    @LibcloudExceptionHandler(mist.api.exceptions.SubnetDeletionError)
    def delete_subnet(self, subnet):
        """Deletes a subnet.

        Subclasses SHOULD NOT override or extend this method.

        If a subclass needs to override the way networks are deleted, it
        should override the private method `_delete_network` instead.
        """
        assert subnet.network.cloud == self.cloud

        libcloud_subnet = self._get_libcloud_subnet(subnet)
        try:
            self._delete_subnet(subnet, libcloud_subnet)
        except mist.api.exceptions.MistError as exc:
            log.error("Could not delete subnet %s", subnet)
            raise

        from mist.api.poller.models import ListNetworksPollingSchedule
        ListNetworksPollingSchedule.add(cloud=self.cloud, interval=10, ttl=120)

    def _delete_subnet(self, subnet, libcloud_subnet):
        """Performs the libcloud call that handles subnet deletion.

        This method is meant to be called internally by `self.delete_subnet`.

        Unless naming conventions change or specialized parsing of the libcloud
        response is needed, subclasses SHOULD NOT need to override this method.

        Subclasses MAY override this method.
        """
        libcloud_subnet.destroy()

    def _get_libcloud_network(self, network):
        """Returns an instance of a libcloud network.

        This method receives a Network mongoengine object and queries libcloud
        for the corresponding network instance.

        Subclasses MAY override this method.
        """
        networks = self.cloud.ctl.compute.connection.ex_list_networks()
        for net in networks:
            if net.id == network.external_id:
                return net
        raise mist.api.exceptions.NetworkNotFoundError(
            'Network %s with external_id %s' %
            (network.name, network.external_id))

    def _get_libcloud_subnet(self, subnet):
        """Returns an instance of a libcloud subnet.

        This method receives a Subnet mongoengine object and queries libcloud
        for the corresponding subnet instance.

        Subclasses MAY override this method.
        """
        subnets = self.cloud.ctl.compute.connection.ex_list_subnets()
        for sub in subnets:
            if sub.id == subnet.external_id:
                return sub
        raise mist.api.exceptions.SubnetNotFoundError(
            'Subnet %s with external_id %s' % (subnet.name,
                                               subnet.external_id))

    def list_vnfs(self, host=None):
        """Available only for Libvirt/KVM clouds

        Subclasses MAY override or extend this method.
        """
        return self._list_vnfs(host=host)

    def _list_vnfs(self, host=None):
        """Available only for Libvirt/KVM clouds

        Subclasses MAY override or extend this method.
        """
        return NotImplementedError()
