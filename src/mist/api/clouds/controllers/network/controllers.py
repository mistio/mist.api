"""Definition of cloud-specific network subcontroller classes.

This file should only contain subclasses of `BaseNetworkController`.

"""

import logging

from mist.api.helpers import rename_kwargs

from mist.api.exceptions import SubnetNotFoundError
from mist.api.exceptions import NetworkNotFoundError
from mist.api.exceptions import MistNotImplementedError
from mist.api.exceptions import MachineNotFoundError
from mist.api.exceptions import PortForwardCreationError

from mist.api.clouds.controllers.network.base import BaseNetworkController

from libcloud.compute.drivers.azure_arm import AzureNetwork
from libcloud.common.exceptions import BaseHTTPError


log = logging.getLogger(__name__)


class AzureArmNetworkController(BaseNetworkController):

    def _list_networks__cidr_range(self, network, libcloud_network):
        return libcloud_network.extra['addressSpace']['addressPrefixes'][0]

    def _list_networks__postparse_network(self, network, libcloud_network,
                                          r_groups=[]):
        from mist.api.clouds.models import CloudLocation
        location = None
        loc_id = libcloud_network.location
        try:
            location = CloudLocation.objects.get(external_id=loc_id,
                                                 cloud=self.cloud)
        except CloudLocation.DoesNotExist:
            pass
        network.location = location

        subnet_id = libcloud_network.extra.get('subnets')[0].get('id')
        r_group_name = subnet_id.split('resourceGroups/')[1].split('/')[0]
        r_group_id = ''
        for r_group in r_groups:
            if r_group.name == r_group_name:
                r_group_id = r_group.id
                break
        network.resource_group = r_group_id

    def _list_subnets__fetch_subnets(self, network):
        l_network = AzureNetwork(network.network_id,
                                 network.name, '', network.extra)
        return self.cloud.ctl.compute.connection.ex_list_subnets(l_network)

    def _list_subnets__cidr_range(self, subnet, libcloud_subnet):
        return subnet.extra.pop('addressPrefix')

    def _get_libcloud_subnet(self, subnet):
        networks = self.cloud.ctl.compute.connection.ex_list_networks()
        network = None
        for net in networks:
            if net.id == subnet.network.network_id:
                network = net
                break
        subnets = self.cloud.ctl.compute.connection.ex_list_subnets(network)
        for sub in subnets:
            if sub.id == subnet.subnet_id:
                return sub
        raise SubnetNotFoundError('Subnet %s with subnet_id \
            %s' % (subnet.name, subnet.subnet_id))

    def _delete_network(self, network, libcloud_network):
        raise MistNotImplementedError()

    def _delete_subnet(self, subnet, libcloud_subnet):
        raise MistNotImplementedError()


class AmazonNetworkController(BaseNetworkController):

    def _create_network__prepare_args(self, kwargs):
        rename_kwargs(kwargs, 'cidr', 'cidr_block')

    def _create_subnet__prepare_args(self, subnet, kwargs):
        kwargs['vpc_id'] = subnet.network.network_id
        rename_kwargs(kwargs, 'cidr', 'cidr_block')

    def _list_networks__cidr_range(self, network, libcloud_network):
        return libcloud_network.cidr_block

    def _list_networks__postparse_network(self, network, libcloud_network,
                                          r_groups=[]):
        tenancy = libcloud_network.extra.pop('instance_tenancy')
        network.instance_tenancy = tenancy

    def _list_subnets__fetch_subnets(self, network):
        kwargs = {'filters': {'vpc-id': network.network_id}}
        return self.cloud.ctl.compute.connection.ex_list_subnets(**kwargs)

    def _list_subnets__cidr_range(self, subnet, libcloud_subnet):
        return subnet.extra.pop('cidr_block')

    def _list_subnets__postparse_subnet(self, subnet, libcloud_subnet):
        subnet.availability_zone = libcloud_subnet.extra.pop('zone')

    def _delete_network(self, network, libcloud_network):
        self.cloud.ctl.compute.connection.ex_delete_network(libcloud_network)

    def _delete_subnet(self, subnet, libcloud_subnet):
        self.cloud.ctl.compute.connection.ex_delete_subnet(libcloud_subnet)

    def _get_libcloud_network(self, network):
        kwargs = {'network_ids': [network.network_id]}
        networks = self.cloud.ctl.compute.connection.ex_list_networks(**kwargs)
        if networks:
            return networks[0]
        raise NetworkNotFoundError('Network %s with network_id %s' %
                                   (network.name, network.network_id))

    def _get_libcloud_subnet(self, subnet):
        kwargs = {'subnet_ids': [subnet.subnet_id]}
        subnets = self.cloud.ctl.compute.connection.ex_list_subnets(**kwargs)
        if subnets:
            return subnets[0]
        raise SubnetNotFoundError('Subnet %s with subnet_id %s' %
                                  (subnet.name, subnet.subnet_id))


class GoogleNetworkController(BaseNetworkController):

    def _create_subnet__prepare_args(self, subnet, kwargs):
        kwargs['network'] = subnet.network.name

    def _create_subnet(self, kwargs):
        return self.cloud.ctl.compute.connection.ex_create_subnetwork(**kwargs)

    def _list_networks__cidr_range(self, network, libcloud_network):
        return libcloud_network.cidr

    def _list_networks__postparse_network(self, network, libcloud_network,
                                          r_groups=[]):
        network.mode = libcloud_network.mode

    def _list_subnets__fetch_subnets(self, network):
        filter_expression = 'network eq %s' % network.extra['selfLink']
        return self.cloud.ctl.compute.connection.ex_list_subnetworks(
            filter_expression=filter_expression)

    def _list_subnets__postparse_subnet(self, subnet, libcloud_subnet):
        # Replace `GCERegion` object with the region's name.
        if hasattr(libcloud_subnet, 'region'):
            region = libcloud_subnet.region.name
        else:
            try:
                region = subnet.extra['region']
                region = region.split('regions/')[-1]
            except (KeyError, IndexError):
                region = ''
                log.error('Failed to extract region name for %s', subnet)
        if region:
            subnet.region = region

    def _get_libcloud_network(self, network):
        return self.cloud.ctl.compute.connection.ex_get_network(network.name)

    def _get_libcloud_subnet(self, subnet):
        kwargs = {'name': subnet.name,
                  'region': subnet.region}
        return self.cloud.ctl.compute.connection.ex_get_subnetwork(**kwargs)


class OpenStackNetworkController(BaseNetworkController):

    def _create_subnet__prepare_args(self, subnet, kwargs):
        kwargs['network_id'] = subnet.network.network_id

    def _list_networks__postparse_network(self, network, libcloud_network,
                                          r_groups=[]):
        for field in network._network_specific_fields:
            if hasattr(libcloud_network, field):
                value = getattr(libcloud_network, field)
            else:
                try:
                    value = network.extra.pop(field)
                except KeyError:
                    log.error('Failed to get value for "%s" for network '
                              '"%s" (%s)', field, network.name, network.id)
                    continue
            setattr(network, field, value)

    def _list_subnets__fetch_subnets(self, network):
        kwargs = {'filters': {'network_id': network.network_id}}
        return self.cloud.ctl.compute.connection.ex_list_subnets(**kwargs)

    def _list_subnets__postparse_subnet(self, subnet, libcloud_subnet):
        for field in subnet._subnet_specific_fields:
            if hasattr(libcloud_subnet, field):
                value = getattr(libcloud_subnet, field)
            else:
                log.error('Failed to get value for "%s" for subnet'
                          ' "%s" (%s)', field, subnet.name, subnet.id)
                continue
            setattr(subnet, field, value)

    def _delete_network(self, network, libcloud_network):
        network_id = libcloud_network.id
        self.cloud.ctl.compute.connection.ex_delete_network(network_id)

    def _delete_subnet(self, subnet, libcloud_subnet):
        self.cloud.ctl.compute.connection.ex_delete_subnet(libcloud_subnet.id)


class LibvirtNetworkController(BaseNetworkController):

    def _list_networks__fetch_networks(self):
        networks = super(LibvirtNetworkController,
                         self)._list_networks__fetch_networks()
        networks.extend(self.cloud.ctl.compute.connection.ex_list_interfaces())
        return networks

    def _list_subnets__fetch_subnets(self, network):
        return []

    def _delete_network(self, network, libcloud_network):
        raise MistNotImplementedError()

    def _delete_subnet(self, subnet, libcloud_subnet):
        raise MistNotImplementedError()


class VSphereNetworkController(BaseNetworkController):

    def _list_subnets__fetch_subnets(self, network):
        return []


class LXDNetworkController(BaseNetworkController):
    """
    Network controller for LXD
    """

    def _create_network__prepare_args(self, kwargs):

        if "description" not in kwargs:
            kwargs["description"] = "No network description"

        # do not expect that kwargs
        # have the configuration wrapped
        # this is the default config
        kwargs["config"] = {"ipv4.address": "none",
                            "ipv6.address": "none",
                            "ipv6.nat": "false"}

        if "cidr" in kwargs:
            kwargs["config"]["ipv4.address"] = kwargs["cidr"]

        if "ipv6.address" in kwargs:
            kwargs["config"]["ipv6.address"] = kwargs["ipv6.address"]

        if "ipv6.nat" in kwargs:
            kwargs["config"]["ipv6.nat"] = kwargs["ipv6.nat"]

    def _delete_network(self, network, libcloud_network):
        conn = self.cloud.ctl.compute.connection
        conn.ex_delete_network(name=libcloud_network.name)

    def _list_subnets__fetch_subnets(self, network):
        return []

    def _list_networks__cidr_range(self, network, net):
        return net.config["ipv4.address"]


class GigG8NetworkController(BaseNetworkController):

    def _list_networks__postparse_network(self, network, libcloud_network,
                                          r_groups=[]):
        network.public_ip = libcloud_network.publicipaddress

    def _list_subnets__fetch_subnets(self, network):
        return []

    def _list_portforwards(self, network):
        connection = network.cloud.ctl.compute.connection
        g8_network = None

        for _network in connection.ex_list_networks():
            if network.network_id == _network.id:
                g8_network = _network
                break

        return connection.ex_list_portforwards(g8_network)

    def _create_portforward(self, network, **kwargs):
        connection = network.cloud.ctl.compute.connection
        g8_network = None
        for _network in connection.ex_list_networks():
            if network.network_id == _network.id:
                g8_network = _network
                break

        from mist.api.machines.models import Machine
        try:
            machine = Machine.objects.get(cloud=self.cloud,
                                          id=kwargs.get('machine_id'))
        except Machine.DoesNotExist:
            raise MachineNotFoundError()

        libcloud_node = None
        for node in connection.list_nodes():
            if node.id == machine.machine_id:
                libcloud_node = node
                break

        try:
            pf = connection.ex_create_portforward(g8_network, libcloud_node,
                                                  kwargs.get('public_port'),
                                                  kwargs.get('private_port'),
                                                  kwargs.get('protocol', 'tcp'))
        except BaseHTTPError as exc:
            raise PortForwardCreationError(exc.message)

        return pf
