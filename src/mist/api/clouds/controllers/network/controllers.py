"""Definition of cloud-specific network subcontroller classes.

This file should only contain subclasses of `BaseNetworkController`.

"""

import logging
import asyncio

from mist.api.helpers import rename_kwargs

from mist.api.exceptions import SubnetNotFoundError
from mist.api.exceptions import NetworkNotFoundError
from mist.api.exceptions import MistNotImplementedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.clouds.controllers.network.base import BaseNetworkController
from mist.api.concurrency.models import PeriodicTaskLockTakenError
from mist.api.concurrency.models import PeriodicTaskTooRecentLastRun
from libcloud.compute.drivers.azure_arm import AzureNetwork


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

        # also save an array of `nic_id`s in network.extra['nics']
        # needed for machine-network association
        for subnet in libcloud_network.extra['subnets']:
            ip_configs = subnet.get('properties').get('ipConfigurations', [])
            for ip_config in ip_configs:
                # IP configurations can also contain load balancers'
                # configurations.
                if 'networkInterfaces' in ip_config.get('id', ''):
                    try:
                        nic_id = ip_config.get(
                            'id').split('/ipConfigurations')[-2]
                    except IndexError:
                        continue
                    if not network.extra.get('nics', []):
                        network.extra['nics'] = [nic_id]
                    else:
                        network.extra['nics'].append(nic_id)

    def _list_subnets__fetch_subnets(self, network):
        l_network = AzureNetwork(network.external_id,
                                 network.name, '', network.extra)
        return self.cloud.ctl.compute.connection.ex_list_subnets(l_network)

    def _list_subnets__cidr_range(self, subnet, libcloud_subnet):
        return subnet.extra.pop('addressPrefix')

    def _get_libcloud_subnet(self, subnet):
        networks = self.cloud.ctl.compute.connection.ex_list_networks()
        network = None
        for net in networks:
            if net.id == subnet.network.external_id:
                network = net
                break
        subnets = self.cloud.ctl.compute.connection.ex_list_subnets(network)
        for sub in subnets:
            if sub.id == subnet.external_id:
                return sub
        raise SubnetNotFoundError('Subnet %s with external_id \
            %s' % (subnet.name, subnet.external_id))

    def _delete_network(self, network, libcloud_network):
        raise MistNotImplementedError()

    def _delete_subnet(self, subnet, libcloud_subnet):
        raise MistNotImplementedError()


class AmazonNetworkController(BaseNetworkController):

    def _create_network__prepare_args(self, kwargs):
        rename_kwargs(kwargs, 'cidr', 'cidr_block')

    def _create_subnet__prepare_args(self, subnet, kwargs):
        kwargs['vpc_id'] = subnet.network.external_id
        rename_kwargs(kwargs, 'cidr', 'cidr_block')

    def _list_networks__cidr_range(self, network, libcloud_network):
        return libcloud_network.cidr_block

    def _list_networks__postparse_network(self, network, libcloud_network,
                                          r_groups=[]):
        tenancy = libcloud_network.extra.pop('instance_tenancy')
        network.instance_tenancy = tenancy

    def _list_subnets__fetch_subnets(self, network):
        kwargs = {'filters': {'vpc-id': network.external_id}}
        return self.cloud.ctl.compute.connection.ex_list_subnets(**kwargs)

    def _list_subnets__cidr_range(self, subnet, libcloud_subnet):
        return subnet.extra.pop('cidr_block')

    def _list_subnets__postparse_subnet(self, subnet, libcloud_subnet):
        subnet.availability_zone = libcloud_subnet.extra.pop('zone')

    def _delete_network(self, network, libcloud_network):
        self.cloud.ctl.compute.connection.ex_delete_network(libcloud_network)

    def _delete_subnet(self, subnet, libcloud_subnet):
        self.cloud.ctl.compute.connection.ex_delete_subnet(libcloud_subnet)

    def _rename_network(self, libcloud_network, name):
        return self.cloud.ctl.compute.connection.ex_rename_node(
            libcloud_network, name)

    def _rename_subnet(self, libcloud_subnet, name):
        return self.cloud.ctl.compute.connection.ex_rename_node(
            libcloud_subnet, name)

    def _get_libcloud_network(self, network):
        kwargs = {'network_ids': [network.external_id]}
        networks = self.cloud.ctl.compute.connection.ex_list_networks(**kwargs)
        if networks:
            return networks[0]
        raise NetworkNotFoundError('Network %s with external_id %s' %
                                   (network.name, network.external_id))

    def _get_libcloud_subnet(self, subnet):
        kwargs = {'subnet_ids': [subnet.external_id]}
        subnets = self.cloud.ctl.compute.connection.ex_list_subnets(**kwargs)
        if subnets:
            return subnets[0]
        raise SubnetNotFoundError('Subnet %s with external_id %s' %
                                  (subnet.name, subnet.external_id))


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
        filter_expression = 'network eq %s' % network.extra.get('selfLink')
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

    def delete_network(self, network):
        # Subnets of Google automatic networks cannot be deleted directly
        if network.mode == 'custom':
            return super().delete_network(network)

        assert network.cloud == self.cloud

        libcloud_network = self._get_libcloud_network(network)
        try:
            self._delete_network(network, libcloud_network)
        except Exception:
            log.error('Could not delete network %s', network)
            raise

        try:
            self.list_networks()
        except (PeriodicTaskLockTakenError,
                PeriodicTaskTooRecentLastRun):
            log.error('Failed to list networks after network deletion '
                      'for Google cloud: %s', self.cloud.id)

        from mist.api.poller.models import ListNetworksPollingSchedule
        ListNetworksPollingSchedule.add(cloud=self.cloud, interval=10, ttl=120)


class OpenStackNetworkController(BaseNetworkController):

    def _create_subnet__prepare_args(self, subnet, kwargs):
        kwargs['network_id'] = subnet.network.external_id

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
        kwargs = {
            'filters': {
                'network_id': network.external_id,
                'ip_version': 4,
            }
        }
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
        self.cloud.ctl.compute.connection.ex_delete_network(libcloud_network)

    def _delete_subnet(self, subnet, libcloud_subnet):
        self.cloud.ctl.compute.connection.ex_delete_subnet(libcloud_subnet.id)


class VexxhostNetworkController(OpenStackNetworkController):
    pass


class LibvirtNetworkController(BaseNetworkController):

    def list_networks_single_host(self, host):
        networks = []
        driver = self.cloud.ctl.compute._get_host_driver(host)
        networks += driver.ex_list_networks()
        networks += driver.ex_list_interfaces()
        return networks

    async def list_networks_all_hosts(self, hosts, loop):
        nets = [
            loop.run_in_executor(None, self.list_networks_single_host, host)
            for host in hosts
        ]
        return await asyncio.gather(*nets)

    def _list_networks__fetch_networks(self):
        from mist.api.machines.models import Machine
        hosts = Machine.objects(cloud=self.cloud, parent=None,
                                missing_since=None)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError('loop is closed')
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())
            loop = asyncio.get_event_loop()
        all_nets = loop.run_until_complete(self.list_networks_all_hosts(hosts,
                                                                        loop))
        return [net for host_nets in all_nets for net in host_nets]

    def _list_networks__postparse_network(self, network, libcloud_network,
                                          r_groups=[]):
        location = None
        host_name = libcloud_network.extra.get('host')
        from mist.api.clouds.models import CloudLocation
        try:
            location = CloudLocation.objects.get(cloud=self.cloud,
                                                 name=host_name)
        except CloudLocation.DoesNotExist:
            host_name = host_name.replace('.', '-')
            try:
                location = CloudLocation.objects.get(cloud=self.cloud,
                                                     external_id=host_name)
            except CloudLocation.DoesNotExist:
                pass

        network.location = location

    def _list_subnets__fetch_subnets(self, network):
        return []

    def _delete_network(self, network, libcloud_network):
        raise MistNotImplementedError()

    def _delete_subnet(self, subnet, libcloud_subnet):
        raise MistNotImplementedError()

    def _list_vnfs(self, host=None):
        from mist.api.machines.models import Machine
        from mist.api.clouds.models import CloudLocation
        if not host:
            hosts = Machine.objects(
                cloud=self.cloud, parent=None, missing_since=None)
        else:
            hosts = [host]
        vnfs = []
        for host in hosts:  # TODO: asyncio
            driver = self.cloud.ctl.compute._get_host_driver(host)
            host_vnfs = driver.ex_list_vnfs()
            try:
                location = CloudLocation.objects.get(cloud=self.cloud,
                                                     name=host.name)
            except CloudLocation.DoesNotExist:
                host_name = host.name.replace('.', '-')
                try:
                    location = CloudLocation.objects.get(cloud=self.cloud,
                                                         external_id=host_name)
                except CloudLocation.DoesNotExist:
                    location = None
            except Exception as e:
                log.error(e)
                location = None
            for vnf in host_vnfs:
                vnf['location'] = location.id
            vnfs += host_vnfs
        return vnfs


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
        return net.config.get("ipv4.address")


class AlibabaNetworkController(BaseNetworkController):

    def _create_network__prepare_args(self, kwargs):
        rename_kwargs(kwargs, 'cidr', 'cidr_block')
        # workaround to avoid create_network failure
        kwargs['only_id'] = False

    def _create_subnet__prepare_args(self, subnet, kwargs):
        rename_kwargs(kwargs, 'availability_zone', 'zone')
        kwargs['vpc'] = subnet.network.network_id
        # workaround to avoid create_subnet failure
        kwargs['only_id'] = False

    def _create_subnet(self, kwargs):
        return self.cloud.ctl.compute.connection.ex_create_switch(**kwargs)

    def _list_networks__cidr_range(self, network, libcloud_network):
        return libcloud_network.cidr_block

    def _list_networks__postparse_network(self, network, libcloud_network,
                                          r_groups=[]):
        network.description = libcloud_network.extra.pop('description', None)

    def _list_subnets__fetch_subnets(self, network):
        params = {
            'VpcId': network.network_id
        }
        return self.cloud.ctl.compute.connection.ex_list_switches(
            ex_filters=params)

    def _list_subnets__cidr_range(self, subnet, libcloud_subnet):
        return libcloud_subnet.cidr_block

    def _list_subnets__postparse_subnet(self, subnet, libcloud_subnet):
        subnet.availability_zone = libcloud_subnet.extra.pop('zone_id')

    def _delete_network(self, network, libcloud_network):
        # Network's security groups need to be deleted first
        params = {
            'VpcId': libcloud_network.id,
        }
        groups = self.cloud.ctl.compute.connection.ex_list_security_groups(
            ex_filters=params
        )
        for group in groups:
            self.cloud.ctl.compute.connection.ex_delete_security_group_by_id(
                group_id=group.id
            )
        self.cloud.ctl.compute.connection.ex_destroy_network(libcloud_network)

    def _delete_subnet(self, subnet, libcloud_subnet):
        self.cloud.ctl.compute.connection.ex_destroy_switch(libcloud_subnet)

    def _get_libcloud_subnet(self, subnet):
        subnets = self.cloud.ctl.compute.connection.ex_list_switches()
        for sub in subnets:
            if sub.id == subnet.subnet_id:
                return sub
        raise SubnetNotFoundError(
            f'Subnet {subnet.name} with subnet_id {subnet.subnet_id}')


class VultrNetworkController(BaseNetworkController):
    def _list_networks__fetch_networks(self):
        networks = self.cloud.ctl.compute.connection.ex_list_networks()
        for network in networks:
            network.name = network.extra.get('description', '')
        return networks

    def _list_networks__cidr_range(self, network, libcloud_network):
        return libcloud_network.cidr_block

    def _list_networks__postparse_network(self, network, libcloud_network,
                                          r_groups=[]):
        from mist.api.clouds.models import CloudLocation
        try:
            location = CloudLocation.objects.get(
                external_id=libcloud_network.location,
                cloud=self.cloud)
        except CloudLocation.DoesNotExist:
            location = None

        network.location = location

    def _list_subnets__fetch_subnets(self, network):
        return []

    def _delete_network(self, network, libcloud_network):
        return self.cloud.ctl.compute.connection.ex_destroy_network(
            libcloud_network)

    def _create_network__prepare_args(self, kwargs):
        if 'location' not in kwargs:
            raise RequiredParameterMissingError('location')
        rename_kwargs(kwargs, 'cidr', 'cidr_block')
        rename_kwargs(kwargs, 'name', 'description')

        kwargs['location'] = kwargs['location'].external_id
