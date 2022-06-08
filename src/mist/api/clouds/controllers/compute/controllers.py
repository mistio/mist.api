"""Cloud ComputeControllers

A cloud controller handles all operations that can be performed on a cloud,
commonly using libcloud under the hood.

It also performs several steps and combines the information stored in the
database with that returned from API calls to providers.

For each different cloud type, there is a corresponding cloud controller
defined here. All the different classes inherit BaseComputeController and share
a common interface, with the exception that some controllers may not have
implemented all methods.

A cloud controller is initialized given a cloud. Most of the time it will be
accessed through a cloud model, using the `ctl` abbreviation, like this:

    cloud = mist.api.clouds.models.Cloud.objects.get(id=cloud_id)
    print cloud.ctl.compute.list_machines()

"""


import re
import copy
import socket
import logging
import datetime
import netaddr
import tempfile
import iso8601
import pytz
import asyncio
import os
import json
import time
import secrets
import requests
import ipaddress
import base64

import mongoengine as me

from requests.exceptions import ConnectionError
from requests.exceptions import ConnectTimeout
from time import sleep
from html import unescape

from xml.sax.saxutils import escape

from libcloud.pricing import get_size_price, get_pricing
from libcloud.pricing import get_gce_image_price

from libcloud.compute.base import Node, NodeImage, NodeLocation
from libcloud.compute.base import NodeAuthSSHKey, NodeAuthPassword
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider, NodeState

from libcloud.container.drivers.kubernetes import Node as KubernetesNode
from libcloud.container.drivers.kubernetes import KubernetesPod
from libcloud.container.providers import get_driver as get_container_driver
from libcloud.container.types import Provider as Container_Provider
from libcloud.container.types import ContainerState
from libcloud.container.base import ContainerImage, Container

from libcloud.common.exceptions import BaseHTTPError
from libcloud.common.types import InvalidCredsError

from libcloud.utils.misc import to_n_bytes
from libcloud.utils.misc import to_memory_str
from libcloud.utils.misc import to_cpu_str
from libcloud.utils.misc import to_n_cpus

from mist.api.exceptions import MistError
from mist.api.exceptions import InternalServerError
from mist.api.exceptions import MachineNotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import ForbiddenError
from mist.api.exceptions import CloudUnauthorizedError
from mist.api.exceptions import CloudUnavailableError
from mist.api.exceptions import MachineCreationError

from mist.api.helpers import sanitize_host
from mist.api.helpers import amqp_owner_listening
from mist.api.helpers import node_to_dict
from mist.api.helpers import generate_secure_password, validate_password

from mist.api.clouds.controllers.main.base import BaseComputeController

from mist.api import config

if config.HAS_VPN:
    from mist.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat


log = logging.getLogger(__name__)


def is_private_subnet(host):
    try:
        ip_addr = netaddr.IPAddress(host)
    except netaddr.AddrFormatError:
        try:
            ip_addr = netaddr.IPAddress(socket.gethostbyname(host))
        except socket.gaierror:
            return False
    return ip_addr.is_private()


class AmazonComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.EC2)(self.cloud.apikey,
                                        self.cloud.apisecret.value,
                                        region=self.cloud.region)

    def _list_machines__machine_actions(self, machine, node_dict):
        super(AmazonComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        machine.actions.rename = True
        if node_dict['state'] != NodeState.TERMINATED.value:
            machine.actions.resize = True

    def _resize_machine(self, machine, node, node_size, kwargs):
        attributes = {'InstanceType.Value': node_size.id}
        # instance must be in stopped mode
        if node.state != NodeState.STOPPED:
            raise BadRequestError('The instance has to be stopped '
                                  'in order to be resized')
        try:
            self.connection.ex_modify_instance_attribute(node,
                                                         attributes)
            self.connection.ex_start_node(node)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        # This is windows for windows servers and None for Linux.
        os_type = node_dict['extra'].get('platform', 'linux')

        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True

        try:
            # return list of ids for network interfaces as str
            network_interfaces = node_dict['extra'].get(
                'network_interfaces', [])
            network_interfaces = [{
                'id': network_interface['id'],
                'state': network_interface['state'],
                'extra': network_interface['extra']
            } for network_interface in network_interfaces]
        except Exception as exc:
            log.warning("Cannot parse net ifaces for machine %s/%s/%s: %r" % (
                machine.name, machine.id, machine.owner.name, exc
            ))
            network_interfaces = []

        if network_interfaces != machine.extra.get('network_interfaces'):
            machine.extra['network_interfaces'] = network_interfaces
            updated = True

        network_id = node_dict['extra'].get('vpc_id')

        if machine.extra.get('network') != network_id:
            machine.extra['network'] = network_id
            updated = True

        # Discover network of machine.
        from mist.api.networks.models import Network
        try:
            network = Network.objects.get(cloud=self.cloud,
                                          external_id=network_id,
                                          missing_since=None)
        except Network.DoesNotExist:
            network = None

        if network != machine.network:
            machine.network = network
            updated = True

        subnet_id = machine.extra.get('subnet_id')
        if machine.extra.get('subnet') != subnet_id:
            machine.extra['subnet'] = subnet_id
            updated = True

        # Discover subnet of machine.
        from mist.api.networks.models import Subnet
        try:
            subnet = Subnet.objects.get(external_id=subnet_id,
                                        network=machine.network,
                                        missing_since=None)
        except Subnet.DoesNotExist:
            subnet = None
        if subnet != machine.subnet:
            machine.subnet = subnet
            updated = True

        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        # TODO: stopped instances still charge for the EBS device
        # https://aws.amazon.com/ebs/pricing/
        # Need to add this cost for all instances
        if node_dict['state'] == NodeState.STOPPED.value:
            return 0, 0

        sizes = self.connection.list_sizes()
        size = node_dict['extra'].get('instance_type')
        for node_size in sizes:
            if node_size.id == size and node_size.price:
                if isinstance(node_size.price, dict):
                    plan_price = node_size.price.get(machine.os_type)
                    if not plan_price:
                        # Use the default which is linux.
                        plan_price = node_size.price.get('linux')
                else:
                    plan_price = node_size.price
                if isinstance(plan_price, float) or isinstance(plan_price,
                                                               int):
                    return plan_price, 0
                else:
                    return plan_price.replace('/hour', '').replace('$', ''), 0
        return 0, 0

    def _list_machines__get_location(self, node):
        return node['extra'].get('availability')

    def _list_machines__get_size(self, node):
        return node['extra'].get('instance_type')

    def _list_images__fetch_images(self, search=None):
        if not search:
            from mist.api.images.models import CloudImage
            images_file = os.path.join(config.MIST_API_DIR,
                                       config.EC2_IMAGES_FILE)
            with open(images_file, 'r') as f:
                default_images = json.load(f)[self.cloud.region]

            image_ids = list(default_images.keys())
            try:
                # this might break if image_ids contains starred images
                # that are not valid anymore for AWS
                images = self.connection.list_images(None, image_ids)
            except Exception as e:
                bad_ids = re.findall(r'ami-\w*', str(e), re.DOTALL)
                for bad_id in bad_ids:
                    try:
                        _image = CloudImage.objects.get(cloud=self.cloud,
                                                        external_id=bad_id)
                        _image.delete()
                    except CloudImage.DoesNotExist:
                        log.error('Image %s not found in cloud %r' % (
                            bad_id, self.cloud
                        ))
                keys = list(default_images.keys())
                try:
                    images = self.connection.list_images(None, keys)
                except BaseHTTPError as e:
                    if 'UnauthorizedOperation' in str(e.message):
                        images = []
                    else:
                        raise()
            for image in images:
                if image.id in default_images:
                    image.name = default_images[image.id]
            try:
                images += self.connection.list_images(ex_owner='self')
            except BaseHTTPError as e:
                if 'UnauthorizedOperation' in str(e.message):
                    pass
                else:
                    raise()
        else:
            # search on EC2.
            search = search.lstrip()
            filters = [
                {
                    'image-id': search,
                    'image-type': 'machine',
                },
                {
                    'name': '%s*' % search,
                    'image-type': 'machine',
                },
                {
                    'description': '*%s*' % search,
                    'image-type': 'machine',
                },
            ]
            images = []
            for filter_ in filters:
                try:
                    images = self.connection.list_images(
                        ex_filters=filter_)
                except BaseHTTPError as e:
                    if 'UnauthorizedOperation' in str(e.message):
                        break
                    else:
                        raise()
                else:
                    if images:
                        break

            def sort_by_owner(libcloud_image):
                """Sort images fetched based on the owner alias.

                Give priority first to Amazon's own images,
                then self and `None` and finally marketplace.
                """
                owner_alias = libcloud_image.extra.get('owner_alias')
                if owner_alias == 'amazon':
                    return 0
                if owner_alias == 'self':
                    return 1
                if owner_alias is None:
                    return 2
                if owner_alias == 'aws-marketplace':
                    return 3
                return 4

            images = sorted(images, key=sort_by_owner)[:50]

        return images

    def _list_machines__get_machine_cluster(self,
                                            machine,
                                            node):
        # Nodes belonging to an EKS Cluster automatically get assigned
        # the 'eks:cluster-name' tag.
        try:
            cluster_name = node['extra']['tags']['eks:cluster-name']
        except KeyError:
            return None

        from mist.api.containers.models import Cluster
        cluster = None
        try:
            cluster = Cluster.objects.get(name=cluster_name,
                                          cloud=self.cloud,
                                          missing_since=None)
        except Cluster.DoesNotExist as exc:
            log.warn('Error getting cluster of %s: %r', machine, exc)

        return cluster

    def image_is_default(self, image_id):
        return image_id in config.EC2_IMAGES[self.cloud.region]

    def _list_locations__fetch_locations(self):
        """List availability zones for EC2 region
        """
        from libcloud.compute.base import NodeLocation
        locations = self.connection.list_locations()
        region = NodeLocation(id=self.cloud.region,
                              name=self.cloud.region,
                              country=self.connection.country,
                              driver=self.connection,
                              extra={})
        locations.insert(0, region)
        return locations

    def _list_locations__get_parent(self, location, libcloud_location):
        from mist.api.clouds.models import CloudLocation
        if libcloud_location.id == self.cloud.region:
            return None

        try:
            parent = CloudLocation.objects.get(
                external_id=self.cloud.region,
                cloud=self.cloud,
                missing_since=None)
            return parent
        except me.DoesNotExist:
            log.error('Parent does not exist for Location: %s',
                      location.id)

    def _list_locations__get_type(self, location, libcloud_location):
        if libcloud_location.id == self.cloud.region:
            return 'region'
        return 'zone'

    def _list_sizes__get_cpu(self, size):
        return int(size.extra.get('vcpu', 1))

    def _list_sizes__get_name(self, size):
        return '%s - %s' % (size.id, size.name)

    def _list_sizes__get_architecture(self, size):
        """Arm-based sizes use Amazon's Graviton processor
        """
        if 'graviton' in size.extra.get('physicalProcessor', '').lower():
            return 'arm'
        return 'x86'

    def _list_images__get_os_type(self, image):
        # os_type is needed for the pricing per VM
        if image.name:
            if any(x in image.name.lower() for x in ['sles',
                                                     'suse linux enterprise']):
                return 'sles'
            if any(x in image.name.lower() for x in ['rhel', 'red hat']):
                return 'rhel'
            if 'windows' in image.name.lower():
                if 'sql' in image.name.lower():
                    if 'web' in image.name.lower():
                        return 'mswinSQLWeb'
                    return 'mswinSQL'
                return 'mswin'
            if 'vyatta' in image.name.lower():
                return 'vyatta'
            return 'linux'

    def _list_images__get_architecture(self, image):
        architecture = image.extra.get('architecture')
        if architecture == 'arm64':
            return ['arm']
        return ['x86']

    def _list_images__get_origin(self, image):
        if image.extra.get('is_public', 'true').lower() == 'true':
            return 'system'
        return 'custom'

    def _list_security_groups(self):
        try:
            sec_groups = \
                self.cloud.ctl.compute.connection.ex_list_security_groups()
        except Exception as exc:
            log.error('Could not list security groups for cloud %s: %r',
                      self.cloud, exc)
            raise CloudUnavailableError(exc=exc)

        return sec_groups

    def _generate_plan__parse_networks(self, auth_context, network_dict,
                                       location):
        security_group = network_dict.get('security_group')
        subnet = network_dict.get('subnet')

        networks = {}
        sec_groups = self.connection.ex_list_security_groups()
        if security_group:
            for sec_group in sec_groups:
                if (security_group == sec_group['id'] or
                        security_group == sec_group['name']):
                    networks['security_group'] = {
                        'name': sec_group['name'],
                        'id': sec_group['id']
                    }
                    break
            else:
                raise NotFoundError('Security group not found: %s'
                                    % security_group)
        else:
            # check if default security_group already exists
            for sec_group in sec_groups:
                if sec_group['name'] == config.EC2_SECURITYGROUP.get('name',
                                                                     ''):
                    networks['security_group'] = {
                        'name': sec_group['name'],
                        'id': sec_group['id']
                    }
                    break
            else:
                networks['security_group'] = {
                    'name': config.EC2_SECURITYGROUP.get('name', ''),
                    'description':
                        config.EC2_SECURITYGROUP.get('description', '').format(
                            portal_name=config.PORTAL_NAME)
                }

        if subnet:
            # APIv1 also searches for amazon's id
            from mist.api.methods import list_resources
            subnets, _ = list_resources(auth_context, 'subnet',
                                        search=subnet,
                                        )
            subnets = [subnet for subnet in subnets
                       if subnet.network.cloud == self.cloud]
            if len(subnets) == 0:
                raise NotFoundError('Subnet not found %s' % subnet)

            networks['subnet'] = subnets[0].id

        return networks

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        if not volume_dict.get('device'):
            raise BadRequestError('Device is mandatory'
                                  ' when attaching a volume')
        ret_dict = {
            'id': vol_obj.id,
            'device': volume_dict['device']
        }
        return ret_dict

    def _generate_plan__parse_custom_volume(self, volume_dict):
        size = volume_dict.get('size')
        name = volume_dict.get('name')
        volume_type = volume_dict.get('volume_type')
        iops = volume_dict.get('iops')
        delete_on_termination = volume_dict.get('delete_on_termination')

        if size is None or name is None:
            raise BadRequestError('Volume required parameter missing')

        ret_dict = {
            'size': size,
            'name': name,
            'volume_type': volume_type,
            'iops': iops,
            'delete_on_termination': delete_on_termination
        }

        return ret_dict

    def _create_machine__get_location_object(self, location):
        from libcloud.compute.drivers.ec2 import ExEC2AvailabilityZone
        location_obj = super()._create_machine__get_location_object(location)
        location_obj.availability_zone = ExEC2AvailabilityZone(
            name=location_obj.name,
            zone_state=None,
            region_name=self.connection.region_name
        )
        return location_obj

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        kwargs['ex_keyname'] = kwargs['auth'].name
        kwargs['auth'] = NodeAuthSSHKey(pubkey=kwargs['auth'].public)

        kwargs['ex_userdata'] = plan.get('cloudinit', '')
        security_group = plan['networks']['security_group']
        # if id is not given, then default security group does not exist
        if not security_group.get('id'):
            try:
                log.info('Attempting to create security group')
                ret_dict = self.connection.ex_create_security_group(
                    name=plan['networks']['security_group']['name'],
                    description=plan['networks']['security_group']['description']  # noqa
                )
                self.connection.ex_authorize_security_group_permissive(
                    name=plan['networks']['security_group']['name'])
            except Exception as exc:
                raise InternalServerError(
                    "Couldn't create security group", exc)
            else:
                security_group['id'] = ret_dict['group_id']

        subnet_id = plan['networks'].get('subnet')
        if subnet_id:
            from mist.api.networks.models import Subnet
            subnet = Subnet.objects.get(id=subnet_id)
            subnet_external_id = subnet.subnet_id

            # TODO check if the following API call is not needed
            # and instead instantiate an EC2NetworkSubnet object
            # libcloud.compute.drivers.ec2.EC2NetworkSubnet
            libcloud_subnets = self.connection.ex_list_subnets()
            for libcloud_subnet in libcloud_subnets:
                if libcloud_subnet.id == subnet_external_id:
                    subnet = libcloud_subnet
                    break
            else:
                raise NotFoundError('Subnet specified does not exist')
            # if subnet is specified, then security group id
            # instead of security group name is needed
            kwargs.update({
                'ex_subnet': subnet,
                'ex_security_group_ids': security_group['id']
            })
        else:
            kwargs.update({
                'ex_securitygroup': plan['networks']['security_group']['name']
            })
        mappings = []
        for volume in plan.get('volumes', []):
            # here only the mappings are handled
            # volumes will be created and attached after machine creation
            if not volume.get('id'):
                mapping = {}
                mapping.update({'Ebs':
                                {'VolumeSize': int(volume.get('size'))}})
                if volume.get('name'):
                    mapping.update({'DeviceName': volume.get('name')})
                if volume.get('volume_type'):
                    volume_type = {'VolumeType': volume.get('volume_type')}
                    mapping['Ebs'].update(volume_type)
                if volume.get('iops'):
                    mapping['Ebs'].update({'Iops': volume.get('iops')})
                if volume.get('delete_on_termination'):
                    delete_on_term = volume.get('delete_on_termination')
                    mapping['Ebs'].update({
                        'DeleteOnTermination': delete_on_term})
                mappings.append(mapping)
        kwargs.update({'ex_blockdevicemappings': mappings})
        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        volumes = []
        for volume in plan.get('volumes', []):
            if volume.get('id'):
                from mist.api.volumes.models import Volume
                from libcloud.compute.base import StorageVolume
                vol = Volume.objects.get(id=volume['id'])
                libcloud_vol = StorageVolume(id=vol.external_id,
                                             name=vol.name,
                                             size=vol.size,
                                             driver=self.connection,
                                             extra=vol.extra)
                ex_vol = {
                    'volume': libcloud_vol,
                    'device': volume.get('device')
                }
                volumes.append(ex_vol)
        if volumes:
            ready = False
            while not ready:
                lib_nodes = self.connection.list_nodes()
                for lib_node in lib_nodes:
                    if lib_node.id == node.id and lib_node.state == 'running':
                        ready = True
            for volume in volumes:
                self.connection.attach_volume(node, volume.get('volume'),
                                              volume.get('device'))

    def _list_machines__get_machine_extra(self, machine, node_dict):
        extra = copy.copy(node_dict['extra'])
        nodepool_name = extra.get(
            'tags', {}).get('eks:nodegroup-name', '')
        if nodepool_name:
            extra['nodepool'] = nodepool_name
        return extra


class AlibabaComputeController(AmazonComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.ALIYUN_ECS)(self.cloud.apikey,
                                               self.cloud.apisecret.value,
                                               region=self.cloud.region)

    def _resize_machine(self, machine, node, node_size, kwargs):
        # instance must be in stopped mode
        if node.state != NodeState.STOPPED:
            raise BadRequestError('The instance has to be stopped '
                                  'in order to be resized')
        try:
            self.connection.ex_resize_node(node, node_size.id)
            self.connection.ex_start_node(node)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__get_location(self, node):
        return node['extra'].get('zone_id')

    def _list_machines__cost_machine(self, machine, node_dict):
        size = node_dict['extra'].get('instance_type', {})
        driver_name = 'ecs-' + node_dict['extra'].get('zone_id')
        price = get_pricing(
            driver_type='compute', driver_name=driver_name).get(size, {})
        image = node_dict['extra'].get('image_id', '')
        if 'win' in image:
            price = price.get('windows', '')
        else:
            price = price.get('linux', '')
        if node_dict['extra'].get('instance_charge_type') == 'PostPaid':
            return (price.get('pay_as_you_go', 0), 0)
        else:
            return (0, price.get('prepaid', 0))

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('creation_time')

    def _list_images__fetch_images(self, search=None):
        return self.connection.list_images()

    def image_is_default(self, image_id):
        return True

    def _list_images__get_os_type(self, image):
        if image.extra.get('os_type', ''):
            return image.extra.get('os_type').lower()
        if 'windows' in image.name.lower():
            return 'windows'
        else:
            return 'linux'

    def _list_locations__fetch_locations(self):
        """List ECS regions as locations, embed info about zones

        In EC2 all locations of a region have the same name, so the
        availability zones are listed instead.

        """
        zones = self.connection.ex_list_zones()
        locations = []
        for zone in zones:
            extra = {
                'name': zone.name,
                'available_disk_categories': zone.available_disk_categories,
                'available_instance_types': zone.available_instance_types,
                'available_resource_types': zone.available_resource_types
            }
            location = NodeLocation(
                id=zone.id, name=zone.id, country=zone.id, driver=zone.driver,
                extra=extra
            )
            locations.append(location)
        return locations

    def _list_locations__get_available_sizes(self, location):
        from mist.api.clouds.models import CloudSize
        return CloudSize.objects(cloud=self.cloud,
                                 external_id__in=location.extra['available_instance_types'])  # noqa

    def _list_sizes__get_cpu(self, size):
        return size.extra['cpu_core_count']

    def _list_sizes__get_name(self, size):
        specs = str(size.extra['cpu_core_count']) + ' cpus/ ' \
            + str(size.ram / 1024) + 'Gb RAM '
        return "%s (%s)" % (size.name, specs)

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('platform').lower()
        except AttributeError:
            return super()._list_images__get_os_distro(image)

        if 'windows' in os_distro:
            os_distro = 'windows'
        return os_distro

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('size'))
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _list_images__get_origin(self, image):
        """ `image_owner_alias` valid values are:

            system: public images provided by alibaba
            self: account's custom images
            others: shared images from other accounts
            marketplace: alibaba marketplace images
        """
        owner = image.extra.get('image_owner_alias', 'system')
        if owner == 'system':
            return 'system'
        elif owner == 'marketplace':
            return 'marketplace'
        else:
            return 'custom'

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        from mist.api.methods import list_resources
        ret_dict = {}

        network_search = networks_dict.get('network', '')
        networks, count = list_resources(auth_context,
                                         'network',
                                         search=network_search,
                                         cloud=self.cloud.id,
                                         )
        if count == 0:
            raise NotFoundError(f'Network "{network_search}" not found')

        subnet_search = networks_dict.get('subnet',
                                          config.ECS_SWITCH.get('name'))
        subnets, _ = list_resources(auth_context,
                                    'subnet',
                                    search=subnet_search,
                                    )
        subnets = subnets.filter(network__in=networks)
        subnets = [subnet for subnet in subnets
                   if subnet.extra['zone_id'] == location.external_id]
        if len(subnets) == 0:
            # Subnet will be created later on the first network found
            ret_dict['network'] = {
                'id': networks[0].id,
                'name': networks[0].name,
                'external_id': networks[0].network_id,
            }
            ret_dict['subnet'] = {
                'name': subnet_search,
            }
        else:
            subnet = subnets[0]
            ret_dict['network'] = {
                'id': subnet.network.id,
                'name': subnet.network.name,
                'external_id': subnet.network.network_id,
            }
            ret_dict['subnet'] = {
                'id': subnet.id,
                'name': subnet.name,
                'external_id': subnet.subnet_id,
            }

        try:
            ret_dict['security_group'] = networks_dict['security_group']
        except KeyError:
            ret_dict['security_group'] = config.EC2_SECURITYGROUP.get('name')

        return ret_dict

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        delete_on_termination = True if volume_dict.get(
            'delete_on_termination', False) is True else False

        return {
            'id': vol_obj.id,
            'name': vol_obj.name,
            'delete_on_termination': delete_on_termination,
        }

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            name = volume_dict['name']
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume name & size are required parameters')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid size type')

        type_ = volume_dict.get('type', config.ALIBABA_DEFAULT_VOLUME_TYPE)
        try:
            min_valid, max_valid = config.ALIBABA_VOLUME_TYPES[type_]
        except KeyError:
            raise BadRequestError(
                f'Permitted volume types are: '
                f'{*config.ALIBABA_VOLUME_TYPES.keys(),}')

        if size not in range(min_valid, max_valid + 1):
            raise BadRequestError(
                f"Valid size values for '{type_}' type are "
                f"{min_valid} to {max_valid}"
            )

        delete_on_termination = True if volume_dict.get(
            'delete_on_termination', False) is True else False

        return {
            'name': name,
            'size': size,
            'type': type_,
            'delete_on_termination': delete_on_termination,
        }

    def _create_machine__get_location_object(self, location):
        # Redefine method to avoid calling Amazon's
        # corresponding method
        return BaseComputeController._create_machine__get_location_object(
            self, location)

    def _create_machine__compute_kwargs(self, plan):
        kwargs = BaseComputeController._create_machine__compute_kwargs(
            self, plan)
        kwargs['ex_zone_id'] = kwargs.pop('location').id
        kwargs['ex_keyname'] = kwargs['auth'].name
        kwargs['auth'] = NodeAuthSSHKey(pubkey=kwargs['auth'].public)
        if plan.get('cloudinit'):
            kwargs['ex_userdata'] = plan['cloudinit']

        vpc_id = plan['networks']['network']['external_id']
        sec_group_name = plan['networks']['security_group']
        security_groups = self.connection.ex_list_security_groups(
            ex_filters={
                'VpcId': vpc_id,
                'SecurityGroupName': sec_group_name
            }
        )
        if security_groups:
            sec_group_id = security_groups[0].id
        else:
            description = config.EC2_SECURITYGROUP['description'].format(
                portal_name=config.PORTAL_NAME
            )
            sec_group_id = self.connection.ex_create_security_group(
                name=sec_group_name,
                description=description,
                vpc_id=vpc_id)
            self.connection.ex_authorize_security_group(
                group_id=sec_group_id,
                description='Allow SSH',
                ip_protocol='tcp',
                port_range='22/22')
        kwargs['ex_security_group_id'] = sec_group_id

        subnet_id = plan['networks']['subnet'].get('external_id')
        if subnet_id:
            kwargs['ex_vswitch_id'] = subnet_id
        else:
            from mist.api.networks.models import AlibabaNetwork, AlibabaSubnet
            network = AlibabaNetwork.objects.get(
                id=plan['networks']['network']['id'],
                cloud=self.cloud)
            cidr_network = ipaddress.IPv4Network(network.cidr)
            # decide the subnet mask length
            mask_length = config.ECS_SWITCH_CIDR_BLOCK_LENGTH
            prefix = (mask_length
                      if cidr_network.prefixlen < mask_length
                      else cidr_network.prefixlen + 2)
            if prefix > 32:
                prefix = 32
            subnets = AlibabaSubnet.objects(network=network,
                                            missing_since=None)
            subnet_cidrs = [ipaddress.IPv4Network(subnet.cidr)
                            for subnet in subnets]
            # Find an available CIDR block for the new subnet
            for subnet in cidr_network.subnets(new_prefix=prefix):
                overlaps = any((
                    subnet.supernet_of(
                        subnet_cidr) or subnet.subnet_of(subnet_cidr)
                    for subnet_cidr in subnet_cidrs))
                if not overlaps:
                    subnet_cidr_block = subnet.exploded
                    break
            else:
                raise MachineCreationError(
                    'Could not find available switch(subnet)')

            subnet_name = plan['networks']['subnet']['name']
            description = config.ECS_SWITCH['description'].format(
                portal_name=config.PORTAL_NAME
            )
            kwargs['ex_vswitch_id'] = self.connection.ex_create_switch(
                subnet_cidr_block,
                kwargs['ex_zone_id'],
                vpc_id,
                name=subnet_name,
                description=description)
            # make sure switch is available to use
            for _ in range(10):
                switches = self.cloud.ctl.compute.connection.ex_list_switches(
                    ex_filters={'VSwitchId': kwargs['ex_vswitch_id']})
                if switches and switches[0].extra['status'] == 'Available':
                    break
                time.sleep(5)
        # already existing volumes cannot be passed as parameters
        # to the createInstance API  endpoint,
        # so they will be attached after machine creation
        new_volumes = []
        for volume in plan.get('volumes', []):
            if volume.get('id') is None:
                # create_node expect category instead of type
                volume['category'] = volume['type']
                new_volumes.append(volume)
        if new_volumes:
            kwargs['ex_data_disks'] = new_volumes

        kwargs['max_tries'] = 1
        kwargs['ex_io_optimized'] = True
        kwargs['ex_allocate_public_ip_address'] = True
        kwargs['ex_internet_charge_type'] = 'PayByTraffic'
        kwargs['ex_internet_max_bandwidth_out'] = 100

        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        from mist.api.volumes.models import Volume
        from libcloud.compute.base import StorageVolume
        existing_volumes = [
            volume for volume in plan.get('volumes', [])
            if volume.get('id')
        ]
        if len(existing_volumes) == 0:
            return
        # wait for node to be running
        for _ in range(10):
            nodes = self.connection.list_nodes(ex_node_ids=[node.id])
            if nodes and nodes[0].state == 'running':
                break
            time.sleep(5)
        for volume in existing_volumes:
            vol = Volume.objects.get(id=volume['id'])
            libcloud_vol = StorageVolume(id=vol.external_id,
                                         name=vol.name,
                                         size=vol.size,
                                         driver=self.connection)
            try:
                self.connection.attach_volume(
                    node,
                    libcloud_vol,
                    ex_delete_with_instance=volume['delete_on_termination'])
            except Exception as exc:
                log.exception('Failed to attach volume')


class DigitalOceanComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.DIGITAL_OCEAN)(self.cloud.token.value)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        cpus = machine.extra.get('size', {}).get('vcpus', 0)
        if machine.extra.get('cpus') != cpus:
            machine.extra['cpus'] = cpus
            updated = True
        return updated

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('created_at')  # iso8601 string

    def _list_machines__machine_actions(self, machine, node_dict):
        super(DigitalOceanComputeController,
              self)._list_machines__machine_actions(machine, node_dict)
        machine.actions.rename = True
        machine.actions.resize = True
        machine.actions.power_cycle = True

    def _resize_machine(self, machine, node, node_size, kwargs):
        try:
            self.connection.ex_resize_node(node, node_size)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__cost_machine(self, machine, node_dict):
        size = node_dict['extra'].get('size', {})
        return size.get('price_hourly', 0), size.get('price_monthly', 0)

    def _stop_machine(self, machine, node):
        self.connection.ex_shutdown_node(node)

    def _start_machine(self, machine, node):
        self.connection.ex_power_on_node(node)

    def _power_cycle_machine(self, node):
        try:
            self.connection.ex_hard_reboot(node)
        except Exception as exc:
            raise BadRequestError('Failed to execute power_cycle on \
                node: %s' % exc)

    def _list_machines__get_location(self, node):
        return node['extra'].get('region')

    def _list_machines__get_size(self, node):
        return node['extra'].get('size_slug')

    def _list_sizes__get_name(self, size):
        cpus = str(size.extra.get('vcpus', ''))
        ram = str(size.ram / 1024)
        disk = str(size.disk)
        bandwidth = str(size.bandwidth)
        price_monthly = str(size.extra.get('price_monthly', ''))
        if cpus:
            name = cpus + ' CPU, ' if cpus == '1' else cpus + ' CPUs, '
        if ram:
            name += ram + ' GB, '
        if disk:
            name += disk + ' GB SSD Disk, '
        if price_monthly:
            name += '$' + price_monthly + '/month'

        return name

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('vcpus')

    def _generate_plan__parse_custom_volume(self, volume_dict):
        size = volume_dict.get('size')
        name = volume_dict.get('name')
        fs_type = volume_dict.get('filesystem_type', '')
        if not size and name:
            raise BadRequestError('Size and name are mandatory'
                                  'for volume creation')
        volume = {
            'size': size,
            'name': name,
            'filesystem_type': fs_type
        }
        return volume

    def _create_machine__get_key_object(self, key):
        key_obj = super()._create_machine__get_key_object(key)
        server_key = ''
        libcloud_keys = self.connection.list_key_pairs()
        for libcloud_key in libcloud_keys:
            if libcloud_key.public_key == key_obj.public:
                server_key = libcloud_key
                break
        if not server_key:
            server_key = self.connection.create_key_pair(
                key_obj.name, key_obj.public
            )
        return server_key.extra.get('id')

    def _create_machine__get_size_object(self, size):
        size_obj = super()._create_machine__get_size_object(size)
        size_obj.name = size_obj.id
        return size_obj

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        # apiV1 function _create_machine_digital_ocean checks for
        # `private_networking` in location.extra but no location
        # seems to return it.
        kwargs['ex_create_attr'] = {
            'private_networking': True,
            'ssh_keys': [kwargs.pop('auth')]
        }

        volumes = []
        from mist.api.volumes.models import Volume
        for volume in plan.get('volumes', []):
            if volume.get('id'):
                try:
                    mist_vol = Volume.objects.get(id=volume['id'])
                    volumes.append(mist_vol.external_id)
                except me.DoesNotExist:
                    # this shouldn't happen as during plan creation
                    # volume id existed in mongo
                    continue
            else:
                fs_type = volume.get('filesystem_type', '')
                name = volume.get('name')
                size = int(volume.get('size'))
                location = kwargs['location']
                # TODO create_volume might raise ValueError
                new_volume = self.connection.create_volume(
                    size, name, location=location, filesystem_type=fs_type)
                volumes.append(new_volume.id)
        kwargs['volumes'] = volumes

        return kwargs

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('distribution').lower()
        except AttributeError:
            return super()._list_images__get_os_distro(image)
        return os_distro

    def _list_sizes__get_available_locations(self, mist_size):
        from mist.api.clouds.models import CloudLocation
        CloudLocation.objects(
            cloud=self.cloud,
            external_id__in=mist_size.extra.get('regions', [])
        ).update(add_to_set__available_sizes=mist_size)

    def _list_images__fetch_images(self, search=None):
        snapshots = self.connection.ex_list_snapshots(resource_type='droplet')
        images = self.connection.list_images()

        return images + snapshots

    def _list_images__get_available_locations(self, mist_image):
        from mist.api.clouds.models import CloudLocation
        CloudLocation.objects(
            cloud=self.cloud,
            external_id__in=mist_image.extra.get('regions', [])
        ).update(add_to_set__available_images=mist_image)

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('min_disk_size'))
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _list_images__get_origin(self, image):
        from libcloud.compute.drivers.digitalocean import DigitalOceanSnapshot
        if isinstance(image, DigitalOceanSnapshot):
            return 'snapshot'

        if image.extra.get('public'):
            return 'system'
        return 'custom'


class MaxihostComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.MAXIHOST)(self.cloud.token.value)

    def _list_machines__machine_actions(self, machine, node_dict):
        super(MaxihostComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        if node_dict['state'] is NodeState.PAUSED.value:
            machine.actions.start = True

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        if node_dict['extra'].get('ips', []):
            name = node_dict['extra'].get('ips')[0].get(
                'device_hostname')
            if machine.hostname != name:
                machine.hostname = name
                updated = True
        return updated

    def _list_machines__get_location(self, node):
        return node['extra'].get('location').get('facility_code')

    def _start_machine(self, machine, node):
        node.id = node.extra.get('id', '')
        return self.connection.ex_start_node(node)

    def _stop_machine(self, machine, node):
        node.id = node.extra.get('id', '')
        return self.connection.ex_stop_node(node)

    def _reboot_machine(self, machine, node):
        node.id = node.extra.get('id', '')
        return self.connection.reboot_node(node)

    def _destroy_machine(self, machine, node):
        node.id = node.extra.get('id', '')
        return self.connection.destroy_node(node)

    def _list_sizes__get_name(self, size):
        name = size.extra['specs']['cpus']['type']
        try:
            cpus = int(size.extra['specs']['cpus']['cores'])
        except ValueError:  # 'N/A'
            cpus = None
        memory = size.extra['specs']['memory']['total']
        disk_count = size.extra['specs']['drives'][0]['count']
        disk_size = size.extra['specs']['drives'][0]['size']
        disk_type = size.extra['specs']['drives'][0]['type']
        cpus_info = str(cpus) + ' cores/' if cpus else ''
        return name + '/ ' + cpus_info \
                           + memory + ' RAM/ ' \
                           + str(disk_count) + ' * ' + disk_size + ' ' \
                           + disk_type

    def _list_images__get_os_type(self, image):
        if image.extra.get('operating_system', ''):
            return image.extra.get('operating_system').lower()
        if 'windows' in image.name.lower():
            return 'windows'
        else:
            return 'linux'


class LinodeComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        if self.cloud.apiversion is not None:
            return get_driver(Provider.LINODE)(
                self.cloud.apikey.value,
                api_version=self.cloud.apiversion)
        else:
            return get_driver(Provider.LINODE)(self.cloud.apikey.value)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        if self.cloud.apiversion is not None:
            return node_dict['extra'].get('CREATE_DT')  # iso8601 string
        else:
            return node_dict.get('created_at')

    def _list_machines__machine_actions(self, machine, node_dict):
        super(LinodeComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        machine.actions.rename = True
        machine.actions.resize = True
        # machine.actions.stop = False
        # After resize, node gets to pending mode, needs to be started.
        if node_dict['state'] is NodeState.PENDING.value:
            machine.actions.start = True

    def _list_machines__cost_machine(self, machine, node_dict):
        if self.cloud.apiversion is not None:
            size = node_dict['extra'].get('PLANID')
            try:
                price = get_size_price(driver_type='compute',
                                       driver_name='linode',
                                       size_id=size)
            except KeyError:
                price = 0
            return 0, price or 0
        else:
            size = node_dict.get('size')
            from mist.api.clouds.models import CloudSize
            try:
                _size = CloudSize.objects.get(external_id=size,
                                              cloud=self.cloud)
            except CloudSize.DoesNotExist:
                raise NotFoundError()

            price_per_month = _size.extra.get('monthly_price', 0.0)
            price_per_hour = _size.extra.get('price', 0.0)

            return price_per_hour, price_per_month

    def _list_machines__get_size(self, node):
        if self.cloud.apiversion is not None:
            return node['extra'].get('PLANID')
        else:
            return node.get('size')

    def _list_machines__get_location(self, node):
        if self.cloud.apiversion is not None:
            return str(node['extra'].get('DATACENTERID'))
        else:
            return node['extra'].get('location')

    def _list_images__fetch_images(self, search=None):
        """ Convert datetime object to isoformat
        """
        images = self.connection.list_images()
        from datetime import datetime
        for image in images:
            if 'created' in image.extra and \
                    isinstance(image.extra['created'], datetime):
                image.extra['created'] = image.extra['created'].isoformat()
        return images

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('vendor').lower()
        except AttributeError:
            return super()._list_images__get_os_distro(image)
        return os_distro

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('size')) / 1000
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _list_images__get_origin(self, image):
        if image.extra.get('public'):
            return 'system'
        return 'custom'

    def _list_sizes__get_cpu(self, size):
        if self.cloud.apiversion is not None:
            return super()._list_sizes__get_cpu(size)
        return int(size.extra.get('vcpus') or 1)

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        persist_across_boots = True if volume_dict.get(
            'persist_across_boots', True) is True else False
        ret = {
            'id': vol_obj.id,
            'name': vol_obj.name,
            'persist_across_boots': persist_across_boots
        }
        return ret

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size parameter is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')

        if size < 10:
            raise BadRequestError('Volume size should be at least 10 GBs')

        try:
            name = str(volume_dict['name'])
        except KeyError:
            raise BadRequestError('Volume name parameter is required')

        return {'name': name, 'size': size}

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        private_ip = True if networks_dict.get(
            'private_ip', True) is True else False
        return {'private_ip': private_ip}

    def _generate_plan__parse_extra(self, extra, plan):
        try:
            root_pass = extra['root_pass']
        except KeyError:
            root_pass = generate_secure_password()
        else:
            if validate_password(root_pass) is False:
                raise BadRequestError(
                    "Your password must contain at least one "
                    "lowercase character, one uppercase and one digit")
        plan['root_pass'] = root_pass

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        key = kwargs.pop('auth')
        kwargs['ex_authorized_keys'] = [key.public]
        kwargs['ex_private_ip'] = plan['networks']['private_ip']
        kwargs['root_pass'] = plan['root_pass']
        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        from mist.api.volumes.models import Volume
        from libcloud.compute.base import StorageVolume
        volumes = plan.get('volumes', [])
        for volume in volumes:
            if volume.get('id'):
                vol = Volume.objects.get(id=volume['id'])
                libcloud_vol = StorageVolume(id=vol.external_id,
                                             name=vol.name,
                                             size=vol.size,
                                             driver=self.connection,
                                             extra=vol.extra)
                try:
                    self.connection.attach_volume(
                        node,
                        libcloud_vol,
                        persist_across_boots=volume['persist_across_boots'])
                except Exception as exc:
                    log.exception('Failed to attach volume')
            else:
                try:
                    self.connection.create_volume(volume['name'],
                                                  volume['size'],
                                                  node=node)
                except Exception as exc:
                    log.exception('Failed to create volume')


class RackSpaceComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        if self.cloud.region in ('us', 'uk'):
            driver = get_driver(Provider.RACKSPACE_FIRST_GEN)
        else:
            driver = get_driver(Provider.RACKSPACE)
        return driver(self.cloud.username, self.cloud.apikey.value,
                      region=self.cloud.region)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('created')  # iso8601 string

    def _list_machines__machine_actions(self, machine, node_dict):
        super(RackSpaceComputeController,
              self)._list_machines__machine_actions(machine, node_dict)
        machine.actions.rename = True

    def _list_machines__cost_machine(self, machine, node_dict):
        # Need to get image in order to specify the OS type
        # out of the image id.
        size = node_dict['extra'].get('flavorId')
        location = self.connection.region[:3]
        driver_name = 'rackspacenova' + location
        price = None
        try:
            price = get_size_price(driver_type='compute',
                                   driver_name=driver_name,
                                   size_id=size)
        except KeyError:
            log.error('Pricing for %s:%s was not found.' % (driver_name, size))

        if price:
            plan_price = price.get(machine.os_type) or price.get('linux')
            # 730 is the number of hours per month as on
            # https://www.rackspace.com/calculator
            return plan_price, float(plan_price) * 730

            # TODO: RackSpace mentions on
            # https://www.rackspace.com/cloud/public-pricing
            # there's a minimum service charge of $50/mo across all servers.
        return 0, 0

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        # Find os_type. TODO: Look in extra
        os_type = machine.os_type or 'linux'
        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True
        return updated

    def _list_machines__get_size(self, node):
        return node['extra'].get('flavorId')

    def _list_sizes__get_cpu(self, size):
        return size.vcpus

    def _list_images__get_os_type(self, image):
        if image.extra.get('metadata', '').get('os_type', ''):
            return image.extra.get('metadata').get('os_type').lower()
        if 'windows' in image.name.lower():
            return 'windows'
        else:
            return 'linux'

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('metadata', {}).get('os_distro').lower()  # noqa
        except AttributeError:
            return super()._list_images__get_os_distro(image)
        return os_distro

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('minDisk'))
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _list_images__get_min_memory_size(self, image):
        try:
            min_memory_size = int(image.extra.get('minRam'))
        except (TypeError, ValueError):
            return None
        return min_memory_size


class SoftLayerComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.SOFTLAYER)(self.cloud.username,
                                              self.cloud.apikey.value)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        try:
            created_at = node_dict['extra']['created']
        except KeyError:
            return None

        try:
            created_at = iso8601.parse_date(created_at)
        except iso8601.ParseError as exc:
            log.error(str(exc))
            return created_at

        created_at = pytz.UTC.normalize(created_at)
        return created_at

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        os_type = 'linux'
        if 'windows' in str(
                node_dict['extra'].get('image', '')).lower():
            os_type = 'windows'
        if os_type != machine.os_type:
            machine.os_type = os_type
            updated = True

        # Get number of vCPUs for bare metal and cloud servers, respectively.
        if 'cpu' in node_dict['extra'] and \
                node_dict['extra'].get('cpu') != machine.extra.get(
                    'cpus'):
            machine.extra['cpus'] = node_dict['extra'].get['cpu']
            updated = True
        elif 'maxCpu' in node_dict.extra and \
                machine.extra['cpus'] != node_dict['extra']['maxCpu']:
            machine.extra['cpus'] = node_dict['extra']['maxCpu']
            updated = True
        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        # SoftLayer includes recurringFee on the VM metadata but
        # this is only for the compute - CPU pricing.
        # Other costs (ram, bandwidth, image) are included
        # on billingItemChildren.

        extra_fee = 0
        if not node_dict['extra'].get('hourlyRecurringFee'):
            cpu_fee = float(node_dict['extra'].get('recurringFee'))
            for item in node_dict['extra'].get('billingItemChildren',
                                               ()):
                # don't calculate billing that is cancelled
                if not item.get('cancellationDate'):
                    extra_fee += float(item.get('recurringFee'))
            return 0, cpu_fee + extra_fee
        else:
            # node_dict['extra'].get('recurringFee')
            # here will show what it has cost for the current month, up to now.
            cpu_fee = float(
                node_dict['extra'].get('hourlyRecurringFee'))
            for item in node_dict['extra'].get('billingItemChildren',
                                               ()):
                # don't calculate billing that is cancelled
                if not item.get('cancellationDate'):
                    extra_fee += float(item.get('hourlyRecurringFee'))

            return cpu_fee + extra_fee, 0

    def _list_machines__get_location(self, node):
        return node['extra'].get('datacenter')

    def _reboot_machine(self, machine, node):
        self.connection.reboot_node(node)
        return True

    def _destroy_machine(self, machine, node):
        self.connection.destroy_node(node)

    def _parse_networks_from_request(self, auth_context, networks_dict):
        ret_networks = {}
        vlan = networks_dict.get('vlan')
        if vlan:
            ret_networks['vlan'] = vlan
        return ret_networks

    def _parse_extra_from_request(self, extra, plan):
        plan['metal'] = extra.get('metal', False)
        plan['hourly'] = extra.get('hourly', False)

    def _post_parse_plan(self, plan):
        machine_name = plan.get('machine_name')
        if '.' in machine_name:
            plan['domain'] = '.'.join(machine_name.split('.')[1:])
            plan['machine_name'] = machine_name.split('.')[0]


class AzureComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        tmp_cert_file = tempfile.NamedTemporaryFile(delete=False)
        tmp_cert_file.write(self.cloud.certificate.value.encode())
        tmp_cert_file.close()
        return get_driver(Provider.AZURE)(self.cloud.subscription_id.value,
                                          tmp_cert_file.name)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        os_type = node_dict['extra'].get('os_type', 'linux')
        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True
        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        if node_dict['state'] not in [NodeState.RUNNING.value,
                                      NodeState.PAUSED.value]:
            return 0, 0
        return node_dict['extra'].get('cost_per_hour', 0), 0

    def _list_images__fetch_images(self, search=None):
        images = self.connection.list_images()
        images = [image for image in images
                  if 'RightImage' not in image.name and
                  'Barracude' not in image.name and
                  'BizTalk' not in image.name]
        # There are many builds for some images eg Ubuntu.
        # All have the same name!
        images_dict = {}
        for image in images:
            if image.name not in images_dict:
                images_dict[image.name] = image
        return list(images_dict.values())

    def _cloud_service(self, node_id):
        """
        Azure libcloud driver needs the cloud service
        specified as well as the node
        """
        cloud_service = self.connection.get_cloud_service_from_node_id(
            node_id)
        return cloud_service

    def _get_libcloud_node(self, machine, no_fail=False):
        cloud_service = self._cloud_service(machine.external_id)
        for node in self.connection.list_nodes(
                ex_cloud_service_name=cloud_service):
            if node.id == machine.external_id:
                return node
            if no_fail:
                return Node(machine.external_id, name=machine.external_id,
                            state=0, public_ips=[], private_ips=[],
                            driver=self.connection)
            raise MachineNotFoundError("Machine with id '%s'." %
                                       machine.external_id)

    def _start_machine(self, machine, node):
        cloud_service = self._cloud_service(machine.external_id)
        return self.connection.ex_start_node(
            node, ex_cloud_service_name=cloud_service)

    def _stop_machine(self, machine, node):
        cloud_service = self._cloud_service(machine.external_id)
        return self.connection.ex_stop_node(
            node, ex_cloud_service_name=cloud_service)

    def _reboot_machine(self, machine, node):
        cloud_service = self._cloud_service(machine.external_id)
        return self.connection.reboot_node(
            node, ex_cloud_service_name=cloud_service)

    def _destroy_machine(self, machine, node):
        cloud_service = self._cloud_service(machine.external_id)
        return self.connection.destroy_node(
            node, ex_cloud_service_name=cloud_service)

    def _list_machines__machine_actions(self, machine, node_dict):
        super(AzureComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        if node_dict['state'] is NodeState.PAUSED.value:
            machine.actions.start = True


class AzureArmComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.AZURE_ARM)(self.cloud.tenant_id,
                                              self.cloud.subscription_id,
                                              self.cloud.key,
                                              self.cloud.secret.value)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        os_type = node_dict['extra'].get('os_type', 'linux')
        if os_type != machine.os_type:
            machine.os_type = os_type
            updated = True

        subnet = node_dict['extra'].get('subnet')
        if subnet:
            network_id = subnet.split('/subnets')[0]
            from mist.api.networks.models import Network
            try:
                network = Network.objects.get(cloud=self.cloud,
                                              external_id=network_id,
                                              missing_since=None)
                if network != machine.network:
                    machine.network = network
                    updated = True
            except me.DoesNotExist:
                pass

        network_id = machine.network.external_id if machine.network else ''
        if machine.extra.get('network') != network_id:
            machine.extra['network'] = network_id
            updated = True

        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        if node_dict['state'] not in [NodeState.RUNNING.value,
                                      NodeState.PAUSED.value]:
            return 0, 0
        return node_dict['extra'].get('cost_per_hour', 0), 0

    def _list_machines__machine_actions(self, machine, node_dict):
        super(AzureArmComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        if node_dict['state'] is NodeState.PAUSED.value:
            machine.actions.start = True

    def _list_machines__get_location(self, node):
        return node['extra'].get('location')

    def _list_machines__get_size(self, node):
        return node['extra'].get('size')

    def _list_images__fetch_images(self, search=None):
        images_file = os.path.join(config.MIST_API_DIR,
                                   config.AZURE_IMAGES_FILE)
        with open(images_file, 'r') as f:
            default_images = json.load(f)
        images = [NodeImage(id=image, name=name,
                            driver=self.connection, extra={})
                  for image, name in list(default_images.items())]
        return images

    def _reboot_machine(self, machine, node):
        self.connection.reboot_node(node)

    def _destroy_machine(self, machine, node):
        self.connection.destroy_node(node)

    def _list_sizes__fetch_sizes(self):
        location = self.connection.list_locations()[0]
        return self.connection.list_sizes(location)

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('numberOfCores')

    def _list_sizes__get_name(self, size):
        return size.name + ' ' + str(size.extra['numberOfCores']) \
                         + ' cpus/' + str(size.ram / 1024) + 'GB RAM/ ' \
                         + str(size.disk) + 'GB SSD'

    def _list_locations__get_available_sizes(self, location):
        libcloud_size_ids = [size.id
                          for size in self.connection.list_sizes(location=location)]  # noqa

        from mist.api.clouds.models import CloudSize

        return CloudSize.objects(cloud=self.cloud,
                                 external_id__in=libcloud_size_ids)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        # workaround to avoid overwriting creation time
        # as Azure updates it when a machine stops, reboots etc.

        if machine.created is not None:
            return machine.created

        return super()._list_machines__machine_creation_date(machine,
                                                             node_dict)

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        return networks_dict.get('network')

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size parameter is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')

        if size < 1:
            raise BadRequestError('Volume size should be at least 1 GB')

        try:
            name = volume_dict['name']
        except KeyError:
            raise BadRequestError('Volume name parameter is required')

        storage_account_type = volume_dict.get('storage_account_type',
                                               'StandardSSD_LRS')
        # https://docs.microsoft.com/en-us/rest/api/compute/virtual-machines/create-or-update#storageaccounttypes  # noqa
        if storage_account_type not in {'Premium_LRS',
                                        'Premium_ZRS',
                                        'StandardSSD_LRS',
                                        'Standard_LRS',
                                        'StandardSSD_ZRS',
                                        'UltraSSD_LRS'}:
            raise BadRequestError('Invalid storage account type for volume')

        caching_type = volume_dict.get('caching_type', 'None')
        if caching_type not in {'None',
                                'ReadOnly',
                                'ReadWrite',
                                }:
            raise BadRequestError('Invalid caching type')

        return {
            'name': name,
            'size': size,
            'storage_account_type': storage_account_type,
            'caching_type': caching_type,
        }

    def _generate_plan__parse_extra(self, extra, plan):
        from mist.api.clouds.models import CloudLocation

        location = CloudLocation.objects.get(
            id=plan['location']['id'], cloud=self.cloud)

        resource_group_name = extra.get('resource_group') or 'mist'
        if not re.match(r'^[-\w\._\(\)]+$', resource_group_name):
            raise BadRequestError('Invalid resource group name')

        resource_group_exists = self.connection.ex_resource_group_exists(
            resource_group_name)
        plan['resource_group'] = {
            'name': resource_group_name,
            'exists': resource_group_exists
        }

        storage_account_type = extra.get('storage_account_type',
                                         'StandardSSD_LRS')
        # https://docs.microsoft.com/en-us/rest/api/compute/virtual-machines/create-or-update#storageaccounttypes    # noqa
        if storage_account_type not in {'Premium_LRS',
                                        'Premium_ZRS',
                                        'StandardSSD_LRS',
                                        'StandardSSD_ZRS',
                                        'Standard_LRS'}:
            raise BadRequestError('Invalid storage account type for OS disk')
        plan['storage_account_type'] = storage_account_type

        plan['user'] = extra.get('user') or 'azureuser'
        if extra.get('password'):
            if validate_password(extra['password']) is False:
                raise BadRequestError(
                    'Password  must be between 8-123 characters long and '
                    'contain: an uppercase character, a lowercase character'
                    ' and a numeric digit')
            plan['password'] = extra['password']

    def _generate_plan__post_parse_plan(self, plan):
        from mist.api.images.models import CloudImage
        from mist.api.clouds.models import CloudLocation

        location = CloudLocation.objects.get(
            id=plan['location']['id'], cloud=self.cloud)
        image = CloudImage.objects.get(
            id=plan['image']['id'], cloud=self.cloud)

        if image.os_type == 'windows':
            plan.pop('key', None)
            if plan.get('password') is None:
                raise BadRequestError('Password is required on Windows images')

        if image.os_type == 'linux':
            # we don't use password in linux images
            # so don't return it in plan
            plan.pop('password', None)
            if plan.get('key') is None:
                raise BadRequestError('Key is required on Unix-like images')

        try:
            network_name = plan.pop('networks')
        except KeyError:
            if plan['resource_group']['name'] == 'mist':
                network_name = (f'mist-{location.external_id}')
            else:
                network_name = (f"mist-{plan['resource_group']['name']}"
                                f"-{location.external_id}")

        if plan['resource_group']['exists'] is True:
            try:
                network = self.connection.ex_get_network(
                    network_name,
                    plan['resource_group']['name'])
            except BaseHTTPError as exc:
                if exc.code == 404:
                    # network doesn't exist so we'll have to create it
                    network_exists = False
                else:
                    # TODO Consider what to raise on other status codes
                    raise BadRequestError(exc)
            else:
                # make sure network is in the same location
                if network.location != location.external_id:
                    raise BadRequestError(
                        'Network is in a different location'
                        ' from the one given')
                network_exists = True
        else:
            network_exists = False
        plan['networks'] = {
            'name': network_name,
            'exists': network_exists
        }

    def _create_machine__get_image_object(self, image):
        from mist.api.images.models import CloudImage
        from libcloud.compute.drivers.azure_arm import AzureImage
        cloud_image = CloudImage.objects.get(id=image)

        publisher, offer, sku, version = cloud_image.external_id.split(':')
        image_obj = AzureImage(version, sku, offer, publisher, None, None)
        return image_obj

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        kwargs['ex_user_name'] = plan['user']
        kwargs['ex_use_managed_disks'] = True
        kwargs['ex_storage_account_type'] = plan['storage_account_type']
        kwargs['ex_customdata'] = plan.get('cloudinit', '')

        key = kwargs.pop('auth', None)
        if key:
            kwargs['auth'] = NodeAuthSSHKey(key.public)
        else:
            kwargs['auth'] = NodeAuthPassword(plan['password'])

        if plan['resource_group']['exists'] is False:
            try:
                self.connection.ex_create_resource_group(
                    plan['resource_group']['name'], kwargs['location'])
            except BaseHTTPError as exc:
                raise MachineCreationError(
                    'Could not create resource group: %s' % exc)
            # add delay because sometimes the resource group is not yet ready
            time.sleep(5)
        kwargs['ex_resource_group'] = plan['resource_group']['name']

        if plan['networks']['exists'] is False:
            try:
                security_group = self.connection.ex_create_network_security_group(  # noqa
                    plan['networks']['name'],
                    kwargs['ex_resource_group'],
                    location=kwargs['location'],
                    securityRules=config.AZURE_SECURITY_RULES
                )
            except BaseHTTPError as exc:
                raise MachineCreationError(
                    'Could not create security group: %s' % exc)

            # add delay because sometimes the security group is not yet ready
            time.sleep(3)

            try:
                network = self.connection.ex_create_network(
                    plan['networks']['name'],
                    kwargs['ex_resource_group'],
                    location=kwargs['location'],
                    networkSecurityGroup=security_group.id)
            except BaseHTTPError as exc:
                raise MachineCreationError(
                    'Could not create network: %s' % exc)
            time.sleep(3)
        else:
            try:
                network = self.connection.ex_get_network(
                    plan['networks']['name'],
                    kwargs['ex_resource_group'],
                )
            except BaseHTTPError as exc:
                raise MachineCreationError(
                    'Could not fetch network: %s' % exc)

        try:
            subnet = self.connection.ex_list_subnets(network)[0]
        except BaseHTTPError as exc:
            raise MachineCreationError(
                'Could not create network: %s' % exc)

        # avoid naming collisions when nic/ip with the same name exists
        temp_name = f"{kwargs['name']}-{secrets.token_hex(3)}"
        try:
            ip = self.connection.ex_create_public_ip(
                temp_name,
                kwargs['ex_resource_group'],
                kwargs['location'])
        except BaseHTTPError as exc:
            raise MachineCreationError('Could not create new ip: %s' % exc)

        try:
            nic = self.connection.ex_create_network_interface(
                temp_name,
                subnet,
                kwargs['ex_resource_group'],
                location=kwargs['location'],
                public_ip=ip)
        except Exception as exc:
            raise MachineCreationError(
                'Could not create network interface: %s' % exc)
        kwargs['ex_nic'] = nic

        data_disks = []
        for volume in plan.get('volumes', []):
            if volume.get('id'):
                from mist.api.volumes.models import Volume
                try:
                    mist_vol = Volume.objects.get(id=volume['id'])
                except me.DoesNotExist:
                    continue
                data_disks.append({'id': mist_vol.external_id})
            else:
                data_disks.append({
                    'name': volume['name'],
                    'size': volume['size'],
                    'storage_account_type': volume['storage_account_type'],
                    'host_caching': volume['caching_type'],
                })
        if data_disks:
            kwargs['ex_data_disks'] = data_disks
        return kwargs


class GoogleComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.GCE)(self.cloud.email,
                                        self.cloud.private_key.value,
                                        project=self.cloud.project_id)

    def _list_machines__get_machine_extra(self, machine, node_dict):
        # FIXME: we delete the extra.metadata for now because it can be
        # > 40kb per machine on GCE clouds with enabled GKE, causing the
        # websocket to overload and hang and is also a security concern.
        # We should revisit this and see if there is some use for this
        # metadata and if there are other fields that should be filtered
        # as well

        extra = copy.copy(node_dict['extra'])

        for key in list(extra.keys()):
            if key in ['metadata']:
                # check for nodepool
                try:
                    kube_labels = extra[key]['items'][3]
                except (IndexError, KeyError):
                    kube_labels = {}
                if kube_labels.get('key', '') == 'kube-labels':
                    # value is a super long string that contains
                    # `,gke-nodepool=xxxx,` among others
                    value = kube_labels.get('value', '')
                    result = re.search('gke-nodepool=', value)
                    if result:
                        index = result.span()[1]
                        nodepool_name = value[index:]
                        # remove anything after first ,
                        nodepool_name = nodepool_name[:nodepool_name.find(',')]
                        extra['nodepool'] = nodepool_name
                del extra[key]
        for disk in extra.get('disks', []):
            disk.pop('shieldedInstanceInitialState', None)
            disk.pop('source', None)
            disk.pop('licenses', None)
        return extra

    def _list_machines__machine_creation_date(self, machine, node_dict):
        try:
            created_at = node_dict['extra']['creationTimestamp']
        except KeyError:
            return None

        try:
            created_at = iso8601.parse_date(created_at)
        except iso8601.ParseError as exc:
            log.error(str(exc))
            return created_at

        created_at = pytz.UTC.normalize(created_at)
        return created_at

    def _list_machines__get_custom_size(self, node):
        machine_type = node['extra'].get('machineType', "").split("/")[-1]
        size = self.connection.ex_get_size(machine_type,
                                           node['extra']['zone'].get('name'))
        # create object only if the size of the node is custom
        if size.name.startswith('custom'):
            # FIXME: resolve circular import issues
            from mist.api.clouds.models import CloudSize
            _size = CloudSize(cloud=self.cloud, external_id=size.id)
            _size.ram = size.ram
            _size.cpus = size.extra.get('guestCpus')
            _size.name = size.name
            _size.save()
            return _size

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        extra = node_dict['extra']

        # Wrap in try/except to prevent from future GCE API changes.
        # Identify server OS.
        os_type = 'linux'
        extra_os_type = None

        try:
            license = extra.get('license')
            if license:
                if 'sles' in license:
                    extra_os_type = 'sles'
                if 'rhel' in license:
                    extra_os_type = 'rhel'
                if 'win' in license:
                    extra_os_type = 'win'
                    os_type = 'windows'
            if extra.get('disks') and extra['disks'][0].get('licenses') and \
                    'windows-cloud' in extra['disks'][0]['licenses'][0]:
                os_type = 'windows'
                extra_os_type = 'win'
            if extra_os_type and machine.extra.get('os_type') != extra_os_type:
                machine.extra['os_type'] = extra_os_type
                updated = True
            if machine.os_type != os_type:
                machine.os_type = os_type
                updated = True
        except:
            log.exception("Couldn't parse os_type for machine %s:%s for %s",
                          machine.id, machine.name, self.cloud)

        # Get disk metadata.
        try:
            if extra.get('boot_disk'):
                if machine.extra.get('boot_disk_size') != extra[
                        'boot_disk'].get('size'):
                    machine.extra['boot_disk_size'] = extra['boot_disk'].get(
                        'size')
                    updated = True
                if machine.extra.get('boot_disk_type') != extra[
                        'boot_disk'].get('extra', {}).get('type'):
                    machine.extra['boot_disk_type'] = extra[
                        'boot_disk'].get('extra', {}).get('type')
                    updated = True
                if machine.extra.get('boot_disk'):
                    machine.extra.pop('boot_disk')
                    updated = True
        except:
            log.exception("Couldn't parse disk for machine %s:%s for %s",
                          machine.id, machine.name, self.cloud)

        # Get zone name.
        try:
            if extra.get('zone'):
                if machine.extra.get('zone') != extra.get('zone',
                                                          {}).get('name'):
                    machine.extra['zone'] = extra.get('zone', {}).get('name')
                    updated = True
        except:
            log.exception("Couldn't parse zone for machine %s:%s for %s",
                          machine.id, machine.name, self.cloud)

        # Get machine type.
        try:
            if extra.get('machineType'):
                machine_type = extra['machineType'].split('/')[-1]
                if machine.extra.get('machine_type') != machine_type:
                    machine.extra['machine_type'] = machine_type
                    updated = True
        except:
            log.exception("Couldn't parse machine type "
                          "for machine %s:%s for %s",
                          machine.id, machine.name, self.cloud)

        network_interface = node_dict['extra'].get(
            'networkInterfaces')[0]
        network = network_interface.get('network')
        network_name = network.split('/')[-1]
        if machine.extra.get('network') != network_name:
            machine.extra['network'] = network_name
            updated = True

        # Discover network of machine.
        from mist.api.networks.models import Network
        try:
            network = Network.objects.get(cloud=self.cloud,
                                          name=network_name,
                                          missing_since=None)
        except Network.DoesNotExist:
            network = None

        if machine.network != network:
            machine.network = network
            updated = True

        subnet = network_interface.get('subnetwork')
        if subnet:
            subnet_name = subnet.split('/')[-1]
            subnet_region = subnet.split('/')[-3]
            if machine.extra.get('subnet') != (subnet_name, subnet_region):
                machine.extra['subnet'] = (subnet_name, subnet_region)
                updated = True
            # Discover subnet of machine.
            from mist.api.networks.models import Subnet
            try:
                subnet = Subnet.objects.get(name=subnet_name,
                                            network=machine.network,
                                            region=subnet_region,
                                            missing_since=None)
            except Subnet.DoesNotExist:
                subnet = None
            if subnet != machine.subnet:
                machine.subnet = subnet
                updated = True

            return updated

    def _list_machines__machine_actions(self, machine, node_dict):
        super(GoogleComputeController,
              self)._list_machines__machine_actions(machine, node_dict)
        machine.actions.resize = True

    def _list_images__fetch_images(self, search=None):
        images = self.connection.list_images()
        # GCE has some objects in extra so we make sure they are not passed.
        for image in images:
            image.extra.pop('licenses', None)
        return images

    def _list_machines__cost_machine(self, machine, node_dict):
        if node_dict['state'] == NodeState.STOPPED.value or not machine.size:
            return 0, 0
        # eg n1-standard-1 (1 vCPU, 3.75 GB RAM)
        machine_cpu = float(machine.size.cpus)
        machine_ram = float(machine.size.ram) / 1024
        size_type = machine.size.name.split(" ")[0][:2]
        if "custom" in machine.size.name:
            size_type += "_custom"
            if machine.size.name.startswith('custom'):
                size_type = 'n1_custom'
        usage_type = "on_demand"
        if "preemptible" in machine.size.name.lower():
            usage_type = "preemptible"
        if "1yr" in machine.size.name.lower():
            usage_type = '1yr_commitment'
        if "3yr" in machine.size.name.lower():
            usage_type = '3yr_commitment'
        default_location = "us-central1"
        location = node_dict['extra'].get('zone', {}).get('name')
        # could be europe-west1-d, we want europe-west1
        location = '-'.join(location.split('-')[:2])
        disk_type = machine.extra.get('boot_disk_type') or \
            node_dict['extra'].get('boot_disk',
                                   {}).get('extra',
                                           {}).get('type')
        disk_usage_type = "on_demand"
        disk_size = 0
        for disk in machine.extra['disks']:
            disk_size += float(disk['diskSizeGb'])
        if 'regional' in disk_type:
            if 'standard' in disk_type:
                disk_type = 'Regional Standard'
            elif 'ssd' in disk_type:
                disk_type = 'Regional SSD'
        elif 'local' in disk_type:
            if 'preemptible' in disk_type:
                disk_usage_type = 'preemptible'
            elif '1yr' in disk_type:
                disk_usage_type = '1yr_commitment'
            elif '3yr' in disk_type:
                disk_usage_type = '3yr_commitment'
            disk_type = 'Local SSD'
        elif 'standard' in disk_type:
            disk_type = 'Standard'
        elif 'ssd' in disk_type:
            disk_type = 'SSD'

        disk_prices = get_pricing(driver_type='compute',
                                  driver_name='gce_disks').get(disk_type, {})
        gce_instance = get_pricing(driver_type='compute',
                                   driver_name='gce_instances').get(
                                       size_type, {})
        cpu_price = 0
        ram_price = 0
        os_price = 0
        disk_price = 0
        if disk_prices:
            try:
                disk_price = disk_prices[disk_usage_type][
                    location].get('price', 0)
            except KeyError:
                disk_price = disk_prices[disk_usage_type][
                    default_location].get('price', 0)
        if gce_instance:
            try:
                cpu_price = gce_instance['cpu'][usage_type][
                    location].get('price', 0)
            except KeyError:
                cpu_price = gce_instance['cpu'][usage_type][
                    default_location].get('price', 0)
            if size_type not in {'f1', 'g1'}:
                try:
                    ram_price = gce_instance['ram'][usage_type][
                        location].get('price', 0)
                except KeyError:
                    ram_price = gce_instance['ram'][usage_type][
                        default_location].get('price', 0)
            ram_instance = None
            if (size_type == "n1" and machine_cpu > 0 and
               machine_ram / machine_cpu > 6.5):
                size_type += "_extended"
                ram_instance = get_size_price(driver_type='compute',
                                              driver_name='gce_instances',
                                              size_id=size_type)
            if (size_type == "n2" and machine_cpu > 0 and
               machine_ram / machine_cpu > 8):
                size_type += "_extended"
                ram_instance = get_size_price(driver_type='compute',
                                              driver_name='gce_instances',
                                              size_id=size_type)
            if (size_type == "n2d" and machine_cpu > 0 and
               machine_ram / machine_cpu > 8):
                size_type += "_extended"
                ram_instance = get_size_price(driver_type='compute',
                                              driver_name='gce_instances',
                                              size_id=size_type)
            if ram_instance:
                try:
                    ram_price = ram_instance['ram'][
                        usage_type][location].get('price', 0)
                except KeyError:
                    ram_price = ram_instance['ram'][
                        usage_type][default_location].get('price', 0)
        image_name = machine.image.name if machine.image \
            else machine.extra.get('image', '')

        os_price = get_gce_image_price(image_name=image_name,
                                       size_name=machine.size.name,
                                       cores=machine_cpu)

        total_price = (machine_cpu * cpu_price + machine_ram *
                       ram_price + os_price + disk_price * disk_size)
        return total_price, 0

    def _list_machines__get_location(self, node_dict):
        return node_dict['extra'].get('zone', {}).get('id')

    def _list_machines__get_machine_cluster(self, machine, node):
        try:
            metadata = node['extra']['metadata']['items']
        except KeyError:
            return None

        for item in metadata:
            if item.get('key') == 'cluster-uid':
                cluster_id = item.get('value')
                break
        else:
            return None

        from mist.api.containers.models import Cluster
        cluster = None
        try:
            cluster = Cluster.objects.get(external_id=cluster_id,
                                          cloud=self.cloud,
                                          missing_since=None)
        except Cluster.DoesNotExist as exc:
            log.warn('Error getting cluster of %s: %r', machine, exc)

        return cluster

    def _list_sizes__get_name(self, size):
        return "%s (%s)" % (size.name, size.extra.get('description'))

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('guestCpus')

    def _list_sizes__get_extra(self, size):
        extra = {}
        description = size.extra.get('description', '')
        if description:
            extra.update({'description': description})
        if size.price:
            extra.update({'price': size.price})
        extra['accelerators'] = size.extra.get('accelerators', [])
        extra['isSharedCpu'] = size.extra.get('isSharedCpu')
        return extra

    def _list_locations__fetch_locations(self):
        regions = self.connection.region_list
        zones = self.connection.zone_list
        # use only the region's slug instead of a GCE url
        for zone in zones:
            try:
                zone.extra['region'] = zone.extra['region'].split('/')[-1]
            except (KeyError, AttributeError):
                zone.extra['region'] = None
            zone.extra['acceleratorTypes'] = (
                self.connection.ex_list_accelerator_types_for_location(zone))

        return regions + zones

    def _list_locations__get_parent(self, location, libcloud_location):
        from libcloud.compute.drivers.gce import GCERegion
        from mist.api.clouds.models import CloudLocation

        if isinstance(libcloud_location, GCERegion):
            return None

        region_name = libcloud_location.extra['region']
        try:
            parent = CloudLocation.objects.get(name=region_name,
                                               missing_since=None,
                                               cloud=self.cloud)
            return parent
        except me.DoesNotExist:
            log.error('Parent does not exist for Location: %s',
                      location.id)
        except me.MultipleObjectsReturned:
            log.error('Multiple parents found for Location: %s',
                      location.id)

    def _list_locations__get_available_sizes(self, location):
        from libcloud.compute.drivers.gce import GCERegion
        if isinstance(location, GCERegion):
            return None
        libcloud_size_ids = [size.id for size
                             in self.connection.list_sizes(location=location)]

        from mist.api.clouds.models import CloudSize

        return CloudSize.objects(cloud=self.cloud,
                                 external_id__in=libcloud_size_ids)

    def _list_locations__get_type(self, location, libcloud_location):
        from libcloud.compute.drivers.gce import GCERegion
        if isinstance(libcloud_location, GCERegion):
            return 'region'
        return 'zone'

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('diskSizeGb'))
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _resize_machine(self, machine, node, node_size, kwargs):
        # instance must be in stopped mode
        if node.state != NodeState.STOPPED:
            raise BadRequestError('The instance has to be stopped '
                                  'in order to be resized')
        # get size name as returned by libcloud
        machine_type = node_size.name.split(' ')[0]
        try:
            self.connection.ex_set_machine_type(node,
                                                machine_type)
            self.connection.ex_start_node(node)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _generate_plan__parse_networks(self, auth_context, network_dict,
                                       location):

        subnet_search = network_dict.get('subnetwork')
        network_search = network_dict.get('network')
        networks_dict = {}

        from mist.api.methods import list_resources
        network = None
        if network_search:
            try:
                [network], _ = list_resources(auth_context, 'network',
                                              search=network_search,
                                              cloud=self.cloud.id,
                                              limit=1)
            except ValueError:
                raise NotFoundError('Network does not exist')

            networks_dict['network'] = network.name
        else:
            networks_dict['network'] = 'default'

        if subnet_search:
            subnets, _ = list_resources(auth_context, 'subnet',
                                        search=subnet_search,
                                        limit=1)
            if network:
                subnets.filter(network=network)
            else:
                subnets = [subnet for subnet in subnets
                           if subnet.network.cloud == self.cloud]
            if len(subnets) == 0:
                raise NotFoundError('Subnet not found %s' % subnet_search)

            networks_dict['subnet'] = subnets[0].name

        return networks_dict

    def _generate_plan__parse_key(self, auth_context, key_obj):
        key, _ = super()._generate_plan__parse_key(auth_context, key_obj)

        # extract ssh user from key param
        try:
            ssh_user = key_obj.get('user') or 'user'
        except AttributeError:
            # key_obj is a string
            ssh_user = 'user'

        if not isinstance(ssh_user, str):
            raise BadRequestError('Invalid type for user')

        extra_attrs = {
            'user': ssh_user,
        }
        return key, extra_attrs

    def _generate_plan__parse_size(self, auth_context, size_obj):
        sizes, _ = super()._generate_plan__parse_size(auth_context, size_obj)
        extra_attrs = None

        try:
            accelerators = size_obj.get('accelerators')
        except AttributeError:
            # size_obj is a string
            accelerators = None

        if accelerators:
            try:
                accelerator_type = accelerators['accelerator_type']
                accelerator_count = accelerators['accelerator_count']
            except KeyError:
                raise BadRequestError(
                    'Both accelerator_type and accelerator_count'
                    ' are required')
            except TypeError:
                raise BadRequestError('Invalid type for accelerators')

            if not isinstance(accelerator_count, int):
                raise BadRequestError('Invalid type for accelerator_count')

            if accelerator_count <= 0:
                raise BadRequestError('Invalid value for accelerator_type')

            # accelerators are currently supported only on N1 sizes
            # https://cloud.google.com/compute/docs/gpus#introduction
            sizes = [size for size in sizes
                     if size.name.startswith('n1') and
                     size.extra.get('isSharedCpu') is False]

            extra_attrs = {
                'accelerator_type': accelerator_type,
                'accelerator_count': accelerator_count,
            }

        return sizes, extra_attrs

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        ret_dict = {
            'id': vol_obj.id,
            'name': vol_obj.name
        }

        boot = volume_dict.get('boot')
        if boot is True:
            ret_dict['boot'] = boot

        return ret_dict

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size parameter is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')

        if size < 1:
            raise BadRequestError('Volume size should be at least 1 GB')

        boot = volume_dict.get('boot')
        name = None
        try:
            name = str(volume_dict['name'])
        except KeyError:
            # name is not required in boot volume
            if boot is not True:
                raise BadRequestError('Volume name parameter is required')

        volume_type = volume_dict.get('type', 'pd-standard')
        if volume_type not in ('pd-standard', 'pd-ssd'):
            raise BadRequestError(
                'Invalid value for volume type, valid values are: '
                'pd-standard, pd-ssd'
            )

        ret_dict = {
            'size': size,
            'type': volume_type
        }
        # boot volumes use machine's name
        if name and boot is not True:
            ret_dict['name'] = name

        if boot is True:
            ret_dict['boot'] = boot

        return ret_dict

    def _get_allowed_image_size_location_combinations(self,
                                                      images,
                                                      locations,
                                                      sizes,
                                                      image_extra_attrs,
                                                      size_extra_attrs):
        # pre-filter locations based on selected accelerator type availability
        size_extra_attrs = size_extra_attrs or {}
        accelerator_type = size_extra_attrs.get('accelerator_type')
        accelerator_count = size_extra_attrs.get('accelerator_count')
        if accelerator_type and accelerator_count:
            filtered_locations = []
            for location in locations:
                try:
                    max_accelerators = \
                        location.extra['acceleratorTypes'][accelerator_type]
                except (KeyError, TypeError):
                    continue

                # check if location supports these many accelerators
                if max_accelerators >= accelerator_count:
                    filtered_locations.append(location)

            locations = filtered_locations

        return super()._get_allowed_image_size_location_combinations(
            images, locations, sizes,
            image_extra_attrs,
            size_extra_attrs)

    def _generate_plan__parse_extra(self, extra, plan) -> None:
        try:
            service_account = extra['service_account']
        except KeyError:
            return

        if not isinstance(service_account, dict):
            raise BadRequestError(
                'Invalid type for service account parameter')

        # use the default service account & scopes if one of the values
        # is not provided
        email = service_account.get('email') or 'default'
        scopes = service_account.get('scopes') or ['devstorage.read_only']

        if not isinstance(email, str) or not isinstance(scopes, list):
            raise BadRequestError(
                'Invalid type for service_account email/scopes parameter')

        plan['service_account'] = {
            'email': email,
            'scopes': scopes
        }

    def _generate_plan__post_parse_plan(self, plan):
        from mist.api.images.models import CloudImage
        image = CloudImage.objects.get(id=plan['image']['id'])

        try:
            image_min_size = int(image.min_disk_size)
        except TypeError:
            image_min_size = 10

        volumes = plan.get('volumes', [])
        # make sure boot drive is first if it exists
        volumes.sort(key=lambda k: k.get('boot') or False,
                     reverse=True)

        if len(volumes) > 1:
            # make sure only one boot volume is set
            if volumes[1].get('boot') is True:
                raise BadRequestError('Up to 1 volume must be set as boot')

        if len(volumes) == 0 or volumes[0].get('boot') is not True:
            boot_volume = {
                'size': image_min_size,
                'type': 'pd-standard',
                'boot': True,
            }
            volumes.insert(0, boot_volume)

        boot_volume = volumes[0]
        if boot_volume.get('size') and boot_volume['size'] < image_min_size:
            raise BadRequestError(f'Boot volume must be '
                                  f'at least {image_min_size} GBs '
                                  f'for image: {image.name}')
        elif boot_volume.get('id'):
            from mist.api.volumes.models import Volume
            vol = Volume.objects.get(id=boot_volume['id'])
            if vol.size < image_min_size:
                raise BadRequestError(f'Boot volume must be '
                                      f'at least {image_min_size} GBs '
                                      f'for image: {image.name}')

        plan['volumes'] = volumes

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        key = kwargs.pop('auth')
        username = plan.get('key', {}).get('user') or 'user'
        metadata = {
            'sshKeys': '%s:%s' % (username, key.public)
        }
        if plan.get('cloudinit'):
            metadata['user-data'] = plan['cloudinit']
        kwargs['ex_metadata'] = metadata

        boot_volume = plan['volumes'].pop(0)
        if boot_volume.get('id'):
            from mist.api.volumes.models import Volume
            from libcloud.compute.base import StorageVolume
            vol = Volume.objects.get(id=boot_volume['id'])
            libcloud_vol = StorageVolume(id=vol.external_id,
                                         name=vol.name,
                                         size=vol.size,
                                         driver=self.connection,
                                         extra=vol.extra)
            kwargs['ex_boot_disk'] = libcloud_vol
        else:
            kwargs['disk_size'] = boot_volume.get('size')
            kwargs['ex_disk_type'] = boot_volume.get('type') or 'pd-standard'

        kwargs['ex_network'] = plan['networks'].get('network')
        kwargs['ex_subnetwork'] = plan['networks'].get('subnet')

        if plan['size'].get('accelerator_type'):
            kwargs['ex_accelerator_type'] = plan['size']['accelerator_type']
            kwargs['ex_accelerator_count'] = plan['size']['accelerator_count']
            # required when attaching accelerators to an instance
            kwargs['ex_on_host_maintenance'] = 'TERMINATE'

        if plan.get('service_account'):
            kwargs['ex_service_accounts'] = [plan['service_account']]
        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        from mist.api.volumes.models import Volume
        from libcloud.compute.base import StorageVolume
        location = kwargs['location']
        volumes = plan['volumes']
        for volume in volumes:
            if volume.get('id'):
                vol = Volume.objects.get(id=volume['id'])
                libcloud_vol = StorageVolume(id=vol.external_id,
                                             name=vol.name,
                                             size=vol.size,
                                             driver=self.connection,
                                             extra=vol.extra)
                try:
                    self.connection.attach_volume(node, libcloud_vol)
                except Exception as exc:
                    log.exception('Attaching volume failed')
            else:
                try:
                    size = volume['size']
                    name = volume['name']
                    volume_type = volume.get('type') or 'pd-standard'
                except KeyError:
                    log.exception('Missing required volume parameter')
                    continue
                try:
                    libcloud_vol = self.connection.create_volume(
                        size,
                        name,
                        location=location,
                        ex_disk_type=volume_type)
                except Exception as exc:
                    log.exception('Failed to create volume')
                    continue
                try:
                    self.connection.attach_volume(node, libcloud_vol)
                except Exception as exc:
                    log.exception('Attaching volume failed')

    def _create_machine__get_size_object(self, size):
        # when providing a Libcloud NodeSize object
        # gce driver tries to get `selfLink` key of size.extra
        # dictionary. Mist sizes do not save selfLink in extra
        # so a KeyError is thrown. Providing only size id
        # seems to resolve this issue
        size_obj = super()._create_machine__get_size_object(size)
        return size_obj.id

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('family').split('-')[0]
        except AttributeError:
            return super()._list_images__get_os_distro(image)

        # windows sql server
        if os_distro == 'sql':
            os_distro = 'windows'
        return os_distro


class HostVirtualComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.HOSTVIRTUAL)(self.cloud.apikey)


class EquinixMetalComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        project_id = self.cloud.project_id.value if self.cloud.project_id \
            else ''
        return get_driver(
            Provider.EQUINIXMETAL)(self.cloud.apikey.value,
                                   project=project_id)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('created_at')  # iso8601 string

    def _list_machines__cost_machine(self, machine, node_dict):
        size = node_dict['extra'].get('plan')
        from mist.api.clouds.models import CloudSize
        try:
            _size = CloudSize.objects.get(external_id=size, cloud=self.cloud)
        except CloudSize.DoesNotExist:
            # for some sizes, part of the name instead of id is returned
            # eg. t1.small.x86 for size is returned for size with external_id
            # baremetal_0 and name t1.small.x86 - 8192 RAM
            try:
                _size = CloudSize.objects.get(cloud=self.cloud,
                                              name__contains=size)
            except CloudSize.DoesNotExist:
                raise NotFoundError()
        price = _size.extra.get('price', 0.0)
        if machine.extra.get('billing_cycle') == 'hourly':
            return price, 0

    def _list_machines__get_location(self, node_dict):
        return node_dict['extra'].get('facility', {}).get('id', '')

    def _list_machines__get_size(self, node_dict):
        return node_dict['extra'].get('plan')

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('distro').lower()
        except AttributeError:
            return super()._list_images__get_os_distro(image)
        return os_distro

    def _list_sizes__get_cpu(self, size):
        return int(size.extra.get('cpu_cores') or 1)

    def _list_sizes__get_available_locations(self, mist_size):
        from mist.api.clouds.models import CloudLocation
        CloudLocation.objects(
            cloud=self.cloud,
            external_id__in=mist_size.extra.get('regions', [])
        ).update(add_to_set__available_sizes=mist_size)

    def _list_images__get_allowed_sizes(self, mist_image):
        from mist.api.clouds.models import CloudSize
        CloudSize.objects(
            cloud=self.cloud,
            external_id__in=mist_image.extra.get('provisionable_on', [])
        ).update(add_to_set__allowed_images=mist_image)

    def _list_images__get_architecture(self, image):
        ret_list = []
        sizes = image.extra.get('provisionable_on', [])
        if any('arm' in size for size in sizes):
            ret_list.append('arm')
        if any('x86' in size for size in sizes):
            ret_list.append('x86')
        return ret_list or ['x86']

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        try:
            ip_addresses = networks_dict['ip_addresses']
        except KeyError:
            return None
        # one private IPv4 is required
        private_ipv4 = False
        for address in ip_addresses:
            try:
                address_family = address['address_family']
                cidr = address['cidr']
                public = address['public']
            except KeyError:
                raise BadRequestError(
                    'Required parameter missing on ip_addresses'
                )
            if address_family == 4 and public is True:
                private_ipv4 = True
            if address_family not in (4, 6):
                raise BadRequestError(
                    'Valid values for address_family are: 4, 6'
                )
            if address_family == 4 and cidr not in range(28, 33):
                raise BadRequestError(
                    'Invalid value for cidr block'
                )
            if address_family == 6 and cidr not in range(124, 128):
                raise BadRequestError(
                    'Invalid value for cidr block'
                )
            if type(public) != bool:
                raise BadRequestError(
                    'Invalid value for public'
                )
        if private_ipv4 is False:
            raise BadRequestError(
                'A private IPv4 needs to be included in ip_addresses'
            )
        return {'ip_addresses': ip_addresses}

    def _generate_plan__parse_extra(self, extra, plan):
        project_id = extra.get('project_id')
        if not project_id:
            if self.connection.project_id:
                project_id = self.connection.project_id
            else:
                try:
                    project_id = self.connection.projects[0].id
                except IndexError:
                    raise BadRequestError(
                        "You don't have any projects on Equinix Metal"
                    )
        else:
            for project in self.connection.projects:
                if project_id in (project.name, project.id):
                    project_id = project.id
                    break
            else:
                raise BadRequestError(
                    "Project does not exist"
                )
        plan['project_id'] = project_id

    def _create_machine__get_key_object(self, key):
        from libcloud.utils.publickey import get_pubkey_openssh_fingerprint
        key_obj = super()._create_machine__get_key_object(key)
        fingerprint = get_pubkey_openssh_fingerprint(key_obj.public)
        keys = self.connection.list_key_pairs()
        for k in keys:
            if fingerprint == k.fingerprint:
                ssh_keys = [{
                    'label': k.extra['label'],
                    'key': k.public_key
                }]
                break
        else:
            ssh_keys = [{
                'label': f'mistio-{key_obj.name}',
                'key': key_obj.public
            }]
        return ssh_keys

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        kwargs['ex_project_id'] = plan['project_id']
        kwargs['cloud_init'] = plan.get('cloudinit')
        kwargs['ssh_keys'] = kwargs.pop('auth')
        try:
            kwargs['ip_addresses'] = plan['networks']['ip_addresses']
        except (KeyError, TypeError):
            pass
        return kwargs


class VultrComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.VULTR)(self.cloud.apikey.value)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        # do not include ipv6 on public ips
        public_ips = []
        for ip in machine.public_ips:
            if ip and ':' not in ip:
                public_ips.append(ip)
        if machine.public_ips != public_ips:
            machine.public_ips = public_ips
            updated = True
        return updated

    def _list_machines__machine_creation_date(self, machine, node_dict):
        try:
            created_at = node_dict['created_at']
        except KeyError:
            return None

        try:
            created_at = iso8601.parse_date(created_at)
        except iso8601.ParseError as exc:
            log.error(repr(exc))
            return None

        created_at = pytz.UTC.normalize(created_at)
        return created_at

    def _list_machines__cost_machine(self, machine, node_dict):
        from mist.api.clouds.models import CloudSize
        external_id = node_dict.get('size')
        try:
            size_ = CloudSize.objects.get(external_id=external_id,
                                          cloud=self.cloud)
        except CloudSize.DoesNotExist:
            log.error("Machine's size with external_id: %s not found",
                      external_id)
            return 0, 0

        monthly_cost = size_.extra.get('price') or 0

        features = node_dict['extra'].get('features', [])
        if 'auto_backups' in features:
            try:
                monthly_cost += config.VULTR_BACKUP_PRICE_PER_SIZE[
                    size_.external_id]
            except KeyError:
                pass

        if 'ddos_protection' in features:
            # DDOS protection is free on Dedicated Cloud sizes
            # and not supported on Bare Metal sizes
            if size_.extra.get('type') in ('vc2', 'vhf'):
                monthly_cost += config.VULTR_DDOS_PROTECTION_PRICE

        return 0, monthly_cost

    def _list_machines__get_location(self, node_dict):
        return node_dict['extra'].get('location')

    def _list_machines__machine_actions(self, machine, node_dict):
        super()._list_machines__machine_actions(machine, node_dict)
        size = node_dict.get('size', '')
        # Bare metal nodes don't support resize & snapshot
        if size.startswith('vbm'):
            machine.actions.resize = False
        else:
            machine.actions.resize = True

    def _list_sizes__get_name(self, size):
        # Vultr doesn't have names on sizes.
        # We name them after their 9 different size types & their specs.
        # - High Frequency
        # - Cloud Compute
        # - Bare Metal
        # - Dedicated Cloud
        # - High Performance
        # - General Purpose Optimized Cloud
        # - CPU Optimized Cloud
        # - Memory Optimized Cloud
        # - Storage Optimized Cloud
        if size.name.startswith('vc2'):
            type_ = 'Cloud Compute'
        elif size.name.startswith('vdc'):
            type_ = 'Dedicated Cloud'
        elif size.name.startswith('vhf'):
            type_ = 'High Frequency'
        elif size.name.startswith('vbm'):
            type_ = 'Bare Metal'
        elif size.name.startswith('vhp'):
            type_ = 'High Performance'
        elif size.name.startswith('voc-g'):
            type_ = 'General Purpose Optimized Cloud'
        elif size.name.startswith('voc-c'):
            type_ = 'CPU Optimized Cloud'
        elif size.name.startswith('voc-m'):
            type_ = 'Memory Optimized Cloud'
        elif size.name.startswith('voc-s'):
            type_ = 'Storage Optimized Cloud'
        else:
            log.warning('Unknown Vultr size id: %s', size.id)
            type_ = 'Unknown'
        cpus = self._list_sizes__get_cpu(size)

        return (f'{type_}: {cpus} CPUs {size.ram} MBs RAM'
                f' {size.disk} GBs disk {size.price}$')

    def _list_sizes__get_cpu(self, size):
        try:
            return size.extra['vcpu_count']
        except KeyError:
            # bare metal size
            return size.extra['cpu_count']

    def _list_sizes__get_available_locations(self, mist_size):
        avail_locations = [str(loc)
                           for loc in mist_size.extra.get('locations', [])]
        from mist.api.clouds.models import CloudLocation
        CloudLocation.objects(
            cloud=self.cloud,
            external_id__in=avail_locations
        ).update(add_to_set__available_sizes=mist_size)

    def _list_images__fetch_images(self, search=None):
        # Vultr has some legacy "dummy" images that were provided when
        # a node was booted from snapshot, iso, application or backup,
        # that are no longer necessary on their API v2.
        images = self.connection.list_images()
        return [image for image in images
                if image.name not in {'Custom',
                                      'Snapshot',
                                      'Backup',
                                      'Application'}]

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('family').lower()
        except AttributeError:
            return super()._list_images__get_os_distro(image)
        return os_distro

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        from mist.api.methods import list_resources
        ret_dict = {
            'ipv6': networks_dict.get('ipv6') is True,
            'hostname': networks_dict.get('hostname')
        }

        networks = networks_dict.get('networks', [])
        if not isinstance(networks, list):
            raise BadRequestError('Invalid "networks" type, expected an array')

        ret_networks = []
        for net in networks:
            networks, _ = list_resources(auth_context,
                                         'network',
                                         search=net,
                                         cloud=self.cloud.id,
                                         )
            networks = networks.filter(location=location)
            try:
                network = networks[0]
            except IndexError:
                raise NotFoundError(f'Network {net} does not exist in'
                                    f' location: {location.name}')
            ret_networks.append({
                'id': network.id,
                'name': network.name,
                'external_id': network.network_id,
            })
        if ret_networks:
            ret_dict['networks'] = ret_networks

        return ret_dict

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        return {
            'id': vol_obj.id,
            'name': vol_obj.name,
            'external_id': vol_obj.external_id
        }

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
            name = volume_dict['name']
        except KeyError:
            raise BadRequestError('name and size are required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid size type')
        if size < 10:
            raise BadRequestError('Size should be at least 10 GBs')

        return {
            'name': name,
            'size': size,
        }

    def _generate_plan__parse_extra(self, extra, plan):
        plan['backups'] = extra.get('backups') is True
        plan['ddos_protection'] = extra.get('ddos_protection') is True

    def _generate_plan__post_parse_plan(self, plan):
        from mist.api.clouds.models import CloudSize, CloudLocation

        size = CloudSize.objects.get(id=plan['size']['id'])
        bare_metal = size.extra['is_bare_metal']
        location = CloudLocation.objects.get(id=plan['location']['id'])

        if plan.get('volumes'):
            if 'block_storage' not in location.extra.get('option', []):
                raise BadRequestError(
                    f'Volumes are not supported in "{location.name}"')
            if bare_metal:
                raise BadRequestError(
                    'Bare Metal metal sizes do not support volume attachment')

        if plan['networks'].get('networks') and bare_metal:
            raise BadRequestError(
                'Bare Metal sizes do not support network attachment')

        if plan['ddos_protection']:
            if 'ddos_protection' not in location.extra.get('option'):
                raise BadRequestError(
                    f'DDoS protection is not supported in "{location.name}"')
            if bare_metal:
                raise BadRequestError(
                    'Bare Metal sizes do not support DDoS protection')

        if plan['backups'] and (bare_metal or
                                size.name.startswith('Dedicated Cloud')):
            raise BadRequestError(
                'Backups are not supported on the given size type')

        hostname = plan['networks']['hostname']
        if hostname is None:
            plan['networks']['hostname'] = plan['machine_name']

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        mist_key = kwargs.pop('auth', None)
        if mist_key:
            vultr_keys = self.connection.list_key_pairs()
            key = next((vultr_key for vultr_key in vultr_keys
                        if vultr_key.public_key.replace('\n', '') == mist_key.public),  # noqa
                       None)
            if key is None:
                try:
                    key = self.connection.import_key_pair_from_string(
                        mist_key.name,
                        mist_key.public)
                except Exception as exc:
                    raise MachineCreationError(
                        f'Failed to import key: {repr(exc)}') from None

            kwargs['ex_ssh_key_ids'] = [key.extra['id']]

        if plan.get('cloudinit'):
            kwargs['ex_userdata'] = plan['cloudinit']

        kwargs['ex_hostname'] = plan['networks']['hostname']
        kwargs['ex_enable_ipv6'] = plan['networks']['ipv6']
        if plan['networks'].get('networks'):
            kwargs['ex_private_network_ids'] = [network['external_id']
                                                for network in plan['networks']['networks']]  # noqa

        kwargs['ex_ddos_protection'] = plan['ddos_protection']
        kwargs['ex_backups'] = plan['backups']

        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        from mist.api.clouds.models import CloudLocation
        from mist.api.volumes.models import Volume
        from libcloud.compute.base import StorageVolume

        volumes = plan.get('volumes', [])
        location = CloudLocation.objects.get(id=plan['location']['id'])

        # wait till machine is in active state to attach volumes
        if volumes:
            for _ in range(10):
                time.sleep(5)
                try:
                    node = self.connection.ex_get_node(node.id)
                except Exception:
                    continue
                if node.state == 'running':
                    break

        for volume in volumes:
            if volume.get('id'):
                vol = Volume.objects.get(id=volume['id'])
                libcloud_vol = StorageVolume(id=vol.external_id,
                                             name=vol.name,
                                             size=vol.size,
                                             driver=self.connection,
                                             extra=vol.extra)
                try:
                    self.connection.attach_volume(node, libcloud_vol)
                except Exception:
                    log.exception('Failed to attach volume')
            else:
                try:
                    libcloud_vol = self.connection.create_volume(
                        size=volume['size'],
                        name=volume['name'],
                        location=location.external_id
                    )
                except Exception:
                    log.exception('Failed to create volume')
                    continue
                try:
                    self.connection.attach_volume(node, libcloud_vol)
                except Exception:
                    log.exception('Failed to attach volume')


class VSphereComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        from libcloud.compute.drivers.vsphere import VSphereNodeDriver
        from libcloud.compute.drivers.vsphere import VSphere_6_7_NodeDriver
        ca_cert = None
        if self.cloud.ca_cert_file:
            ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            ca_cert_temp_file.write(self.cloud.ca_cert_file.value.encode())
            ca_cert_temp_file.close()
            ca_cert = ca_cert_temp_file.name

        host, port = dnat(self.cloud.owner, self.cloud.host, 443)
        driver_6_5 = VSphereNodeDriver(host=host,
                                       username=self.cloud.username,
                                       password=self.cloud.password.value,
                                       port=port,
                                       ca_cert=ca_cert)
        self.version = driver_6_5._get_version()
        if '6.7' in self.version and config.ENABLE_VSPHERE_REST:
            self.version = '6.7'
            return VSphere_6_7_NodeDriver(self.cloud.username,
                                          secret=self.cloud.password.value,
                                          host=host,
                                          port=port,
                                          ca_cert=ca_cert)
        else:
            self.version = "6.5-"
            return driver_6_5

    def check_connection(self):
        """Check connection without performing `list_machines`

        In vSphere we are sure we got a successful connection with the provider
        if `self.connect` works, no need to run a `list_machines` to find out.

        """
        self.connect()

    def _list_machines__get_location(self, node_dict):
        cluster = node_dict['extra'].get('cluster', '')
        host = node_dict['extra'].get('host', '')
        return cluster or host

    def list_vm_folders(self):
        all_folders = self.connection.ex_list_folders()
        vm_folders = [folder for folder in all_folders if
                      "VirtualMachine" in folder[
                          'type'] or "VIRTUAL_MACHINE" in folder['type']]
        return vm_folders

    def list_datastores(self):
        datastores_raw = self.connection.ex_list_datastores()
        return datastores_raw

    def _list_locations__fetch_locations(self):
        """List locations for vSphere

        Return all locations, clusters and hosts
        """
        return self.connection.list_locations()

    def _list_machines__fetch_machines(self):
        """Perform the actual libcloud call to get list of nodes"""
        machine_list = []
        for node in self.connection.list_nodes(
                max_properties=self.cloud.max_properties_per_request,
                extra=config.VSPHERE_FETCH_ALL_EXTRA):
            # Check for VMs without uuid
            if node.id is None:
                log.error("Skipping machine {} on cloud {} - {}): uuid is "
                          "null".format(node.name,
                                        self.cloud.name,
                                        self.cloud.id))
                continue
            machine_list.append(node_to_dict(node))
        return machine_list

    def _list_machines__get_size(self, node_dict):
        """Return key of size_map dict for a specific node

        Subclasses MAY override this method.
        """
        return None

    def _list_machines__get_custom_size(self, node_dict):
        # FIXME: resolve circular import issues
        from mist.api.clouds.models import CloudSize
        updated = False
        try:
            _size = CloudSize.objects.get(
                cloud=self.cloud,
                external_id=node_dict['size'].get('id'))
        except me.DoesNotExist:
            _size = CloudSize(cloud=self.cloud,
                              external_id=str(node_dict['size'].get('id')))
            updated = True
        if _size.ram != node_dict['size'].get('ram'):
            _size.ram = node_dict['size'].get('ram')
            updated = True
        if _size.cpus != node_dict['size'].get('extra', {}).get('cpus'):
            _size.cpus = node_dict['size'].get('extra', {}).get('cpus')
            updated = True
        if _size.disk != node_dict['size'].get('disk'):
            _size.disk = node_dict['size'].get('disk')
            updated = True
        name = ""
        if _size.cpus:
            name += f'{_size.cpus}vCPUs, '
        if _size.ram:
            name += f'{_size.ram}MB RAM, '
        if _size.disk:
            name += f'{_size.disk}GB disk.'
        if _size.name != name:
            _size.name = name
            updated = True
        if updated:
            _size.save()
        return _size

    def _list_machines__machine_actions(self, machine, node_dict):
        super(VSphereComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        machine.actions.clone = True
        machine.actions.rename = True
        machine.actions.create_snapshot = True
        machine.actions.remove_snapshot = True
        machine.actions.revert_to_snapshot = True

    def _stop_machine(self, machine, node):
        return self.connection.stop_node(node)

    def _start_machine(self, machine, node):
        return self.connection.start_node(node)

    def _create_machine_snapshot(self, machine, node,
                                 snapshot_name, description='',
                                 dump_memory=False, quiesce=False):
        """Create a snapshot for a given machine"""
        return self.connection.ex_create_snapshot(
            node, snapshot_name, description,
            dump_memory=dump_memory, quiesce=quiesce)

    def _revert_machine_to_snapshot(self, machine, node,
                                    snapshot_name=None):
        """Revert a given machine to a previous snapshot"""
        return self.connection.ex_revert_to_snapshot(node,
                                                     snapshot_name)

    def _remove_machine_snapshot(self, machine, node,
                                 snapshot_name=None):
        """Removes a given machine snapshot"""
        return self.connection.ex_remove_snapshot(node,
                                                  snapshot_name)

    def _list_machine_snapshots(self, machine, node):
        return self.connection.ex_list_snapshots(node)

    def _list_images__fetch_images(self, search=None):
        image_folders = []
        if config.VSPHERE_IMAGE_FOLDERS:
            image_folders = config.VSPHERE_IMAGE_FOLDERS
        image_list = self.connection.list_images(folder_ids=image_folders)
        # Check for templates without uuid
        for image in image_list[:]:
            if image.id is None:
                log.error("Skipping machine {} on cloud {} - {}): uuid is "
                          "null".format(image.name,
                                        self.cloud.name,
                                        self.cloud.id))
                image_list.remove(image)
        return image_list

    def _clone_machine(self, machine, node, name, resume):
        locations = self.connection.list_locations()
        node_location = None
        if not machine.location:
            vm = self.connection.find_by_uuid(node.id)
            location_id = vm.summary.runtime.host.name
        else:
            location_id = machine.location.external_id
        for location in locations:
            if location.id == location_id:
                node_location = location
                break
        folder = node.extra.get('folder', None)

        if not folder:
            try:
                folder = vm.parent._moId
            except Exception as exc:
                raise BadRequestError(
                    "Failed to find folder the folder containing the machine")
                log.error(
                    "Clone Machine: Exception when "
                    "looking for folder: {}".format(exc))
        datastore = node.extra.get('datastore', None)
        return self.connection.create_node(name=name, image=node,
                                           size=node.size,
                                           location=node_location,
                                           ex_folder=folder,
                                           ex_datastore=datastore)

    def _get_libcloud_node(self, machine):
        vm = self.connection.find_by_uuid(machine.external_id)
        return self.connection._to_node_recursive(vm)

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):

        try:
            network_search = networks_dict['network']
        except KeyError:
            return None

        from mist.api.methods import list_resources

        try:
            [network], _ = list_resources(auth_context,
                                          'network',
                                          search=network_search,
                                          cloud=self.cloud.id,
                                          limit=1)
        except ValueError:
            raise BadRequestError(f'Network: {network_search} not found')

        return {
            'id': network.id,
            'name': network.name,
            'external_id': network.network_id,
        }

    def _generate_plan__parse_extra(self, extra, plan):
        folder = extra.get('folder')
        if folder:
            folders = self.connection.ex_list_folders()
            folder_dict = next((item for item in folders
                                if (item.get('id') == folder or
                                    item.get('name') == folder)),
                               None)
            if folder_dict is None:
                raise NotFoundError(
                    f'Folder: {folder} not found')

            folder_features = folder_dict.get('type') or []
            if 'VirtualMachine' not in folder_features:
                raise BadRequestError(
                    f'Folder: {folder} does not support machine provisioning'
                )
            plan['folder'] = {
                'id': folder_dict['id'],
                'name': folder_dict['name'],
            }

        datastore = extra.get('datastore')
        if datastore:
            datastores = self.connection.ex_list_datastores()
            datastore_dict = next((item for item in datastores
                                   if (item.get('id') == datastore or
                                       item.get('name') == datastore)),
                                  None)

            if datastore_dict is None:
                raise NotFoundError(
                    f'Datastore: {datastore} not found'
                )
            plan['datastore'] = {
                'id': datastore_dict['id'],
                'name': datastore_dict['name'],
            }

    def _create_machine__get_size_object(self, size):
        # even though vsphere has custom sizes `create_node`
        # expects a libcloud NodeSize object. Create a dummy
        # one with only the attributes necessary
        from libcloud.compute.base import NodeSize
        nodesize = NodeSize(id=None,
                            name=None,
                            ram=size['ram'],
                            disk=None,
                            bandwidth=None,
                            price=None,
                            driver=self.connection,
                            extra={
                                'cpus': size['cpus']
                            })
        return nodesize

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)

        try:
            kwargs['ex_network'] = plan['networks']['external_id']
        except KeyError:
            kwargs['ex_network'] = None

        try:
            kwargs['ex_folder'] = plan['folder']['id']
        except KeyError:
            kwargs['ex_folder'] = None
        try:
            kwargs['ex_datastore'] = plan['datastore']['id']
        except KeyError:
            kwargs['ex_datastore'] = None
        return kwargs


class OpenStackComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        url = dnat(self.cloud.owner, self.cloud.url)
        return get_driver(Provider.OPENSTACK)(
            self.cloud.username,
            self.cloud.password.value,
            api_version='2.2',
            ex_force_auth_version='3.x_password',
            ex_tenant_name=self.cloud.tenant,
            ex_force_service_region=self.cloud.region,
            ex_force_base_url=self.cloud.compute_endpoint,
            ex_auth_url=url,
            ex_domain_name=self.cloud.domain or 'Default'
        )

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('created')  # iso8601 string

    def _list_machines__machine_actions(self, machine, node_dict):
        super(OpenStackComputeController,
              self)._list_machines__machine_actions(machine, node_dict)
        machine.actions.rename = True
        machine.actions.resize = True

    def _resize_machine(self, machine, node, node_size, kwargs):
        try:
            self.connection.ex_resize(node, node_size)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

        try:
            sleep(50)
            node = self._get_libcloud_node(machine)
            return self.connection.ex_confirm_resize(node)
        except Exception as exc:
            sleep(50)
            node = self._get_libcloud_node(machine)
            try:
                return self.connection.ex_confirm_resize(node)
            except Exception as exc:
                raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        # do not include ipv6 on public ips
        public_ips = []
        for ip in machine.public_ips:
            if ip and ':' not in ip:
                public_ips.append(ip)
        if machine.public_ips != public_ips:
            machine.public_ips = public_ips
            updated = True
        return updated

    def _list_machines__get_location(self, node):
        return node['extra'].get('availability_zone', '')

    def _list_sizes__get_cpu(self, size):
        return size.vcpus

    def _list_machines__get_size(self, node):
        return node['extra'].get('flavorId')

    def _list_security_groups(self):
        if self.cloud.tenant_id is None:
            # try to populate tenant_id field
            try:
                tenant_id = \
                    self.cloud.ctl.compute.connection.ex_get_tenant_id()
            except Exception as exc:
                log.error(
                    'Failed to retrieve project id for Openstack cloud %s: %r',
                    self.cloud.id, exc)
            else:
                self.cloud.tenant_id = tenant_id
                try:
                    self.cloud.save()
                except me.ValidationError as exc:
                    log.error(
                        'Error adding tenant_id to %s: %r',
                        self.cloud.name, exc)
        try:
            sec_groups = \
                self.cloud.ctl.compute.connection.ex_list_security_groups(
                    tenant_id=self.cloud.tenant_id
                )
        except Exception as exc:
            log.error('Could not list security groups for cloud %s: %r',
                      self.cloud, exc)
            raise CloudUnavailableError(exc=exc)

        sec_groups = [{'id': sec_group.id,
                       'name': sec_group.name,
                       'tenant_id': sec_group.tenant_id,
                       'description': sec_group.description,
                       }
                      for sec_group in sec_groups]

        return sec_groups

    def _list_locations__fetch_locations(self):
        return self.connection.ex_list_availability_zones()

    def _generate_plan__parse_location(self, auth_context, location_search):
        # If a location string is not given, let openstack set
        # the default location
        if not location_search:
            from mist.api.clouds.models import CloudLocation
            return [CloudLocation()]

        locations = super()._generate_plan__parse_location(
            auth_context, location_search)
        # filter out locations that do not supoort compute resources
        return [location for location in locations
                if location.extra.get('compute', False) is True]

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        from mist.api.methods import list_resources
        from mist.api.networks.models import Network

        ret_dict = {}

        ret_dict['associate_floating_ip'] = True if networks_dict.get(
            'associate_floating_ip', True) is True else False

        networks = networks_dict.get('networks', [])
        ret_dict['networks'] = []

        # if multiple networks exist, network parameter must be defined
        if (len(networks) == 0 and Network.objects(cloud=self.cloud, missing_since=None).count() > 1):  # noqa
            raise BadRequestError('Multiple networks found, define a network to be more specific.')  # noqa

        for net in networks:
            try:
                [network], _ = list_resources(auth_context, 'network',
                                              search=net,
                                              cloud=self.cloud.id,
                                              limit=1)
            except ValueError:
                raise NotFoundError(f'Network {net} does not exist')

            ret_dict['networks'].append({'id': network.network_id,
                                         'name': network.name})

        try:
            security_groups = set(networks_dict.get('security_groups', []))
        except TypeError:
            raise BadRequestError('Invalid type for security groups')

        ret_dict['security_groups'] = []
        if security_groups:
            try:
                sec_groups = \
                    self.cloud.ctl.compute.connection.ex_list_security_groups(
                        tenant_id=self.cloud.tenant_id
                    )
            except Exception as exc:
                log.exception('Could not list security groups for cloud %s',
                              self.cloud)
                raise CloudUnavailableError(exc=exc) from None

            ret_dict['security_groups'] = list({
                sec_group.name for sec_group in sec_groups
                if sec_group.name in security_groups or
                sec_group.id in security_groups})

        return ret_dict

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        delete_on_termination = True if volume_dict.get(
            'delete_on_termination', False) is True else False

        boot = True if volume_dict.get(
            'boot', False) is True else False

        return {
            'id': vol_obj.id,
            'name': vol_obj.name,
            'delete_on_termination': delete_on_termination,
            'boot': boot,
        }

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')

        delete_on_termination = True if volume_dict.get(
            'delete_on_termination', False) is True else False

        boot = True if volume_dict.get(
            'boot', False) is True else False

        return {
            'size': size,
            'delete_on_termination': delete_on_termination,
            'boot': boot,
        }

    def _generate_plan__post_parse_plan(self, plan):
        volumes = plan.get('volumes', [])

        # make sure boot drive is first if it exists
        volumes.sort(key=lambda k: k['boot'],
                     reverse=True)

        if len(volumes) > 1:
            # make sure only one boot volume is set
            if volumes[1].get('boot') is True:
                raise BadRequestError('Up to 1 volume must be set as boot')

        plan['volumes'] = volumes

    def _create_machine__compute_kwargs(self, plan):
        from libcloud.compute.drivers.openstack import OpenStackSecurityGroup
        from libcloud.compute.drivers.openstack import OpenStackNetwork
        kwargs = super()._create_machine__compute_kwargs(plan)

        if kwargs.get('location'):
            kwargs['ex_availability_zone'] = kwargs.pop('location').name

        if plan.get('cloudinit'):
            kwargs['ex_userdata'] = plan['cloudinit']

        key = kwargs.pop('auth')
        try:
            openstack_keys = self.connection.list_key_pairs()
        except Exception as exc:
            log.exception('Failed to fetch keypairs')
            raise

        for openstack_key in openstack_keys:
            if key.public == openstack_key.public_key:
                server_key = openstack_key
                break
        else:
            try:
                server_key = self.connection.import_key_pair_from_string(
                    name=f'mistio-{secrets.token_hex(3)}',
                    key_material=key.public,
                )
            except Exception:
                log.exception('Failed to create keypair')
                raise
        kwargs['ex_keyname'] = server_key.name

        # use dummy objects with only the attributes needed
        kwargs['networks'] = [OpenStackNetwork(network['id'],
                                               None,
                                               None,
                                               self.connection)
                              for network in plan['networks']['networks']]

        kwargs['ex_security_groups'] = [
            OpenStackSecurityGroup(id=None,
                                   name=sec_group,
                                   tenant_id=None,
                                   description=None,
                                   driver=self.connection)
            for sec_group in plan['networks']['security_groups']
        ]

        blockdevicemappings = []
        for volume in plan['volumes']:
            mapping = {
                'delete_on_termination': volume['delete_on_termination'],
                'destination_type': 'volume',
            }
            if volume.get('id'):
                from mist.api.volumes.models import Volume
                vol = Volume.objects.get(id=volume['id'])
                if volume['boot'] is True:
                    mapping['boot_index'] = 0
                else:
                    mapping['boot_index'] = None
                mapping['uuid'] = vol.external_id
                mapping['source_type'] = 'volume'
            else:
                mapping['volume_size'] = volume['size']
                if volume['boot'] is True:
                    mapping['boot_index'] = 0
                    mapping['source_type'] = 'image'
                    mapping['uuid'] = kwargs.pop('image').id
                else:
                    mapping['boot_index'] = None
                    mapping['source_type'] = 'blank'
            blockdevicemappings.append(mapping)

        # This is a workaround for an issue which occurs only
        # when non-boot volumes are passed. Openstack expects a
        # block device mapping with boot_index 0.
        # http://lists.openstack.org/pipermail/openstack-dev/2015-March/059332.html  # noqa
        if (blockdevicemappings and
                blockdevicemappings[0]['boot_index'] is None):
            blockdevicemappings.insert(0, {'uuid': kwargs.pop('image').id,
                                           'source_type': 'image',
                                           'destination_type': 'local',
                                           'boot_index': 0,
                                           'delete_on_termination': True})

        kwargs['ex_blockdevicemappings'] = blockdevicemappings
        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        if plan['networks']['associate_floating_ip'] is False:
            return

        # From the already created floating ips try to find one
        # that is not associated to a node
        floating_ips = self.connection.ex_list_floating_ips()
        unassociated_floating_ip = next((ip for ip in floating_ips
                                         if ip.status == 'DOWN'), None)

        # Find the ports which are associated to the machine
        # (e.g. the ports of the private ips)
        # and use one to associate a floating ip
        for _ in range(5):
            ports = self.connection.ex_list_ports()
            machine_port_id = next((port.id for port in ports
                                    if port.extra.get('device_id') == node.id),  # noqa
                                   None)
            if machine_port_id is None:
                # sleep in case a port has not been yet associated
                # with the machine
                time.sleep(5)
            else:
                break
        else:
            log.error('Unable to find machine port.'
                      'OpenstackCloud: %s, Machine external_id: %s',
                      self.cloud.id, node.id)
            return

        if unassociated_floating_ip:
            log.info('Associating floating ip with machine: %s', node.id)
            try:
                self.connection.ex_associate_floating_ip_to_node(
                    unassociated_floating_ip.id, machine_port_id)
            except BaseHTTPError:
                log.exception('Failed to associate ip address to node')
        else:
            # Find the external network
            networks = self.connection.ex_list_networks()
            ext_net_id = next((network.id for network in networks
                               if network.router_external is True),
                              None)
            if ext_net_id is None:
                log.error('Failed to find external network')
                return
            log.info('Create and associating floating ip with machine: %s',
                     node.id)
            try:
                self.connection.ex_create_floating_ip(ext_net_id,
                                                      machine_port_id)
            except BaseHTTPError:
                log.exception('Failed to create floating ip address')


class VexxhostComputeController(OpenStackComputeController):
    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        ret_dict = super()._generate_plan__parse_networks(
            auth_context,
            networks_dict,
            location
        )

        # Vexxhost assigns a public IP when a machine is attached to the
        # 'public' network, so there's no need to assign a floating IP
        # when a user hasn't explicitly asked for it.
        if networks_dict.get('associate_floating_ip') is None:
            ret_dict['associate_floating_ip'] = False

        return ret_dict


class DockerComputeController(BaseComputeController):

    def __init__(self, *args, **kwargs):
        super(DockerComputeController, self).__init__(*args, **kwargs)
        self._dockerhost = None

    def _connect(self, **kwargs):
        host, port = dnat(self.cloud.owner, self.cloud.host,
                          self.cloud.port)

        try:
            socket.setdefaulttimeout(15)
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.connect((sanitize_host(host), int(port)))
            so.close()
        except:
            raise Exception("Make sure host is accessible "
                            "and docker port is specified")

        # TLS authentication.
        if self.cloud.key_file and self.cloud.cert_file:
            key_temp_file = tempfile.NamedTemporaryFile(delete=False)
            key_temp_file.write(self.cloud.key_file.value.encode())
            key_temp_file.close()
            cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            cert_temp_file.write(self.cloud.cert_file.value.encode())
            cert_temp_file.close()
            ca_cert = None
            if self.cloud.ca_cert_file:
                ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
                ca_cert_temp_file.write(self.cloud.ca_cert_file.value.encode())
                ca_cert_temp_file.close()
                ca_cert = ca_cert_temp_file.name

            # tls auth
            return get_container_driver(Container_Provider.DOCKER)(
                host=host, port=port,
                key_file=key_temp_file.name,
                cert_file=cert_temp_file.name,
                ca_cert=ca_cert)

        # Username/Password authentication.
        if self.cloud.username and self.cloud.password:

            return get_container_driver(Container_Provider.DOCKER)(
                key=self.cloud.username.value,
                secret=self.cloud.password.value,
                host=host, port=port)
        # open authentication.
        else:
            return get_container_driver(Container_Provider.DOCKER)(
                host=host, port=port)

    def _list_machines__fetch_machines(self):
        """Perform the actual libcloud call to get list of containers"""
        containers = self.connection.list_containers(all=self.cloud.show_all)
        # add public/private ips for mist
        for container in containers:
            public_ips, private_ips = [], []
            host = sanitize_host(self.cloud.host)
            if is_private_subnet(host):
                private_ips.append(host)
            else:
                public_ips.append(host)
            container.public_ips = public_ips
            container.private_ips = private_ips
            container.size = None
            container.image = container.image.name
        return [node_to_dict(node) for node in containers]

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('created')  # unix timestamp

    def _list_machines__machine_actions(self, machine, node_dict):
        # todo this is not necessary
        super(DockerComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        if node_dict['state'] in (ContainerState.RUNNING,):
            machine.actions.rename = True
        elif node_dict['state'] in (ContainerState.REBOOTING,
                                    ContainerState.PENDING):
            machine.actions.start = False
            machine.actions.stop = False
            machine.actions.reboot = False
        elif node_dict['state'] in (ContainerState.STOPPED,
                                    ContainerState.UNKNOWN):
            # We assume unknown state means stopped.
            machine.actions.start = True
            machine.actions.stop = False
            machine.actions.reboot = False
            machine.actions.rename = True
        elif node_dict['state'] in (ContainerState.TERMINATED, ):
            machine.actions.start = False
            machine.actions.stop = False
            machine.actions.reboot = False
            machine.actions.destroy = False
            machine.actions.rename = False

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        if machine.machine_type != 'container':
            machine.machine_type = 'container'
            updated = True
        if machine.parent != self.dockerhost:
            machine.parent = self.dockerhost
            updated = True
        return updated

    @property
    def dockerhost(self):
        """This is a helper method to get the machine representing the host"""
        if self._dockerhost is not None:
            return self._dockerhost

        from mist.api.machines.models import Machine
        try:
            # Find dockerhost from database.
            machine = Machine.objects.get(cloud=self.cloud,
                                          machine_type='container-host')
        except Machine.DoesNotExist:
            try:
                # Find dockerhost with previous format from database.
                machine = Machine.objects.get(
                    cloud=self.cloud,
                    # Nested query. Trailing underscores to avoid conflict
                    # with mongo's $type operator. See:
                    # https://github.com/MongoEngine/mongoengine/issues/1410
                    **{'extra__tags__type__': 'docker_host'}
                )
            except Machine.DoesNotExist:
                # Create dockerrhost machine.
                machine = Machine(cloud=self.cloud,
                                  machine_type='container-host')

        # Update dockerhost machine model fields.
        changed = False
        for attr, val in {'name': self.cloud.name,
                          'hostname': self.cloud.host,
                          'machine_type': 'container-host'}.items():
            if getattr(machine, attr) != val:
                setattr(machine, attr, val)
                changed = True
        if not machine.external_id:
            machine.external_id = machine.id
            changed = True
        try:
            ip_addr = socket.gethostbyname(machine.hostname)
        except socket.gaierror:
            pass
        else:
            is_private = netaddr.IPAddress(ip_addr).is_private()
            ips = machine.private_ips if is_private else machine.public_ips
            if ip_addr not in ips:
                ips.insert(0, ip_addr)
                changed = True
        if changed:
            machine.save()

        self._dockerhost = machine
        return machine

    def inspect_node(self, node):
        """
        Inspect a container
        """
        result = self.connection.connection.request(
            "/v%s/containers/%s/json" % (self.connection.version,
                                         node.id)).object

        name = result.get('Name').strip('/')
        if result['State']['Running']:
            state = ContainerState.RUNNING
        else:
            state = ContainerState.STOPPED

        extra = {
            'image': result.get('Image'),
            'volumes': result.get('Volumes'),
            'env': result.get('Config', {}).get('Env'),
            'ports': result.get('ExposedPorts'),
            'network_settings': result.get('NetworkSettings', {}),
            'exit_code': result['State'].get("ExitCode")
        }

        node_id = result.get('Id')
        if not node_id:
            node_id = result.get('ID', '')

        host = sanitize_host(self.cloud.host)
        public_ips, private_ips = [], []
        if is_private_subnet(host):
            private_ips.append(host)
        else:
            public_ips.append(host)

        networks = result['NetworkSettings'].get('Networks', {})
        for network in networks:
            network_ip = networks[network].get('IPAddress')
            if is_private_subnet(network_ip):
                private_ips.append(network_ip)
            else:
                public_ips.append(network_ip)

        ips = []  # TODO maybe the api changed
        ports = result.get('Ports', [])
        for port in ports:
            if port.get('IP') is not None:
                ips.append(port.get('IP'))

        contnr = (Container(id=node_id,
                            name=name,
                            image=result.get('Image'),
                            state=state,
                            ip_addresses=ips,
                            driver=self.connection,
                            extra=extra))
        contnr.public_ips = public_ips
        contnr.private_ips = private_ips
        contnr.size = None
        return contnr

    def _list_machines__fetch_generic_machines(self):
        return [self.dockerhost]

    def _list_images__fetch_images(self, search=None):
        if not search:
            # Fetch mist's recommended images
            images = [ContainerImage(id=image, name=name, path=None,
                                     version=None, driver=self.connection,
                                     extra={})
                      for image, name in list(config.DOCKER_IMAGES.items())]
            images += self.connection.list_images()

        else:
            # search on dockerhub
            images = self.connection.ex_search_images(term=search)[:100]

        return images

    def image_is_default(self, image_id):
        return image_id in config.DOCKER_IMAGES

    def _action_change_port(self, machine, node):
        """This part exists here for docker specific reasons. After start,
        reboot and destroy actions, docker machine instance need to rearrange
        its port. Finally save the machine in db.
        """
        # this exist here cause of docker host implementation
        if machine.machine_type == 'container-host':
            return
        container_info = self.inspect_node(node)

        try:
            port = container_info.extra[
                'network_settings']['Ports']['22/tcp'][0]['HostPort']
        except (KeyError, TypeError):
            # add TypeError in case of 'Ports': {u'22/tcp': None}
            port = 22

        from mist.api.machines.models import KeyMachineAssociation
        key_associations = KeyMachineAssociation.objects(machine=machine)
        for key_assoc in key_associations:
            key_assoc.port = port
            key_assoc.save()
        return True

    def _get_libcloud_node(self, machine, no_fail=False):
        """Return an instance of a libcloud node

        This is a private method, used mainly by machine action methods.
        """
        assert self.cloud == machine.cloud
        for node in self.connection.list_containers():
            if node.id == machine.external_id:
                return node
        if no_fail:
            container = Container(id=machine.external_id,
                                  name=machine.external_id,
                                  image=machine.image.id,
                                  state=0,
                                  ip_addresses=[],
                                  driver=self.connection,
                                  extra={})
            container.public_ips = []
            container.private_ips = []
            container.size = None
            return container
        raise MachineNotFoundError(
            "Machine with external_id '%s'." % machine.external_id
        )

    def _start_machine(self, machine, node):
        ret = self.connection.start_container(node)
        self._action_change_port(machine, node)
        return ret

    def reboot_machine(self, machine):
        if machine.machine_type == 'container-host':
            return self.reboot_machine_ssh(machine)
        return super(DockerComputeController, self).reboot_machine(machine)

    def _reboot_machine(self, machine, node):
        self.connection.restart_container(node)
        self._action_change_port(machine, node)

    def _stop_machine(self, machine, node):
        return self.connection.stop_container(node)

    def _destroy_machine(self, machine, node):
        try:
            if node.state == ContainerState.RUNNING:
                self.connection.stop_container(node)
            return self.connection.destroy_container(node)
        except Exception as e:
            log.error('Destroy failed: %r' % e)
            return False

    def _list_sizes__fetch_sizes(self):
        return []

    def _rename_machine(self, machine, node, name):
        """Private method to rename a given machine"""
        self.connection.ex_rename_container(node, name)

    def _generate_plan__parse_size(self, auth_context, size_obj):
        size_obj = size_obj or {}
        if not isinstance(size_obj, dict):
            raise BadRequestError('Invalid size type')

        cpu_limit = size_obj.get('cpu')
        if cpu_limit and cpu_limit <= 0:
            raise BadRequestError('Cpu limit value should be bigger than 0')

        memory_limit = size_obj.get('memory')
        if memory_limit and memory_limit < 6:
            raise BadRequestError('Memory limit value should be at least 6 MB')

        cpu_shares = size_obj.get('prefer', {}).get('cpu_shares')
        if cpu_shares and cpu_shares < 2:
            raise BadRequestError('Cpu shares value should be at least 2')

        ret_size = {}
        if cpu_shares:
            ret_size['cpu_shares'] = cpu_shares

        limits = {}
        if cpu_limit:
            limits['cpu'] = cpu_limit
        if memory_limit:
            limits['memory'] = memory_limit

        if limits:
            ret_size['limits'] = limits

        return [ret_size], None

    def _generate_plan__parse_custom_image(self, image_obj):
        # Image does not exist, so it needs to be pulled.
        # Instead of pulling it here synchronously, we create a dummy
        # CloudImage object that will be pulled later on asynchronous context
        from mist.api.images.models import CloudImage
        from mist.api.helpers import get_docker_image_sha
        if isinstance(image_obj, str):
            name = image_obj
        else:
            name = image_obj.get('image')

        # Use the default "latest" tag if image path given is not tagged
        if ':' not in name:
            name = f'{name}:latest'

        try:
            image_sha = get_docker_image_sha(name)
        except Exception:
            log.exception('Failed to fetch image sha256 hash')
            raise CloudUnavailableError(
                'Failed to fetch image sha256 hash') from None

        if image_sha is None:
            raise BadRequestError('Image does not exist on docker registry')

        try:
            image = CloudImage.objects.get(cloud=self.cloud,
                                           external_id=image_sha)
        except CloudImage.DoesNotExist:
            image = CloudImage(external_id=image_sha,
                               name=name,
                               cloud=self.cloud,
                               missing_since=datetime.datetime.now()
                               ).save()

        return image, {'pull': True}

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        port_bindings = networks_dict.get('port_bindings', {})

        if not isinstance(port_bindings, dict):
            raise BadRequestError('Invalid port_bindings parameter')

        host_port_regex = r'^\d{1,5}$'
        container_port_regex = r'^\d{1,5}(\/\w+)?$'

        for container_port, host_port in port_bindings.items():
            if (not re.match(host_port_regex, host_port) or
                    not re.match(container_port_regex, container_port)):
                raise BadRequestError('Invalid port bindings')

        return {
            'port_bindings': port_bindings
        }

    def _generate_plan__parse_extra(self, extra, plan) -> None:
        if extra.get('command'):
            plan['command'] = extra['command']

        if extra.get('environment'):
            if not isinstance(extra['environment'], dict):
                raise BadRequestError('Invalid port_bindings parameter')

            plan['environment'] = extra['environment']

    def _compute_best_combination(self, combination_list):
        if not combination_list:
            raise NotFoundError('No available plan exists for given '
                                'images, sizes, locations')

        # prioritize images tagged latest
        def sort_by_tag(value):
            image, size, location = value
            tagged_latest = ':latest' in image.name
            return -tagged_latest, -image.starred

        return sorted(combination_list, key=sort_by_tag)[0]

    def _create_machine__get_image_object(self, image):
        if image.get('pull') is True:
            from mist.api.helpers import pull_docker_image
            try:
                image_obj = pull_docker_image(self.cloud.id, image['name'])
            except Exception as exc:
                raise MachineCreationError(
                    f'Failed to pull image with exception: {exc!r}')
        else:
            image_obj = super()._create_machine__get_image_object(image['id'])
            # Docker deploy_container method uses the image name to deploy from
            image_obj.name = image_obj.id

        return image_obj

    def _create_machine__compute_kwargs(self, plan):
        kwargs = {
            'name': plan['machine_name'],
            'image': self._create_machine__get_image_object(plan['image'])
        }

        environment = [f'{key}={value}' for key, value in
                       plan.get('environment', {}).items()]

        key = self._create_machine__get_key_object(
            plan.get('key', {}).get('id'))
        if key:
            environment.append(f'PUBLIC_KEY={key.public}')
        kwargs['environment'] = environment
        kwargs['command'] = plan.get('command', '')

        if plan.get('size'):
            # The Docker API expects cpu quota in units of 10^9 CPUs.
            try:
                kwargs['nano_cpus'] = int(
                    plan['size']['limits']['cpu'] * (10**9))
            except KeyError:
                pass
            # The Docker API expects memory quota in bytes
            try:
                kwargs['mem_limit'] = int(
                    plan['size']['limits']['memory'] * 1024 * 1024)
            except KeyError:
                pass

            try:
                kwargs['cpu_shares'] = plan['size']['cpu_shares']
            except KeyError:
                pass

        if plan.get('networks'):
            port_bindings = plan['networks']['port_bindings']
            exposed_ports = {}
            bindings = {}
            # Docker API expects an object with the exposed container ports
            # in the form: {"<port>/<tcp|udp|sctp>": {}}
            for container_port, host_port in port_bindings.items():
                port = (container_port if '/' in container_port
                        else f'{container_port}/tcp')
                exposed_ports[port] = {}
                bindings[port] = [{
                    'HostPort': host_port
                }]

            kwargs['ports'] = exposed_ports
            kwargs['port_bindings'] = bindings

        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        if plan.get('key'):
            node_info = self.inspect_node(node)
            try:
                ssh_port = int(
                    node_info.extra[
                        'network_settings']['Ports']['22/tcp'][0]['HostPort'])
            except KeyError:
                pass
            else:
                node.extra['ssh_port'] = ssh_port


class LXDComputeController(BaseComputeController):
    """
    Compute controller for LXC containers
    """

    def __init__(self, *args, **kwargs):
        super(LXDComputeController, self).__init__(*args, **kwargs)
        self._lxchost = None
        self.is_lxc = True

    def _stop_machine(self, machine, node):
        """Stop the given machine"""
        return self.connection.stop_container(container=machine)

    def _start_machine(self, machine, node):
        """Start the given container"""
        return self.connection.start_container(container=machine)

    def _destroy_machine(self, machine, node):
        """Delete the given container"""

        from libcloud.container.drivers.lxd import LXDAPIException
        from libcloud.container.types import ContainerState
        try:

            if node.state == ContainerState.RUNNING:
                self.connection.stop_container(container=machine)

            container = self.connection.destroy_container(container=machine)
            return container
        except LXDAPIException as e:
            raise MistError(msg=e.message, exc=e)
        except Exception as e:
            raise MistError(exc=e)

    def _reboot_machine(self, machine, node):
        """Restart the given container"""
        return self.connection.restart_container(container=machine)

    def _list_sizes__fetch_sizes(self):
        return []

    def _list_machines__fetch_machines(self):
        """Perform the actual libcloud call to get list of containers"""

        containers = self.connection.list_containers()

        # add public/private ips for mist
        for container in containers:
            public_ips, private_ips = [], []
            for ip in container.extra.get('ips'):
                if is_private_subnet(ip):
                    private_ips.append(ip)
                else:
                    public_ips.append(ip)

            container.public_ips = public_ips
            container.private_ips = private_ips
            container.size = None
            container.image = container.image.name

        return [node_to_dict(node) for node in containers]

    def _list_machines__machine_creation_date(self, machine, node_dict):
        """Unix timestap of when the machine was created"""
        return node_dict['extra'].get('created')  # unix timestamp

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        if machine.machine_type != 'container':
            machine.machine_type = 'container'
            updated = True
        return updated

    def _get_libcloud_node(self, machine, no_fail=False):
        """Return an instance of a libcloud node

        This is a private method, used mainly by machine action methods.
        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        for node in self.connection.list_containers():
            if node.id == machine.external_id:
                return node
        if no_fail:
            return Node(machine.external_id, name=machine.external_id,
                        state=0, public_ips=[], private_ips=[],
                        driver=self.connection)
        raise MachineNotFoundError(
            "Machine with external_id '%s'." % machine.external_id
        )

    def _connect(self, **kwargs):
        host, port = dnat(self.cloud.owner, self.cloud.host,
                          self.cloud.port)

        try:
            socket.setdefaulttimeout(15)
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.connect((sanitize_host(host), int(port)))
            so.close()
        except:
            raise Exception("Make sure host is accessible "
                            "and LXD port is specified")

        if self.cloud.key_file and self.cloud.cert_file:
            tls_auth = self._tls_authenticate(host=host, port=port)

            if tls_auth is None:
                raise Exception("key_file and cert_file exist "
                                "but TLS certification was not possible ")
            return tls_auth

        # Username/Password authentication.
        if self.cloud.username and self.cloud.password:

            return get_container_driver(Container_Provider.LXD)(
                key=self.cloud.username.value,
                secret=self.cloud.password.value,
                host=host, port=port)
        # open authentication.
        else:
            return get_container_driver(Container_Provider.LXD)(
                host=host, port=port)

    def _tls_authenticate(self, host, port):
        """Perform TLS authentication given the host and port"""

        # TLS authentication.

        key_temp_file = tempfile.NamedTemporaryFile(delete=False)
        key_temp_file.write(self.cloud.key_file.value.encode())
        key_temp_file.close()
        cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
        cert_temp_file.write(self.cloud.cert_file.value.encode())
        cert_temp_file.close()
        ca_cert = None

        if self.cloud.ca_cert_file:
            ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            ca_cert_temp_file.write(self.cloud.ca_cert_file.value.encode())
            ca_cert_temp_file.close()
            ca_cert = ca_cert_temp_file.name

        # tls auth
        cert_file = cert_temp_file.name
        key_file = key_temp_file.name
        return \
            get_container_driver(Container_Provider.LXD)(host=host,
                                                         port=port,
                                                         key_file=key_file,
                                                         cert_file=cert_file,
                                                         ca_cert=ca_cert)

    def _generate_plan__parse_size(self, auth_context, size_obj):
        size_obj = size_obj or {}

        if not isinstance(size_obj, dict):
            raise BadRequestError('Invalid size type')

        cpu_limit = size_obj.get('cpu')
        if cpu_limit and cpu_limit <= 0:
            raise BadRequestError('Cpu limit value should be bigger than 0')

        memory_limit = size_obj.get('memory')
        if memory_limit and memory_limit < 6:
            raise BadRequestError('Memory limit value should be at least 6 MB')

        ret_size = {}
        limits = {}

        if cpu_limit:
            limits['cpu'] = str(cpu_limit)
        if memory_limit:
            limits['memory'] = f'{memory_limit}MB'

        if limits:
            ret_size['limits'] = limits

        return [ret_size], None

    def _generate_plan__parse_networks(self,
                                       auth_context,
                                       networks_dict,
                                       location):
        from mist.api.methods import list_resources
        networks = networks_dict.get('networks') or []
        ret_networks = []
        for net in networks:
            try:
                [network], _ = list_resources(auth_context,
                                              'network',
                                              search=net,
                                              cloud=self.cloud.id,
                                              limit=1)
            except ValueError:
                raise NotFoundError(f'Network: {net} not found')

            ret_networks.append({
                'id': network.id,
                'name': network.name,
            })

        return ret_networks

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        try:
            path = volume_dict['path']
        except KeyError:
            raise BadRequestError('Volume path parameter is required')

        return {
            'id': vol_obj.id,
            'name': vol_obj.name,
            'path': path,
        }

    def _generate_plan__parse_custom_volume(self, volume_dict):
        ret_volume = {}
        try:
            ret_volume['name'] = volume_dict['name']
        except KeyError:
            raise BadRequestError('Volume name parameter is required')

        try:
            ret_volume['size'] = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size parameter is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')

        try:
            ret_volume['path'] = volume_dict['path']
        except KeyError:
            raise BadRequestError('Volume path parameter is required')

        ret_volume['filesystem'] = volume_dict.get('filesystem') or 'ext4'
        ret_volume['mount_options'] = (volume_dict.get('mount_options') or
                                       'discard')
        ret_volume['pool'] = volume_dict.get('pool') or 'default'

        security_shifted = volume_dict.get('security_shifted') is True
        if security_shifted:
            ret_volume['security_shifted'] = security_shifted

        return ret_volume

    def _generate_plan__parse_extra(self, extra, plan):
        plan['ephemeral'] = extra.get('ephemeral') is True

    def _create_machine__compute_kwargs(self, plan):
        from mist.api.volumes.models import Volume
        kwargs = super()._create_machine__compute_kwargs(plan)
        image = kwargs.pop('image')
        kwargs['image'] = None
        parameters = {
            'source': {
                'type': 'image',
                'fingerprint': image.id
            }
        }
        kwargs['parameters'] = json.dumps(parameters)
        devices = {}
        volumes = plan.get('volumes', [])
        for volume in volumes:
            if volume.get('id'):
                mist_volume = Volume.objects.get(id=volume['id'])
                devices[mist_volume.name] = {
                    'type': 'disk',
                    'path': volume['path'],
                    'source': mist_volume.name,
                    'pool': mist_volume.extra['pool_id']
                }
            else:
                definition = {
                    'name': volume['name'],
                    'type': 'custom',
                    'size_type': 'GB',
                    'config': {
                        'size': volume['size'],
                        'block.filesystem': volume['filesystem'],
                        'block.mount_options': volume['mount_options'],
                    }
                }
                try:
                    libcloud_volume = self.connection.create_volume(
                        pool_id=volume['pool'],
                        definition=definition)
                except Exception:
                    log.error('Failed to create volume for LXD cloud: %s',
                              self.cloud.id)
                else:
                    devices[libcloud_volume.name] = {
                        'type': 'disk',
                        'path': volume['path'],
                        'source': libcloud_volume.name,
                        'pool': libcloud_volume.extra['pool_id']
                    }

        networks = plan.get('networks', [])
        for network in networks:
            devices[network['name']] = {
                'name': network['name'],
                'type': 'nic',
                'nictype': 'bridged',
                'parent': 'lxdbr0',
            }
        if devices:
            kwargs['ex_devices'] = devices

        kwargs['ex_ephemeral'] = plan['ephemeral']
        if plan.get('size'):
            kwargs['ex_config'] = {}
            try:
                kwargs['ex_config']['limits.cpu'] = plan['size']['limits']['cpu']  # noqa
            except KeyError:
                pass
            try:
                kwargs['ex_config']['limits.memory'] = plan['size']['limits']['memory']  # noqa
            except KeyError:
                pass

        return kwargs


class LibvirtComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        """
        Look for the host that corresponds to the provided location
        """
        from mist.api.clouds.models import CloudLocation
        from mist.api.machines.models import Machine
        location = CloudLocation.objects.get(
            id=kwargs.get('location_id'), cloud=self.cloud)
        host = Machine.objects.get(
            cloud=self.cloud, parent=None, external_id=location.external_id)

        return self._get_host_driver(host)

    def _get_host_driver(self, machine):
        import libcloud.compute.drivers.libvirt_driver
        libvirt_driver = libcloud.compute.drivers.libvirt_driver
        libvirt_driver.ALLOW_LIBVIRT_LOCALHOST = config.ALLOW_LIBVIRT_LOCALHOST

        if not machine.extra.get('tags', {}).get('type') == 'hypervisor':
            machine = machine.parent

        from mist.api.machines.models import KeyMachineAssociation
        from mongoengine import Q
        # Get key associations, prefer root or sudoer ones
        # TODO: put this in a helper function
        key_associations = KeyMachineAssociation.objects(
            Q(machine=machine) & (Q(ssh_user='root') | Q(sudo=True))) \
            or KeyMachineAssociation.objects(machine=machine)
        if not key_associations:
            raise ForbiddenError()

        host, port = dnat(machine.cloud.owner,
                          machine.hostname, machine.ssh_port)
        driver = get_driver(Provider.LIBVIRT)(
            host, hypervisor=machine.hostname, ssh_port=int(port),
            user=key_associations[0].ssh_user,
            ssh_key=key_associations[0].key.private.value)

        return driver

    def list_machines_single_host(self, host):
        driver = self._get_host_driver(host)
        return driver.list_nodes()

    async def list_machines_all_hosts(self, hosts, loop):
        vms = [
            loop.run_in_executor(None, self.list_machines_single_host, host)
            for host in hosts
        ]
        return await asyncio.gather(*vms)

    def _list_machines__fetch_machines(self):
        from mist.api.machines.models import Machine
        nodes = []
        for machine in Machine.objects.filter(cloud=self.cloud,
                                              missing_since=None):
            if machine.extra.get('tags', {}).get('type') == 'hypervisor':
                driver = self._get_host_driver(machine)
                nodes += [node_to_dict(node)
                          for node in driver.list_nodes()]

        return nodes

    def _list_machines__fetch_generic_machines(self):
        machines = []
        from mist.api.machines.models import Machine
        all_machines = Machine.objects(cloud=self.cloud, missing_since=None)
        for machine in all_machines:
            if machine.extra.get('tags', {}).get('type') == 'hypervisor':
                machines.append(machine)

        return machines

    def _list_machines__update_generic_machine_state(self, machine):
        # Defaults
        machine.unreachable_since = None
        machine.state = config.STATES[NodeState.RUNNING.value]

        # If any of the probes has succeeded, then state is running
        if (
            machine.ssh_probe and not machine.ssh_probe.unreachable_since or
            machine.ping_probe and not machine.ping_probe.unreachable_since
        ):
            machine.state = config.STATES[NodeState.RUNNING.value]

        # If ssh probe failed, then unreachable since then
        if machine.ssh_probe and machine.ssh_probe.unreachable_since:
            machine.unreachable_since = machine.ssh_probe.unreachable_since
            machine.state = config.STATES[NodeState.UNKNOWN.value]
        # Else if ssh probe has never succeeded and ping probe failed,
        # then unreachable since then
        elif (not machine.ssh_probe and
              machine.ping_probe and machine.ping_probe.unreachable_since):
            machine.unreachable_since = machine.ping_probe.unreachable_since
            machine.state = config.STATES[NodeState.UNKNOWN.value]

    def _list_machines__machine_actions(self, machine, node_dict):
        super(LibvirtComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        machine.actions.clone = True
        machine.actions.undefine = False
        if node_dict['state'] is NodeState.TERMINATED.value:
            # In libvirt a terminated machine can be started.
            machine.actions.start = True
            machine.actions.undefine = True
            machine.actions.rename = True
        if node_dict['state'] is NodeState.RUNNING.value:
            machine.actions.suspend = True
        if node_dict['state'] is NodeState.SUSPENDED.value:
            machine.actions.resume = True

    def _list_machines__generic_machine_actions(self, machine):
        super(LibvirtComputeController,
              self)._list_machines__generic_machine_actions(machine)
        machine.actions.rename = True
        machine.actions.start = False
        machine.actions.stop = False
        machine.actions.destroy = False
        machine.actions.reboot = False

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        xml_desc = node_dict['extra'].get('xml_description')
        if xml_desc:
            escaped_xml_desc = escape(xml_desc)
            if machine.extra.get('xml_description') != escaped_xml_desc:
                machine.extra['xml_description'] = escaped_xml_desc
                updated = True
            import xml.etree.ElementTree as ET
            root = ET.fromstring(unescape(xml_desc))
            devices = root.find('devices')
            # TODO: rethink image association

            vnfs = []
            hostdevs = devices.findall('hostdev') + \
                devices.findall('interface[@type="hostdev"]')
            for hostdev in hostdevs:
                address = hostdev.find('source').find('address')
                vnf_addr = '%s:%s:%s.%s' % (
                    address.attrib.get('domain').replace('0x', ''),
                    address.attrib.get('bus').replace('0x', ''),
                    address.attrib.get('slot').replace('0x', ''),
                    address.attrib.get('function').replace('0x', ''),
                )
                vnfs.append(vnf_addr)
            if machine.extra.get('vnfs', []) != vnfs:
                machine.extra['vnfs'] = vnfs
                updated = True

        # Number of CPUs allocated to guest.
        if 'processors' in machine.extra and \
                machine.extra.get('cpus', []) != machine.extra['processors']:
            machine.extra['cpus'] = machine.extra['processors']
            updated = True

        # set machine's parent
        hypervisor = machine.extra.get('hypervisor', '')
        if hypervisor:
            try:
                from mist.api.machines.models import Machine
                parent = Machine.objects.get(cloud=machine.cloud,
                                             name=hypervisor)
            except Machine.DoesNotExist:
                # backwards compatibility
                hypervisor = hypervisor.replace('.', '-')
                try:
                    parent = Machine.objects.get(cloud=machine.cloud,
                                                 external_id=hypervisor)
                except me.DoesNotExist:
                    parent = None
            if machine.parent != parent:
                machine.parent = parent
                updated = True
        return updated

    def _list_machines__get_machine_extra(self, machine, node_dict):
        extra = copy.copy(node_dict['extra'])
        # make sure images_location is not overridden
        extra.update({'images_location': machine.extra.get('images_location')})
        return extra

    def _list_machines__get_size(self, node):
        return None

    def _list_machines__get_custom_size(self, node):
        if not node.get('size'):
            return
        from mist.api.clouds.models import CloudSize
        updated = False
        try:
            _size = CloudSize.objects.get(
                cloud=self.cloud, external_id=node['size'].get('name'))
        except me.DoesNotExist:
            _size = CloudSize(cloud=self.cloud,
                              external_id=node['size'].get('name'))
            updated = True
        if int(_size.ram or 0) != int(node['size'].get('ram', 0)):
            _size.ram = int(node['size'].get('ram'))
            updated = True
        if _size.cpus != node['size'].get('extra', {}).get('cpus'):
            _size.cpus = node['size'].get('extra', {}).get('cpus')
            updated = True
        if _size.disk != int(node['size'].get('disk')):
            _size.disk = int(node['size'].get('disk'))
        name = ""
        if _size.cpus:
            name += '%s CPUs, ' % _size.cpus
        if _size.ram:
            name += '%dMB RAM' % _size.ram
        if _size.disk:
            name += f', {_size.disk}GB disk.'
        if _size.name != name:
            _size.name = name
            updated = True
        if updated:
            _size.save()

        return _size

    def _list_machines__get_location(self, node):
        return node['extra'].get('hypervisor').replace('.', '-')

    def list_sizes(self, persist=True):
        return []

    def _list_locations__fetch_locations(self, persist=True):
        """
        We refer to hosts (KVM hypervisors) as 'location' for
        consistency purpose.
        """
        from mist.api.machines.models import Machine
        # FIXME: query parent for better performance
        hosts = Machine.objects(cloud=self.cloud,
                                missing_since=None,
                                parent=None)
        locations = [NodeLocation(id=host.external_id,
                                  name=host.name,
                                  country='', driver=None,
                                  extra=copy.deepcopy(host.extra))
                     for host in hosts]

        return locations

    def list_images_single_host(self, host):
        driver = self._get_host_driver(host)
        return driver.list_images(location=host.extra.get(
            'images_location', {}))

    async def list_images_all_hosts(self, hosts, loop):
        images = [
            loop.run_in_executor(None, self.list_images_single_host, host)
            for host in hosts
        ]
        return await asyncio.gather(*images)

    def _list_images__fetch_images(self, search=None):
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
        all_images = loop.run_until_complete(self.list_images_all_hosts(hosts,
                                                                        loop))
        return [image for host_images in all_images for image in host_images]

    def _list_images__postparse_image(self, image, image_libcloud):
        locations = []
        if image_libcloud.extra.get('host', ''):
            host_name = image_libcloud.extra.get('host')
            from mist.api.clouds.models import CloudLocation
            try:
                host = CloudLocation.objects.get(cloud=self.cloud,
                                                 name=host_name)
                locations.append(host.id)
            except me.DoesNotExist:
                host_name = host_name.replace('.', '-')
                try:
                    host = CloudLocation.objects.get(cloud=self.cloud,
                                                     external_id=host_name)
                    locations.append(host.id)
                except me.DoesNotExist:
                    pass
        image.extra.update({'locations': locations})

    def _get_libcloud_node(self, machine, no_fail=False):
        assert self.cloud == machine.cloud
        machine_type = machine.extra.get('tags', {}).get('type')
        host = machine if machine_type == 'hypervisor' else machine.parent

        driver = self._get_host_driver(host)

        for node in driver.list_nodes():
            if node.id == machine.external_id:
                return node

        if no_fail:
            return Node(machine.external_id, name=machine.external_id,
                        state=0, public_ips=[], private_ips=[],
                        driver=self.connection)
        raise MachineNotFoundError(
            "Machine with external_id '%s'." % machine.external_id
        )

    def _reboot_machine(self, machine, node):
        hypervisor = node.extra.get('tags', {}).get('type', None)
        if hypervisor == 'hypervisor':
            # issue an ssh command for the libvirt hypervisor
            try:
                hostname = node.public_ips[0] if \
                    node.public_ips else \
                    node.private_ips[0]
                command = '$(command -v sudo) shutdown -r now'
                # todo move it up
                from mist.api.methods import ssh_command
                ssh_command(self.cloud.owner, self.cloud.id,
                            node.id, hostname, command)
                return True
            except MistError as exc:
                log.error("Could not ssh machine %s", machine.name)
                raise
            except Exception as exc:
                log.exception(exc)
                # FIXME: Do not raise InternalServerError!
                raise InternalServerError(exc=exc)
        else:
            node.reboot()

    def _rename_machine(self, machine, node, name):
        if machine.extra.get('tags', {}).get('type') == 'hypervisor':
            machine.name = name
            machine.save()
            from mist.api.helpers import trigger_session_update
            trigger_session_update(machine.owner.id, ['clouds'])
        else:
            self._get_host_driver(machine).ex_rename_node(node, name)

    def remove_machine(self, machine):
        from mist.api.machines.models import KeyMachineAssociation
        KeyMachineAssociation.objects(machine=machine).delete()
        machine.missing_since = datetime.datetime.now()
        machine.save()
        if machine.machine_type == 'hypervisor':
            self.cloud.hosts.remove(machine.id)
            self.cloud.save()
        if amqp_owner_listening(self.cloud.owner.id):
            old_machines = [m.as_dict() for m in
                            self.cloud.ctl.compute.list_cached_machines()]
            new_machines = self.cloud.ctl.compute.list_machines()
            self.cloud.ctl.compute.produce_and_publish_patch(
                old_machines, new_machines)

    def _start_machine(self, machine, node):
        driver = self._get_host_driver(machine)
        return driver.ex_start_node(node)

    def _stop_machine(self, machine, node):
        driver = self._get_host_driver(machine)
        return driver.ex_stop_node(node)

    def _resume_machine(self, machine, node):
        driver = self._get_host_driver(machine)
        return driver.ex_resume_node(node)

    def _destroy_machine(self, machine, node):
        driver = self._get_host_driver(machine)
        return driver.destroy_node(node)

    def _suspend_machine(self, machine, node):
        driver = self._get_host_driver(machine)
        return driver.ex_suspend_node(node)

    def _undefine_machine(self, machine, node, delete_domain_image=False):
        if machine.extra.get('active'):
            raise BadRequestError('Cannot undefine an active domain')
        driver = self._get_host_driver(machine)
        result = driver.ex_undefine_node(node)
        if delete_domain_image and result:
            xml_description = node.extra.get('xml_description', '')
            if xml_description:
                index1 = xml_description.index("source file") + 13
                index2 = index1 + xml_description[index1:].index('\'')
                image_path = xml_description[index1:index2]
                driver._run_command("rm {}".format(image_path))
        return result

    def _clone_machine(self, machine, node, name, resume):
        driver = self._get_host_driver(machine)
        return driver.ex_clone_node(node, new_name=name)

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('cpu')

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        """
        Parse network interfaces.
        - If networks_dict is empty, no network interface will be configured.
        - If only `id` or `name` is given, the interface will be
        configured by DHCP.
        - If `ip` is given, it will be statically assigned to the interface and
          optionally `gateway` and `primary` attributes will be used.
        """
        from mist.api.methods import list_resources
        from libcloud.utils.networking import is_valid_ip_address

        if not networks_dict:
            return None

        ret_dict = {
            'networks': [],
        }
        networks = networks_dict.get('networks', [])
        for net in networks:
            network_id = net.get('id') or net.get('name')
            if not network_id:
                raise BadRequestError('network id or name is required')
            try:
                [network], _ = list_resources(auth_context, 'network',
                                              search=network_id,
                                              cloud=self.cloud.id,
                                              limit=1)
            except ValueError:
                raise NotFoundError('Network does not exist')

            nid = {
                'network_name': network.name
            }
            if net.get('ip'):
                if is_valid_ip_address(net['ip']):
                    nid['ip'] = net['ip']
                else:
                    raise BadRequestError('IP given is invalid')
                if net.get('gateway'):
                    if is_valid_ip_address(net['gateway']):
                        nid['gateway'] = net['gateway']
                    else:
                        raise BadRequestError('Gateway IP given is invalid')
                if net.get('primary'):
                    nid['primary'] = net['primary']
            ret_dict['networks'].append(nid)

        if networks_dict.get('vnfs'):
            ret_dict['vnfs'] = networks_dict['vnfs']

        return ret_dict

    def _generate_plan__parse_disks(self, auth_context, disks_dict):
        ret_dict = {
            'disk_size': disks_dict.get('disk_size', 4),
        }
        if disks_dict.get('disk_path'):
            ret_dict['disk_path'] = disks_dict.get('disk_path')

        return ret_dict

    def _create_machine__get_image_object(self, image):
        from mist.api.images.models import CloudImage
        try:
            cloud_image = CloudImage.objects.get(id=image)
        except me.DoesNotExist:
            raise NotFoundError('Image does not exist')
        return cloud_image.external_id

    def _create_machine__get_size_object(self, size):
        if isinstance(size, dict):
            return size
        from mist.api.clouds.models import CloudSize
        try:
            cloud_size = CloudSize.objects.get(id=size)
        except me.DoesNotExist:
            raise NotFoundError('Size does not exist')
        return {'cpus': cloud_size.cpus, 'ram': cloud_size.ram}

    def _create_machine__get_location_object(self, location):
        from mist.api.clouds.models import CloudLocation
        try:
            cloud_location = CloudLocation.objects.get(id=location)
        except me.DoesNotExist:
            raise NotFoundError('Location does not exist')
        return cloud_location.external_id

    def _create_machine__compute_kwargs(self, plan):
        from mist.api.machines.models import Machine
        kwargs = super()._create_machine__compute_kwargs(plan)
        location_id = kwargs.pop('location')
        try:
            host = Machine.objects.get(
                cloud=self.cloud, external_id=location_id)
        except me.DoesNotExist:
            raise MachineCreationError("The host specified does not exist")
        driver = self._get_host_driver(host)
        kwargs['driver'] = driver
        size = kwargs.pop('size')
        kwargs['cpu'] = size['cpus']
        kwargs['ram'] = size['ram']
        if kwargs.get('auth'):
            kwargs['public_key'] = kwargs.pop('auth').public
        kwargs['disk_size'] = plan['disks'].get('disk_size')
        kwargs['disk_path'] = plan['disks'].get('disk_path')
        kwargs['networks'] = plan.get('networks', {}).get('networks', [])
        kwargs['vnfs'] = plan.get('networks', {}).get('vnfs', [])
        kwargs['cloud_init'] = plan.get('cloudinit')

        return kwargs

    def _create_machine__create_node(self, kwargs):
        driver = kwargs.pop('driver')
        node = driver.create_node(**kwargs)
        return node


class OnAppComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.ONAPP)(key=self.cloud.username,
                                          secret=self.cloud.apikey.value,
                                          host=self.cloud.host,
                                          verify=self.cloud.verify)

    def _list_machines__machine_actions(self, machine, node_dict):
        super(OnAppComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        machine.actions.resize = True
        if node_dict['state'] is NodeState.RUNNING.value:
            machine.actions.suspend = True
        if node_dict['state'] is NodeState.SUSPENDED.value:
            machine.actions.resume = True

    def _list_machines__machine_creation_date(self, machine, node_dict):
        created_at = node_dict['extra'].get('created_at')
        created_at = iso8601.parse_date(created_at)
        created_at = pytz.UTC.normalize(created_at)
        return created_at

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False

        os_type = node_dict['extra'].get('operating_system', 'linux')
        # on a VM this has been freebsd and it caused list_machines to raise
        # exception due to validation of machine model
        if os_type not in ('unix', 'linux', 'windows', 'coreos'):
            os_type = 'linux'
        if os_type != machine.os_type:
            machine.os_type = os_type
            updated = True

        image_id = machine.extra.get('template_label') \
            or machine.extra.get('operating_system_distro')
        if image_id != machine.extra.get('image_id'):
            machine.extra['image_id'] = image_id
            updated = True

        if machine.extra.get('template_label'):
            machine.extra.pop('template_label', None)
            updated = True

        size = "%scpu, %sM ram" % \
            (machine.extra.get('cpus'), machine.extra.get('memory'))
        if size != machine.extra.get('size'):
            machine.extra['size'] = size
            updated = True

        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        if node_dict['state'] == NodeState.STOPPED.value:
            cost_per_hour = node_dict['extra'].get(
                'price_per_hour_powered_off', 0)
        else:
            cost_per_hour = node_dict['extra'].get('price_per_hour', 0)
        return cost_per_hour, 0

    def _list_machines__get_custom_size(self, node):
        # FIXME: resolve circular import issues
        from mist.api.clouds.models import CloudSize
        _size = CloudSize(cloud=self.cloud,
                          external_id=str(node['extra'].get('id')))
        _size.ram = node['extra'].get('memory')
        _size.cpus = node['extra'].get('cpus')
        _size.save()
        return _size

    def _resume_machine(self, machine, node):
        return self.connection.ex_resume_node(node)

    def _suspend_machine(self, machine, node):
        return self.connection.ex_suspend_node(node)

    def _resize_machine(self, machine, node, node_size, kwargs):
        # send only non empty valid args
        valid_kwargs = {}
        for param in kwargs:
            if param in ['memory', 'cpus', 'cpu_shares', 'cpu_units'] \
                    and kwargs[param]:
                valid_kwargs[param] = kwargs[param]
        try:
            return self.connection.ex_resize_node(node,
                                                  **valid_kwargs)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_locations__fetch_locations(self):
        """Get locations

        We will perform a few calls to get hypervisor_group_id
        parameter sent for create machine, and the max sizes to
        populate the create machine wizard for cpu/disk/memory,
        since this info can be retrieved per location.
        We will also get network information and match it per
        location, useful only to choose network on new VMs

        """
        # calls performed:
        # 1) get list of compute zones - associate
        # location with hypervisor_group_id, max_cpu, max_memory
        # 2) get data store zones and data stores to get max_disk_size
        # 3) get network ids per location

        locations = self.connection.list_locations()
        if locations:
            hypervisors = self.connection.connection.request(
                "/settings/hypervisor_zones.json")
            for l in locations:
                for hypervisor in hypervisors.object:
                    h = hypervisor.get("hypervisor_group")
                    if str(h.get("location_group_id")) == l.id:
                        # get max_memory/max_cpu
                        l.extra["max_memory"] = h.get("max_host_free_memory")
                        l.extra["max_cpu"] = h.get("max_host_cpu")
                        l.extra["hypervisor_group_id"] = h.get("id")
                        break

            try:
                data_store_zones = self.connection.connection.request(
                    "/settings/data_store_zones.json").object
                data_stores = self.connection.connection.request(
                    "/settings/data_stores.json").object
            except:
                pass

            for l in locations:
                # get data store zones, and match with locations
                # through location_group_id
                # then calculate max_disk_size per data store,
                # by matching data store zones and data stores
                try:
                    store_zones = [dsg for dsg in data_store_zones if l.id is
                                   str(dsg['data_store_group']
                                       ['location_group_id'])]
                    for store_zone in store_zones:
                        stores = [store for store in data_stores if
                                  store['data_store']['data_store_group_id'] is
                                  store_zone['data_store_group']['id']]
                        for store in stores:
                            l.extra['max_disk_size'] = store['data_store']
                            ['data_store_size'] - store['data_store']['usage']
                except:
                    pass

            try:
                networks = self.connection.connection.request(
                    "/settings/network_zones.json").object
            except:
                pass

            for l in locations:
                # match locations with network ids (through location_group_id)
                l.extra['networks'] = []

                try:
                    for network in networks:
                        net = network["network_group"]
                        if str(net["location_group_id"]) == l.id:
                            l.extra['networks'].append({'name': net['label'],
                                                        'id': net['id']})
                except:
                    pass

        return locations

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('min_disk_size'))
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _list_images__get_min_memory_size(self, image):
        try:
            min_memory_size = int(image.extra.get('min_memory_size'))
        except (TypeError, ValueError):
            return None
        return min_memory_size


class OtherComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return None

    def _list_machines__fetch_machines(self):
        return []

    def _list_machines__update_generic_machine_state(self, machine):
        """Update generic machine state (based on ping/ssh probes)

        It is only used in generic machines.
        """

        # Defaults
        machine.unreachable_since = None

        # If any of the probes has succeeded, then state is running
        if (
            machine.ssh_probe and not machine.ssh_probe.unreachable_since or
            machine.ping_probe and not machine.ping_probe.unreachable_since
        ):
            machine.state = config.STATES[NodeState.RUNNING.value]
        # If ssh probe failed, then unreachable since then
        elif machine.ssh_probe and machine.ssh_probe.unreachable_since:
            machine.unreachable_since = machine.ssh_probe.unreachable_since
            machine.state = config.STATES[NodeState.UNKNOWN.value]
        # Else if ssh probe has never succeeded and ping probe failed,
        # then unreachable since then
        elif (not machine.ssh_probe and
              machine.ping_probe and machine.ping_probe.unreachable_since):
            machine.unreachable_since = machine.ping_probe.unreachable_since
            machine.state = config.STATES[NodeState.UNKNOWN.value]
        else:  # Assume running if no indication otherwise
            machine.state = config.STATES[NodeState.RUNNING.value]

    def _list_machines__generic_machine_actions(self, machine):
        """Update an action for a bare metal machine

        Bare metal machines only support remove, reboot and tag actions"""

        super(OtherComputeController,
              self)._list_machines__generic_machine_actions(machine)
        machine.actions.remove = True

    def _get_libcloud_node(self, machine):
        return None

    def _list_machines__fetch_generic_machines(self):
        from mist.api.machines.models import Machine
        return Machine.objects(cloud=self.cloud, missing_since=None)

    def reboot_machine(self, machine):
        return self.reboot_machine_ssh(machine)

    def remove_machine(self, machine):
        from mist.api.machines.models import KeyMachineAssociation
        KeyMachineAssociation.objects(machine=machine).delete()
        machine.missing_since = datetime.datetime.now()
        machine.save()

    def list_images(self, persist=True, search=None):
        return []

    def list_sizes(self, persist=True):
        return []

    def list_locations(self, persist=True):
        return []


class _KubernetesBaseComputeController(BaseComputeController):
    def _connect(self, provider, use_container_driver=True, **kwargs):
        host, port = dnat(self.cloud.owner,
                          self.cloud.host, self.cloud.port)
        url = f'https://{sanitize_host(host)}:{port}'

        try:
            requests.get(url, verify=False, timeout=15)
        except (ConnectionError, ConnectTimeout):
            raise Exception("Make sure host is accessible. ")
        if use_container_driver:
            get_driver_method = get_container_driver
        else:
            get_driver_method = get_driver

        ca_cert = None
        if self.cloud.ca_cert_file:
            ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            ca_cert_temp_file.write(self.cloud.ca_cert_file.value.encode())
            ca_cert_temp_file.close()
            ca_cert = ca_cert_temp_file.name

        # tls authentication
        if self.cloud.key_file and self.cloud.cert_file:
            key_temp_file = tempfile.NamedTemporaryFile(delete=False)
            key_temp_file.write(self.cloud.key_file.value.encode())
            key_temp_file.close()
            key_file = key_temp_file.name
            cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            cert_temp_file.write(self.cloud.cert_file.value.encode())
            cert_temp_file.close()
            cert_file = cert_temp_file.name

            return get_driver_method(provider)(secure=True,
                                               host=host,
                                               port=port,
                                               key_file=key_file,
                                               cert_file=cert_file,
                                               ca_cert=ca_cert)

        elif self.cloud.token:
            token = self.cloud.token.value

            return get_driver_method(provider)(key=token,
                                               secure=True,
                                               host=host,
                                               port=port,
                                               ca_cert=ca_cert,
                                               ex_token_bearer_auth=True)
        # username/password auth
        elif self.cloud.username and self.cloud.password:
            key = self.cloud.username.value
            secret = self.cloud.password.value

            return get_driver_method(provider)(key=key,
                                               secret=secret,
                                               secure=True,
                                               host=host,
                                               port=port)
        else:
            msg = '''Necessary parameters for authentication are missing.
            Either a key_file/cert_file pair or a username/pass pair
            or a bearer token.'''
            raise ValueError(msg)

    def _list_machines__machine_actions(self, machine, node_dict):
        super()._list_machines__machine_actions(machine, node_dict)
        machine.actions.start = True
        machine.actions.stop = True
        machine.actions.reboot = True
        machine.actions.destroy = True

    def _reboot_machine(self, machine, node):
        return self.connection.reboot_node(node)

    def _start_machine(self, machine, node):
        return self.connection.start_node(node)

    def _stop_machine(self, machine, node):
        return self.connection.stop_node(node)

    def _destroy_machine(self, machine, node):
        res = self.connection.destroy_node(node)
        if res:
            if machine.extra.get('pvcs'):
                # FIXME: resolve circular import issues
                from mist.api.models import Volume
                volumes = Volume.objects.filter(cloud=self.cloud)
                for volume in volumes:
                    if machine.id in volume.attached_to:
                        volume.attached_to.remove(machine.id)

    def _list_machines__get_location(self, node):
        return node.get('extra', {}).get('namespace', "")

    def _list_machines__get_image(self, node):
        return node.get('image', {}).get('id')

    def _list_machines__get_size(self, node):
        return node.get('size', {}).get('id')

    def _list_sizes__get_cpu(self, size):
        cpu = int(size.extra.get('cpus') or 1)
        if cpu > 1000:
            cpu = cpu / 1000
        elif cpu > 99:
            cpu = 1
        return cpu


class KubernetesComputeController(_KubernetesBaseComputeController):
    def _connect(self, **kwargs):
        return super()._connect(Container_Provider.KUBERNETES, **kwargs)

    def check_connection(self):
        try:
            self._connect().list_namespaces()
        except InvalidCredsError as e:
            raise CloudUnauthorizedError(str(e))

    def list_namespaces(self):
        return [node_to_dict(ns) for ns in self.connection.list_namespaces()]

    def list_services(self):
        return self.connection.ex_list_services()

    def get_version(self):
        return self.connection.ex_get_version()

    def get_node_resources(self):
        nodes = self._list_nodes()
        available_cpu = 0
        available_memory = 0
        used_cpu = 0
        used_memory = 0
        for node in nodes:
            available_cpu += to_n_cpus(
                node['extra']['cpu'])
            available_memory += to_n_bytes(
                node['extra']['memory'])
            used_cpu += to_n_cpus(
                node['extra']['usage']['cpu'])
            used_memory += to_n_bytes(
                node['extra']['usage']['memory'])
        return dict(cpu=to_cpu_str(available_cpu),
                    memory=to_memory_str(
                        available_memory),
                    usage=dict(cpu=to_cpu_str(used_cpu),
                               memory=to_memory_str(
                                   used_memory)))

    def _list_nodes(self, return_node_map=False):
        node_map = {}
        nodes = []
        try:
            nodes_metrics = self.connection.ex_list_nodes_metrics()
        except BaseHTTPError:
            nodes_metrics = []
        nodes_metrics_dict = {node_metrics['metadata']['name']: node_metrics
                              for node_metrics in nodes_metrics}
        for node in self.connection.ex_list_nodes():
            node_map[node.name] = node.id
            node.type = 'node'
            node.os = node.extra.get('os')
            node_metrics = nodes_metrics_dict.get(node.name)
            if node_metrics:
                node.extra['usage'] = node_metrics['usage']
            nodes.append(node_to_dict(node))
        if return_node_map:
            return nodes, node_map
        return nodes

    def _list_machines__fetch_machines(self):
        """List all kubernetes machines: nodes, pods and containers"""
        nodes, node_map = self._list_nodes(return_node_map=True)
        pod_map = {}
        pods = []
        pod_containers = []
        try:
            pods_metrics = self.connection.ex_list_pods_metrics()
        except BaseHTTPError:
            pods_metrics = []
        pods_metrics_dict = {pods_metrics['metadata']['name']: pods_metrics
                             for pods_metrics in pods_metrics}
        containers_metrics_dict = {}
        for pod in self.connection.ex_list_pods():
            pod.type = 'pod'
            pod_map[pod.name] = pod.id
            pod_containers += pod.containers
            pod.parent_id = node_map.get(pod.node_name)
            pod.public_ips, pod.private_ips = [], []
            for ip in pod.ip_addresses:
                if is_private_subnet(ip):
                    pod.private_ips.append(ip)
                else:
                    pod.public_ips.append(ip)
            containers_metrics = pods_metrics_dict.get(
                pod.name, {}).get('containers')
            if containers_metrics:
                total_usage = {'cpu': 0, 'memory': 0}
                for container_metrics in containers_metrics:
                    containers_metrics_dict.setdefault(pod.id, {})[
                        container_metrics['name']] = container_metrics
                    ctr_cpu_usage = container_metrics['usage']['cpu']
                    ctr_memory_usage = container_metrics['usage']['memory']
                    total_usage['cpu'] += to_n_cpus(
                        ctr_cpu_usage)
                    total_usage['memory'] += \
                        to_n_bytes(
                            ctr_memory_usage)
                total_usage['cpu'] = to_cpu_str(total_usage['cpu'])
                total_usage['memory'] = to_memory_str(
                    total_usage['memory']
                )
                pod.extra['usage'] = {
                    'containers': containers_metrics,
                    'total': total_usage
                }
            pod.extra['namespace'] = pod.namespace
            pods.append(node_to_dict(pod))
        containers = []
        for container in pod_containers:
            container.type = 'container'
            container.public_ips, container.private_ips = [], []
            container.parent_id = pod_map.get(container.extra['pod'])
            metrics = containers_metrics_dict.get(
                container.parent_id, {}).get(container.name)
            if metrics:
                container.extra['usage'] = metrics['usage']
            containers.append(node_to_dict(container))
        machines = nodes + pods + containers
        return machines

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        node_type = node_dict['type']
        if machine.machine_type != node_type:
            machine.machine_type = node_type
            updated = True
        node_parent_id = node_dict.get('parent_id')
        if node_parent_id:
            from mist.api.machines.models import Machine
            try:
                machine_parent = Machine.objects.get(
                    cloud=machine.cloud, external_id=node_parent_id)
            except Machine.DoesNotExist:
                pass
            else:
                if machine.parent != machine_parent:
                    machine.parent = machine_parent
                    updated = True
        node_cpu = node_dict.get('extra', {}).get('cpu')
        if node_cpu and (isinstance(node_cpu, int) or node_cpu.isdigit()):
            machine.cores = float(node_cpu)
            updated = True
        os_type = node_dict.get('extra', {}).get('os')
        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True
        return updated

    def _list_machines__get_custom_image(self, node_dict):
        updated = False
        from mist.api.images.models import CloudImage
        node_image = node_dict.get('image')
        if node_image is None:
            return None
        image_id = node_image.get('id')
        if image_id is None or image_id == 'undefined':
            return None
        try:
            image = CloudImage.objects.get(cloud=self.cloud,
                                           external_id=image_id)
        except CloudImage.DoesNotExist:
            image = CloudImage(cloud=self.cloud,
                               external_id=str(image_id),
                               name=node_image.get('name'),
                               extra=node_image.get('extra'))
            updated = True
        if updated:
            image.save()
        return image

    def _list_machines__get_custom_size(self, node_dict):
        node_size = node_dict.get('size')
        if node_size is None:
            return None
        from mist.api.clouds.models import CloudSize
        updated = False
        size_id = node_size.get('id')
        try:
            size = CloudSize.objects.get(
                cloud=self.cloud, external_id=str(size_id))
        except me.DoesNotExist:
            size = CloudSize(cloud=self.cloud,
                             external_id=str(size_id))
            updated = True
        ram = node_size.get('ram')
        if size.ram != ram:
            if isinstance(ram, str) and ram.isalnum():
                ram = to_n_bytes(ram)
            size.ram = ram
            updated = True
        cpu = node_size.get('cpu')
        if size.cpus != cpu:
            size.cpus = cpu
            updated = True
        disk = node_size.get('disk')
        if size.disk != disk:
            size.disk = disk
            updated = True
        name = node_size.get('name')
        if size.name != name:
            size.name = name
            updated = True
        if updated:
            size.save()
        return size

    def _list_machines__get_machine_extra(self, machine, node_dict):
        node_extra = node_dict.get('extra')
        return copy.copy(node_extra) if node_extra else {}

    def _list_machines__machine_actions(self, machine, node_dict):
        machine.actions.start = False
        machine.actions.stop = False
        machine.actions.reboot = False
        machine.actions.rename = False
        machine.actions.expose = False
        machine.actions.resume = False
        machine.actions.suspend = False
        machine.actions.undefine = False
        machine.actions.tag = True
        machine.actions.destroy = True

    def _get_libcloud_node(self, machine):
        """Return an instance of a libcloud node"""
        assert self.cloud == machine.cloud
        nodes = self.connection.ex_list_nodes() + \
            self.connection.ex_list_pods() + \
            self.connection.list_containers()
        for node in nodes:
            if node.id == machine.external_id:
                return node
        raise MachineNotFoundError(
            "Machine with external_id '%s'." % machine.external_id
        )

    def _destroy_machine(self, machine, node):
        if isinstance(node, KubernetesNode):
            self.connection.ex_destroy_node(node.name)
        elif isinstance(node, KubernetesPod):
            self.connection.ex_destroy_pod(node.namespace, node.name)
        elif isinstance(node, Container):
            self.connection.destroy_container(node)


class OpenShiftComputeController(KubernetesComputeController):
    def _connect(self, **kwargs):
        host, port = dnat(self.cloud.owner,
                          self.cloud.host, self.cloud.port)
        try:
            socket.setdefaulttimeout(15)
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.connect((sanitize_host(host), int(port)))
            so.close()
        except Exception:
            raise Exception("Make sure host is accessible "
                            "and kubernetes port is specified")
        # username/password auth
        if self.cloud.username and self.cloud.password:
            key = self.cloud.username
            secret = self.cloud.password
            return get_container_driver(Container_Provider.OPENSHIFT)(
                key=key,
                secret=secret,
                secure=True,
                host=host,
                port=port)
        else:
            msg = '''Necessary parameters for authentication are missing.
            Either a key_file/cert_file pair or a username/pass pair
            or a bearer token.'''
            raise ValueError(msg)


class KubeVirtComputeController(_KubernetesBaseComputeController):
    def _connect(self, **kwargs):
        return super()._connect(Provider.KUBEVIRT,
                                use_container_driver=False,
                                **kwargs)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        if machine.machine_type != 'container':
            machine.machine_type = 'container'
            updated = True

        if node_dict['extra']['pvcs']:
            pvcs = node_dict['extra']['pvcs']
            from mist.api.models import Volume
            volumes = Volume.objects.filter(
                cloud=self.cloud, missing_since=None)
            for volume in volumes:
                if 'pvc' in volume.extra:
                    if volume.extra['pvc']['name'] in pvcs:
                        if machine not in volume.attached_to:
                            volume.attached_to.append(machine)
                            volume.save()
                            updated = True
        return updated

    def _list_machines__machine_actions(self, machine, node_dict):
        super()._list_machines__machine_actions(machine, node_dict)
        machine.actions.expose = True

    def expose_port(self, machine, port_forwards):
        machine_libcloud = self._get_libcloud_node(machine)

        # validate input
        from mist.api.machines.methods import validate_portforwards_kubevirt
        data = validate_portforwards_kubevirt(port_forwards)

        self.connection.ex_create_service(machine_libcloud, data.get(
                                          'ports', []),
                                          service_type=data.get(
                                              'service_type'),
                                          override_existing_ports=True,
                                          cluster_ip=data.get(
                                              'cluster_ip', None),
                                          load_balancer_ip=data.get(
                                              'load_balancer_ip', None))


class CloudSigmaComputeController(BaseComputeController):
    def _connect(self, **kwargs):
        return get_driver(Provider.CLOUDSIGMA)(
            key=self.cloud.username,
            secret=self.cloud.password.value,
            region=self.cloud.region)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        if node_dict['extra'].get('runtime'):
            return node_dict['extra']['runtime'].get('active_since')

    def _list_machines__cost_machine(self, machine, node_dict):
        from mist.api.volumes.models import Volume
        try:
            pricing = machine.location.extra['pricing']
        except KeyError:
            return 0, 0

        # cloudsigma calculates pricing using GHz/hour
        # where 2 GHz = 1 core
        cpus = node_dict['extra']['cpus'] * 2
        # machine memory in GBs as pricing uses GB/hour
        memory = node_dict['extra']['memory'] / 1024

        volume_uuids = [item['drive']['uuid'] for item
                        in node_dict['extra']['drives']]
        volumes = Volume.objects(cloud=self.cloud,
                                 missing_since=None,
                                 external_id__in=volume_uuids)
        ssd_size = 0
        hdd_size = 0
        for volume in volumes:
            if volume.extra['storage_type'] == 'dssd':
                ssd_size += volume.size
            else:
                hdd_size += volume.size
        # cpu and memory pricing per hour
        cpu_price = cpus * float(pricing['intel_cpu']['price'])
        memory_price = memory * float(pricing['intel_mem']['price'])
        # disk pricing per month
        ssd_price = ssd_size * float(pricing['dssd']['price'])
        hdd_price = hdd_size * float(pricing['zadara']['price'])
        cost_per_month = ((24 * 30 * (cpu_price + memory_price)) +
                          ssd_price + hdd_price)
        return 0, cost_per_month

    def _list_machines__get_location(self, node):
        return self.connection.region

    def _list_machines__get_size(self, node):
        return node['size'].get('id')

    def _list_machines__get_custom_size(self, node_dict):
        from mist.api.clouds.models import CloudSize
        updated = False
        try:
            _size = CloudSize.objects.get(
                cloud=self.cloud,
                external_id=str(node_dict['size'].get('id')))
        except me.DoesNotExist:
            _size = CloudSize(cloud=self.cloud,
                              external_id=str(node_dict['size'].get('id')))
            updated = True

        if _size.ram != node_dict['size'].get('ram'):
            _size.ram = node_dict['size'].get('ram')
            updated = True
        if _size.cpus != node_dict['size'].get('cpu'):
            _size.cpus = node_dict['size'].get('cpu')
            updated = True
        if _size.disk != node_dict['size'].get('disk'):
            _size.disk = node_dict['size'].get('disk')
            updated = True
        if _size.name != node_dict['size'].get('name'):
            _size.name = node_dict['size'].get('name')
            updated = True

        if updated:
            _size.save()
        return _size

    def _destroy_machine(self, machine, node):
        if node.state == NodeState.RUNNING.value:
            self.connection.ex_stop_node(node)
        ret_val = False
        for _ in range(10):
            try:
                self.connection.destroy_node(node)
            except Exception:
                sleep(1)
                continue
            else:
                ret_val = True
                break
        return ret_val

    def _list_locations__fetch_locations(self):
        from libcloud.common.cloudsigma import API_ENDPOINTS_2_0
        attributes = API_ENDPOINTS_2_0[self.connection.region]
        pricing = self.connection.ex_get_pricing()
        # get only the default burst level pricing for resources in USD
        pricing = {item.pop('resource'): item for item in pricing['objects']
                   if item['level'] == 0 and item['currency'] == 'USD'}

        location = NodeLocation(id=self.connection.region,
                                name=attributes['name'],
                                country=attributes['country'],
                                driver=self.connection,
                                extra={
                                    'pricing': pricing,
                                })
        return [location]

    def _list_sizes__get_cpu(self, size):
        cpus = int(round(size.cpu))
        if cpus == 0:
            cpus = 1
        return cpus

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size parameter is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')
        if size < 1:
            raise BadRequestError('Volume size should be at least 1 GBs')

        try:
            name = volume_dict['name']
        except KeyError:
            raise BadRequestError('Volume name parameter is required')

        return {
            'name': name,
            'size': size,
        }

    def _generate_plan__parse_disks(self,
                                    auth_context,
                                    disks_dict):
        disk_size = disks_dict.get('disk_size')
        if disk_size:
            try:
                disk_size = int(disk_size)
            except (TypeError, ValueError):
                raise BadRequestError('Invalid disk size type')

            return {
                'size': disk_size
            }

    def _generate_plan__post_parse_plan(self, plan) -> None:
        # In CloudSigma we have both custom sizes and "standard" sizes
        # from their "Simple Server Creation" wizard.
        # If a custom size is provided then it's necessary to provide
        # the disk size.

        if plan['size'].get('cpus'):
            try:
                plan['size']['disk'] = plan['disks']['size']
            except KeyError:
                raise BadRequestError(
                    'Disk size is required when providing a custom size'
                )

    def _create_machine__get_size_object(self, size):
        from libcloud.compute.drivers.cloudsigma import CloudSigmaNodeSize
        if isinstance(size, str):
            from mist.api.clouds.models import CloudSize
            size = CloudSize.objects.get(id=size)
            cpus = size.cpus
            ram = size.ram
            disk = size.disk
        else:
            cpus = size['cpus']
            ram = size['ram']
            disk = size['disk']

        return CloudSigmaNodeSize(
            id=None,
            name=None,
            cpu=cpus,
            ram=ram,
            disk=disk,
            bandwidth=None,
            price=None,
            driver=self.connection
        )

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)

        mist_key = kwargs.pop('auth')
        key_pairs = self.connection.list_key_pairs()
        key = next((key_pair for key_pair in key_pairs
                    if key_pair.public_key == mist_key.public),
                   None)
        if key is None:
            key = self.connection.import_key_pair_from_string(
                mist_key.name,
                mist_key.public)
        kwargs['public_keys'] = [key.extra['uuid']]

        if plan.get('cloudinit'):
            kwargs['ex_metadata'] = {
                'base64_fields': 'cloudinit-user-data',
                'cloudinit-user-data': base64.b64encode(
                    plan['cloudinit'].encode('utf-8')).decode('utf-8')
            }

        # Volumes can be attached only when the machine is stopped
        if plan.get('volumes'):
            kwargs['ex_boot'] = False

        return kwargs

    def _create_machine__create_node(self, kwargs):
        node = super()._create_machine__create_node(kwargs)
        node.extra['username'] = 'cloudsigma'
        return node

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        from mist.api.volumes.models import Volume
        from libcloud.compute.base import StorageVolume

        volumes = plan.get('volumes', [])
        for volume in volumes:
            if volume.get('id'):
                vol = Volume.objects.get(id=volume['id'])
                libcloud_vol = StorageVolume(id=vol.external_id,
                                             name=vol.name,
                                             size=vol.size,
                                             driver=self.connection,
                                             extra=vol.extra)
                try:
                    self.connection.attach_volume(node, libcloud_vol)
                except Exception:
                    log.exception(
                        'Failed to attach existing volume to machine')
            else:
                name = volume['name']
                size = volume['size']
                try:
                    libcloud_vol = self.connection.create_volume(name=name,
                                                                 size=size)
                except Exception:
                    log.exception('Failed to create volume')
                else:
                    try:
                        self.connection.attach_volume(node, libcloud_vol)
                    except Exception:
                        log.exception('Failed to attach volume to machine')

        if kwargs.get('ex_boot') is False:
            self.connection.start_node(node)
