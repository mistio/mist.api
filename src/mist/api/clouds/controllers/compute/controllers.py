"""Cloud ComputeControllers

A cloud controller handles all operations that can be performed on a cloud,
commonly using libcloud under the hood.

It also performs several steps and combines the information stored in the
database with that returned from API calls to providers.

For each different cloud type, there is a corresponding cloud controller
defined here. All the different classes inherit BaseComputeController and share
a commmon interface, with the exception that some controllers may not have
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

import mongoengine as me

from time import sleep
from html import unescape

from xml.sax.saxutils import escape

from libcloud.pricing import get_size_price
from libcloud.compute.base import Node, NodeImage, NodeLocation
from libcloud.compute.providers import get_driver
from libcloud.container.providers import get_driver as get_container_driver
from libcloud.compute.types import Provider, NodeState
from libcloud.container.types import Provider as Container_Provider
from libcloud.container.types import ContainerState
from libcloud.container.base import ContainerImage, Container
from mist.api.exceptions import MistError
from mist.api.exceptions import InternalServerError
from mist.api.exceptions import MachineNotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError
from mist.api.helpers import sanitize_host

from mist.api.misc.cloud import CloudImage

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

    def _connect(self):
        return get_driver(Provider.EC2)(self.cloud.apikey,
                                        self.cloud.apisecret,
                                        region=self.cloud.region)

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(AmazonComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        machine.actions.rename = True
        if machine_libcloud.state != NodeState.TERMINATED:
            machine.actions.resize = True

    def _resize_machine(self, machine, machine_libcloud, node_size, kwargs):
        attributes = {'InstanceType.Value': node_size.id}
        # instance must be in stopped mode
        if machine_libcloud.state != NodeState.STOPPED:
            raise BadRequestError('The instance has to be stopped '
                                  'in order to be resized')
        try:
            self.connection.ex_modify_instance_attribute(machine_libcloud,
                                                         attributes)
            self.connection.ex_start_node(machine_libcloud)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        # Find os_type.
        try:
            os_type = CloudImage.objects.get(
                cloud_provider=machine_libcloud.driver.type,
                image_id=machine_libcloud.extra.get('image_id'),
            ).os_type
        except:
            # This is windows for windows servers and None for Linux.
            os_type = machine_libcloud.extra.get('platform')
        os_type = os_type or 'linux'
        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True

        try:
            # return list of ids for network interfaces as str
            network_interfaces = machine.extra['network_interfaces']
            network_interfaces = [network_interface.id for network_interface
                                  in network_interfaces]
            network_interfaces = ','.join(network_interfaces)
        except:
            network_interfaces = []

        if network_interfaces != machine.extra['network_interfaces']:
            machine.extra['network_interfaces'] = network_interfaces
            updated = True

        network_id = machine_libcloud.extra.get('vpc_id')

        if machine.extra['network'] != network_id:
            machine.extra['network'] = network_id
            updated = True

        # Discover network of machine.
        from mist.api.networks.models import Network
        try:
            network = Network.objects.get(cloud=self.cloud,
                                          network_id=network_id,
                                          missing_since=None)
        except Network.DoesNotExist:
            network = None

        if network != machine.network:
            machine.network = network
            updated = True

        subnet_id = machine.extra.get('subnet_id')
        if machine.extra['subnet'] != subnet_id:
            machine.extra['subnet'] = subnet_id
            updated = True

        # Discover subnet of machine.
        from mist.api.networks.models import Subnet
        try:
            subnet = Subnet.objects.get(subnet_id=subnet_id,
                                        network=machine.network,
                                        missing_since=None)
        except Subnet.DoesNotExist:
            subnet = None
        if subnet != machine.subnet:
            machine.subnet = subnet
            updated = True

        return updated

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        # TODO: stopped instances still charge for the EBS device
        # https://aws.amazon.com/ebs/pricing/
        # Need to add this cost for all instances
        if machine_libcloud.state == NodeState.STOPPED:
            return 0, 0

        sizes = machine_libcloud.driver.list_sizes()
        size = machine_libcloud.extra.get('instance_type')
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
        return node.extra.get('availability')

    def _list_machines__get_size(self, node):
        return node.extra.get('instance_type')

    def _list_images__fetch_images(self, search=None):
        default_images = config.EC2_IMAGES[self.cloud.region]
        image_ids = list(default_images.keys()) + self.cloud.starred
        if not search:
            try:
                # this might break if image_ids contains starred images
                # that are not valid anymore for AWS
                images = self.connection.list_images(None, image_ids)
            except Exception as e:
                bad_ids = re.findall(r'ami-\w*', str(e), re.DOTALL)
                for bad_id in bad_ids:
                    try:
                        self.cloud.starred.remove(bad_id)
                    except ValueError:
                        log.error('Starred Image %s not found in cloud %r' % (
                            bad_id, self.cloud
                        ))
                self.cloud.save()
                images = self.connection.list_images(
                    None, list(default_images.keys()) + self.cloud.starred)
            for image in images:
                if image.id in default_images:
                    image.name = default_images[image.id]
            images += self.connection.list_images(ex_owner='self')
        else:
            image_models = CloudImage.objects(
                me.Q(cloud_provider=self.connection.type,
                     image_id__icontains=search) |
                me.Q(cloud_provider=self.connection.type,
                     name__icontains=search)
            )[:200]
            images = [NodeImage(id=image.image_id, name=image.name,
                                driver=self.connection, extra={})
                      for image in image_models]
            if not images:
                # Actual search on EC2.
                images = self.connection.list_images(
                    ex_filters={'name': '*%s*' % search}
                )
        return images

    def image_is_default(self, image_id):
        return image_id in config.EC2_IMAGES[self.cloud.region]

    def _list_locations__fetch_locations(self):
        """List availability zones for EC2 region

        In EC2 all locations of a region have the same name, so the
        availability zones are listed instead.

        """
        locations = self.connection.list_locations()
        for location in locations:
            try:
                location.name = location.availability_zone.name
            except:
                pass
        return locations

    def _list_sizes__get_cpu(self, size):
        return int(size.extra.get('vcpu', 1))

    def _list_sizes__get_name(self, size):
        return '%s - %s' % (size.id, size.name)


class AlibabaComputeController(AmazonComputeController):

    def _connect(self):
        return get_driver(Provider.ALIYUN_ECS)(self.cloud.apikey,
                                               self.cloud.apisecret,
                                               region=self.cloud.region)

    def _resize_machine(self, machine, machine_libcloud, node_size, kwargs):
        # instance must be in stopped mode
        if machine_libcloud.state != NodeState.STOPPED:
            raise BadRequestError('The instance has to be stopped '
                                  'in order to be resized')
        try:
            self.connection.ex_resize_node(machine_libcloud, node_size.id)
            self.connection.ex_start_node(machine_libcloud)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__get_location(self, node):
        return node.extra.get('zone_id')

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        size = machine_libcloud.extra.get('instance_type', {})
        driver_name = 'ecs-' + machine_libcloud.extra.get('zone_id')
        price = get_size_price(driver_type='compute', driver_name=driver_name,
                               size_id=size)
        image = machine_libcloud.extra.get('image_id', '')
        if 'win' in image:
            price = price.get('windows', '')
        else:
            price = price.get('linux', '')
        if machine_libcloud.extra.get('instance_charge_type') == 'PostPaid':
            return (price.get('pay_as_you_go', 0), 0)
        else:
            return (0, price.get('prepaid', 0))

    def _list_images__fetch_images(self, search=None):
        return self.connection.list_images()

    def image_is_default(self, image_id):
        return True

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

    def _list_sizes__get_cpu(self, size):
        return size.extra['cpu_core_count']

    def _list_sizes__get_name(self, size):
        specs = str(size.extra['cpu_core_count']) + ' cpus/ ' \
            + str(size.ram) + 'Gb RAM '
        return "%s (%s)" % (size.name, specs)


class DigitalOceanComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.DIGITAL_OCEAN)(self.cloud.token)

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        cpus = machine.extra.get('size', {}).get('vcpus', 0)
        if machine.extra['cpus'] != cpus:
            machine.extra['cpus'] = cpus
            updated = True
        return updated

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        return machine_libcloud.extra.get('created_at')  # iso8601 string

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(DigitalOceanComputeController,
              self)._list_machines__machine_actions(machine, machine_libcloud)
        machine.actions.rename = True
        machine.actions.resize = True

    def _resize_machine(self, machine, machine_libcloud, node_size, kwargs):
        try:
            self.connection.ex_resize_node(machine_libcloud, node_size)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        size = machine_libcloud.extra.get('size', {})
        return size.get('price_hourly', 0), size.get('price_monthly', 0)

    def _stop_machine(self, machine, machine_libcloud):
        self.connection.ex_shutdown_node(machine_libcloud)

    def _list_machines__get_location(self, node):
        return node.extra.get('region')

    def _list_machines__get_size(self, node):
        return node.extra.get('size_slug')

    def _list_sizes__get_name(self, size):
        cpus = str(size.extra.get('vcpus', ''))
        ram = str(size.ram / 1024)
        disk = str(size.disk)
        bandwidth = str(size.bandwidth)
        price_monthly = str(size.extra.get('price_monthly', ''))
        if cpus:
            name = cpus + ' CPU/ ' if cpus == '1' else cpus + ' CPUs/ '
        if ram:
            name += ram + ' GB/ '
        if disk:
            name += disk + ' GB SSD Disk/ '
        if bandwidth:
            name += bandwidth + ' TB transfer/ '
        if price_monthly:
            name += price_monthly + '$/month'

        return name

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('vcpus')


class MaxihostComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.MAXIHOST)(self.cloud.token)

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(MaxihostComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        if machine_libcloud.state is NodeState.PAUSED:
            machine.actions.start = True

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        if machine_libcloud.extra.get('ips', []):
            name = machine_libcloud.extra.get('ips')[0].get('device_hostname')
            if machine.hostname != name:
                machine.hostname = name
                updated = True
        return updated

    def _list_machines__get_location(self, node):
        return node.extra.get('location').get('facility_code')

    def _start_machine(self, machine, machine_libcloud):
        machine_libcloud.id = machine_libcloud.extra.get('id', '')
        return self.connection.ex_start_node(machine_libcloud)

    def _stop_machine(self, machine, machine_libcloud):
        machine_libcloud.id = machine_libcloud.extra.get('id', '')
        return self.connection.ex_stop_node(machine_libcloud)

    def _reboot_machine(self, machine, machine_libcloud):
        machine_libcloud.id = machine_libcloud.extra.get('id', '')
        return self.connection.reboot_node(machine_libcloud)

    def _destroy_machine(self, machine, machine_libcloud):
        machine_libcloud.id = machine_libcloud.extra.get('id', '')
        return self.connection.destroy_node(machine_libcloud)

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


class GigG8ComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.GIG_G8)(self.cloud.user_id,
                                           self.cloud.apikey,
                                           self.cloud.url)

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        # Discover network of machine.
        network_id = machine_libcloud.extra.get('network_id', None)
        if network_id:
            from mist.api.networks.models import Network
            try:
                machine.network = Network.objects.get(cloud=self.cloud,
                                                      network_id=network_id,
                                                      missing_since=None)
            except Network.DoesNotExist:
                machine.network = None

        if machine.network:
            machine.public_ips = [machine.network.public_ip]

        if machine_libcloud.extra.get('ssh_port', None):
            machine.ssh_port = machine_libcloud.extra['ssh_port']

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(GigG8ComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        if machine_libcloud.state is NodeState.PAUSED:
            machine.actions.start = True

    def _list_machines__get_size(self, node):
        """Return key of size_map dict for a specific node

        Subclasses MAY override this method.
        """
        return None

    def _list_machines__get_custom_size(self, node):
        from mist.api.clouds.models import CloudSize
        try:
            _size = CloudSize.objects.get(external_id=str(node.size.id))
        except me.DoesNotExist:
            _size = CloudSize(cloud=self.cloud,
                              external_id=str(node.size.id))
        _size.ram = node.size.ram
        _size.cpus = node.size.extra.get('cpus')
        _size.disk = node.size.disk
        name = ""
        if _size.cpus:
            name += '%s CPUs, ' % _size.cpus
        if _size.ram:
            name += '%sMB RAM, ' % _size.ram
        if _size.disk:
            name += '%sGB disk.' % _size.disk
        _size.name = name
        _size.save()

        return _size

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        return machine_libcloud.extra.get('created_at')

    def list_sizes(self, persist=True):
        # only custom sizes are supported
        return []

    def list_locations(self, persist=True):
        return []

    def _stop_machine(self, machine, machine_libcloud):
        self.connection.stop_node(machine_libcloud)

    def _start_machine(self, machine, machine_libcloud):
        self.connection.start_node(machine_libcloud)

    def _reboot_machine(self, machine, machine_libcloud):
        self.connection.reboot_node(machine_libcloud)


class LinodeComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.LINODE)(self.cloud.apikey)

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        return machine_libcloud.extra.get('CREATE_DT')  # iso8601 string

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(LinodeComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        machine.actions.rename = True
        machine.actions.resize = True
        # machine.actions.stop = False
        # After resize, node gets to pending mode, needs to be started.
        if machine_libcloud.state is NodeState.PENDING:
            machine.actions.start = True

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        size = machine_libcloud.extra.get('PLANID')
        price = get_size_price(driver_type='compute', driver_name='linode',
                               size_id=size)
        return 0, price or 0

    def _list_machines__get_size(self, node):
        return node.extra.get('PLANID')

    def _list_machines__get_location(self, node):
        return str(node.extra.get('DATACENTERID'))


class RackSpaceComputeController(BaseComputeController):

    def _connect(self):
        if self.cloud.region in ('us', 'uk'):
            driver = get_driver(Provider.RACKSPACE_FIRST_GEN)
        else:
            driver = get_driver(Provider.RACKSPACE)
        return driver(self.cloud.username, self.cloud.apikey,
                      region=self.cloud.region)

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        return machine_libcloud.extra.get('created')  # iso8601 string

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(RackSpaceComputeController,
              self)._list_machines__machine_actions(machine, machine_libcloud)
        machine.actions.rename = True

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        # Need to get image in order to specify the OS type
        # out of the image id.
        size = machine_libcloud.extra.get('flavorId')
        location = machine_libcloud.driver.region[:3]
        driver_name = 'rackspacenova' + location
        try:
            price = get_size_price(driver_type='compute',
                                   driver_name=driver_name,
                                   size_id=size)
        except KeyError:
            log.error('Pricing for %s:%s was not found.') % (driver_name, size)

        if price:
            plan_price = price.get(machine.os_type) or price.get('linux')
            # 730 is the number of hours per month as on
            # https://www.rackspace.com/calculator
            return plan_price, float(plan_price) * 730

            # TODO: RackSpace mentions on
            # https://www.rackspace.com/cloud/public-pricing
            # there's a minimum service charge of $50/mo across all servers.

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        # Find os_type.
        try:
            os_type = CloudImage.objects.get(
                cloud_provider=machine_libcloud.driver.type,
                image_id=machine_libcloud.extra.get('imageId'),
            ).os_type
        except:
            os_type = 'linux'
        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True
        return updated

    def _list_machines__get_size(self, node):
        return node.extra.get('flavorId')

    def _list_sizes__get_cpu(self, size):
        return size.vcpus


class SoftLayerComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.SOFTLAYER)(self.cloud.username,
                                              self.cloud.apikey)

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        return machine_libcloud.extra.get('created')  # iso8601 string

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        os_type = 'linux'
        if 'windows' in str(machine_libcloud.extra.get('image', '')).lower():
            os_type = 'windows'
        if os_type != machine.os_type:
            machine.os_type = os_type
            updated = True

        # Get number of vCPUs for bare metal and cloud servers, respectively.
        if 'cpu' in machine.extra and \
                machine.extra['cpus'] != machine.extra['cpu']:
            machine.extra['cpus'] = machine.extra['cpu']
            updated = True
        if 'maxCpu' in machine.extra and \
                machine.extra['cpus'] != machine.extra['maxCpu']:
            machine.extra['cpus'] = machine.extra['maxCpu']
            updated = True
        return updated

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        # SoftLayer includes recurringFee on the VM metadata but
        # this is only for the compute - CPU pricing.
        # Other costs (ram, bandwidth, image) are included
        # on billingItemChildren.

        extra_fee = 0
        if not machine_libcloud.extra.get('hourlyRecurringFee'):
            cpu_fee = float(machine_libcloud.extra.get('recurringFee'))
            for item in machine_libcloud.extra.get('billingItemChildren', ()):
                # don't calculate billing that is cancelled
                if not item.get('cancellationDate'):
                    extra_fee += float(item.get('recurringFee'))
            return 0, cpu_fee + extra_fee
        else:
            # machine_libcloud.extra.get('recurringFee')
            # here will show what it has cost for the current month, up to now.
            cpu_fee = float(machine_libcloud.extra.get('hourlyRecurringFee'))
            for item in machine_libcloud.extra.get('billingItemChildren', ()):
                # don't calculate billing that is cancelled
                if not item.get('cancellationDate'):
                    extra_fee += float(item.get('hourlyRecurringFee'))

            return cpu_fee + extra_fee, 0

    def _list_machines__get_location(self, node):
        return node.extra.get('datacenter')

    def _reboot_machine(self, machine, machine_libcloud):
        self.connection.reboot_node(machine_libcloud)
        return True

    def _destroy_machine(self, machine, machine_libcloud):
        self.connection.destroy_node(machine_libcloud)


class AzureComputeController(BaseComputeController):

    def _connect(self):
        tmp_cert_file = tempfile.NamedTemporaryFile(delete=False)
        tmp_cert_file.write(self.cloud.certificate.encode())
        tmp_cert_file.close()
        return get_driver(Provider.AZURE)(self.cloud.subscription_id,
                                          tmp_cert_file.name)

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        os_type = machine_libcloud.extra.get('os_type', 'linux')
        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True
        return updated

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        if machine_libcloud.state not in [NodeState.RUNNING, NodeState.PAUSED]:
            return 0, 0
        return machine_libcloud.extra.get('cost_per_hour', 0), 0

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

    def _cloud_service(self, machine_libcloud_id):
        """
        Azure libcloud driver needs the cloud service
        specified as well as the node
        """
        cloud_service = self.connection.get_cloud_service_from_node_id(
            machine_libcloud_id)
        return cloud_service

    def _get_machine_libcloud(self, machine, no_fail=False):
        cloud_service = self._cloud_service(machine.machine_id)
        for node in self.connection.list_nodes(
                ex_cloud_service_name=cloud_service):
            if node.id == machine.machine_id:
                return node
            if no_fail:
                return Node(machine.machine_id, name=machine.machine_id,
                            state=0, public_ips=[], private_ips=[],
                            driver=self.connection)
            raise MachineNotFoundError("Machine with id '%s'." %
                                       machine.machine_id)

    def _start_machine(self, machine, machine_libcloud):
        cloud_service = self._cloud_service(machine.machine_id)
        return self.connection.ex_start_node(
            machine_libcloud, ex_cloud_service_name=cloud_service)

    def _stop_machine(self, machine, machine_libcloud):
        cloud_service = self._cloud_service(machine.machine_id)
        return self.connection.ex_stop_node(
            machine_libcloud, ex_cloud_service_name=cloud_service)

    def _reboot_machine(self, machine, machine_libcloud):
        cloud_service = self._cloud_service(machine.machine_id)
        return self.connection.reboot_node(
            machine_libcloud, ex_cloud_service_name=cloud_service)

    def _destroy_machine(self, machine, machine_libcloud):
        cloud_service = self._cloud_service(machine.machine_id)
        return self.connection.destroy_node(
            machine_libcloud, ex_cloud_service_name=cloud_service)

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(AzureComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        if machine_libcloud.state is NodeState.PAUSED:
            machine.actions.start = True


class AzureArmComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.AZURE_ARM)(self.cloud.tenant_id,
                                              self.cloud.subscription_id,
                                              self.cloud.key,
                                              self.cloud.secret)

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        os_type = machine_libcloud.extra.get('os_type', 'linux')
        if os_type != machine.os_type:
            machine.os_type = os_type
            updated = True

        net_id = machine_libcloud.extra.get('networkProfile')[0].get('id')
        network_id = net_id.split('/')[-1] + '-vnet'
        if machine.extra['network'] != network_id:
            machine.extra['network'] = network_id
            updated = True

        # Discover network of machine.
        from mist.api.networks.models import Network
        try:
            network = Network.objects.get(cloud=self.cloud,
                                          network_id=network_id,
                                          missing_since=None)
        except Network.DoesNotExist:
            network = None

        if network != machine.network:
            machine.network = network
            updated = True

        return updated

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        if machine_libcloud.state not in [NodeState.RUNNING, NodeState.PAUSED]:
            return 0, 0
        return machine_libcloud.extra.get('cost_per_hour', 0), 0

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(AzureArmComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        if machine_libcloud.state is NodeState.PAUSED:
            machine.actions.start = True

    def _list_machines__get_location(self, node):
        return node.extra.get('location')

    def _list_machines__get_size(self, node):
        return node.extra.get('size')

    def _list_images__fetch_images(self, search=None):
        # Fetch mist's recommended images
        images = [NodeImage(id=image, name=name,
                            driver=self.connection, extra={})
                  for image, name in list(config.AZURE_ARM_IMAGES.items())]
        return images

    def _reboot_machine(self, machine, machine_libcloud):
        self.connection.reboot_node(machine_libcloud)

    def _destroy_machine(self, machine, machine_libcloud):
        self.connection.destroy_node(machine_libcloud)

    def _list_sizes__fetch_sizes(self):
        location = self.connection.list_locations()[0]
        return self.connection.list_sizes(location)

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('numberOfCores')

    def _list_sizes__get_name(self, size):
        return size.name + ' ' + str(size.extra['numberOfCores']) \
                         + ' cpus/' + str(size.ram / 1024) + 'GB RAM/ ' \
                         + str(size.disk) + 'GB SSD'


class GoogleComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.GCE)(self.cloud.email,
                                        self.cloud.private_key,
                                        project=self.cloud.project_id)

    def _list_machines__get_machine_extra(self, machine, machine_libcloud):
        # FIXME: we delete the extra.metadata for now because it can be
        # > 40kb per machine on GCE clouds with enabled GKE, causing the
        # websocket to overload and hang and is also a security concern.
        # We should revisit this and see if there is some use for this
        # metadata and if there are other fields that should be filtered
        # as well

        extra = copy.copy(machine_libcloud.extra)

        for key in list(extra.keys()):
            if key in ['metadata']:
                del extra[key]
        return extra

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        # iso8601 string
        return machine_libcloud.extra.get('creationTimestamp')

    def _list_machines__get_custom_size(self, node):
        size = self.connection.get_size_metadata_from_node(node.extra.
                                                           get('machineType'))
        # create object only if the size of the node is custom
        if size.get('name', '').startswith('custom'):
            # FIXME: resolve circular import issues
            from mist.api.clouds.models import CloudSize
            _size = CloudSize(cloud=self.cloud, external_id=size.get('id'))
            _size.ram = size.get('memoryMb')
            _size.cpus = size.get('guestCpus')
            _size.name = size.get('name')
            _size.save()
            return _size

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        extra = machine_libcloud.extra

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
                        'boot_disk'].size:
                    machine.extra['boot_disk_size'] = extra['boot_disk'].size
                    updated = True
                if machine.extra.get('boot_disk_type') != extra[
                        'boot_disk'].extra.get('type'):
                    machine.extra['boot_disk_type'] = extra[
                        'boot_disk'].extra.get('type')
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
                if machine.extra['zone'] != extra['zone'].name:
                    machine.extra['zone'] = extra['zone'].name
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

        network_interface = machine_libcloud.extra.get('networkInterfaces')[0]
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

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(GoogleComputeController,
              self)._list_machines__machine_actions(machine, machine_libcloud)
        machine.actions.resize = True

    def _list_images__fetch_images(self, search=None):
        images = self.connection.list_images()
        # GCE has some objects in extra so we make sure they are not passed.
        for image in images:
            image.extra.pop('licenses', None)
        return images

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        if machine_libcloud.state == NodeState.STOPPED:
            return 0, 0
        # https://cloud.google.com/compute/pricing
        size = machine_libcloud.extra.get('machineType').split('/')[-1]
        location = machine_libcloud.extra.get('zone').name
        # could be europe-west1-d, we want europe_west1
        location = '-'.join(location.split('-')[:2])

        driver_name = 'google_' + location
        price = get_size_price(driver_type='compute', driver_name=driver_name,
                               size_id=size)

        if not price:
            if size.startswith('custom'):
                cpu_price = 'custom-vm-core'
                ram_price = 'custom-vm-ram'
                if 'preemptible' in size:
                    cpu_price = 'custom-vm-core-preemptible'
                    ram_price = 'custom-vm-ram-preemptible'

                cpu_price = get_size_price(driver_type='compute',
                                           driver_name=driver_name,
                                           size_id=cpu_price)
                ram_price = get_size_price(driver_type='compute',
                                           driver_name=driver_name,
                                           size_id=ram_price)
                # Example custom-4-16384
                try:
                    cpu = int(size.split('-')[1])
                    ram = int(size.split('-')[2]) / 1024
                    price = cpu * cpu_price + ram * ram_price
                except:
                    log.exception("Couldn't parse custom size %s for cloud %s",
                                  size, self.cloud)
                    return 0, 0
            else:
                return 0, 0
        os_type = machine_libcloud.extra.get('os_type')
        os_cost_per_hour = 0
        if os_type == 'sles':
            if size in ('f1-micro', 'g1-small'):
                os_cost_per_hour = 0.02
            else:
                os_cost_per_hour = 0.11
        if os_type == 'win':
            if size in ('f1-micro', 'g1-small'):
                os_cost_per_hour = 0.02
            else:
                cores = size.split('-')[-1]
                os_cost_per_hour = cores * 0.04
        if os_type == 'rhel':
            if size in ('n1-highmem-2', 'n1-highcpu-2', 'n1-highmem-4',
                        'n1-highcpu-4', 'f1-micro', 'g1-small',
                        'n1-standard-1', 'n1-standard-2', 'n1-standard-4'):
                os_cost_per_hour = 0.06
            else:
                os_cost_per_hour = 0.13

        try:
            if 'preemptible' in size:
                # No monthly discount.
                return price + os_cost_per_hour, 0
            else:
                # Monthly discount of 30% if the VM runs all the billing month.
                # Monthly discount on instance size only (not on OS image).
                return 0.7 * price + os_cost_per_hour, 0
            # TODO: better calculate the discounts, taking under consideration
            # when the VM has been initiated.
        except:
            pass

    def _list_machines__get_location(self, node):
        return node.extra.get('zone').id

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
        return extra

    def _resize_machine(self, machine, machine_libcloud, node_size, kwargs):
        # instance must be in stopped mode
        if machine_libcloud.state != NodeState.STOPPED:
            raise BadRequestError('The instance has to be stopped '
                                  'in order to be resized')
        # get size name as returned by libcloud
        machine_type = node_size.name.split(' ')[0]
        try:
            self.connection.ex_set_machine_type(machine_libcloud,
                                                machine_type)
            self.connection.ex_start_node(machine_libcloud)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)


class HostVirtualComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.HOSTVIRTUAL)(self.cloud.apikey)


class PacketComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.PACKET)(self.cloud.apikey,
                                           project=self.cloud.project_id)

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        return machine_libcloud.extra.get('created_at')  # iso8601 string

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        size = machine_libcloud.extra.get('plan')
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

    def _list_machines__get_location(self, node):
        return node.extra.get('facility', {}).get('id', '')

    def _list_machines__get_size(self, node):
        return node.extra.get('plan')


class VultrComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.VULTR)(self.cloud.apikey)

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        if machine.extra['cpus'] != machine.extra.get('vcpu_count', 0):
            machine.extra['cpus'] = machine.extra.get('vcpu_count', 0)
            updated = True
        return updated

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        return machine_libcloud.extra.get('date_created')  # iso8601 string

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        return 0, machine_libcloud.extra.get('cost_per_month', 0)

    def _list_machines__get_size(self, node):
        return node.extra.get('VPSPLANID')

    def _list_machines__get_location(self, node):
        return node.extra.get('DCID')

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('vcpu_count')

    def _list_sizes__fetch_sizes(self):
        sizes = self.connection.list_sizes()
        return [size for size in sizes if not size.extra.get('deprecated')]


class VSphereComputeController(BaseComputeController):

    def _connect(self):
        from libcloud.compute.drivers.vsphere import VSphereNodeDriver
        from libcloud.compute.drivers.vsphere import VSphere_6_7_NodeDriver
        ca_cert = None
        if self.cloud.ca_cert_file:
            ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            ca_cert_temp_file.write(self.cloud.ca_cert_file.encode())
            ca_cert_temp_file.close()
            ca_cert = ca_cert_temp_file.name

        host, port = dnat(self.cloud.owner, self.cloud.host, 443)
        driver_6_5 = VSphereNodeDriver(host=host,
                                       username=self.cloud.username,
                                       password=self.cloud.password,
                                       port=port,
                                       ca_cert=ca_cert)
        self.version = driver_6_5._get_version()
        if '6.7'in self.version and config.ENABLE_VSPHERE_REST:
            self.version = '6.7'
            return VSphere_6_7_NodeDriver(self.cloud.username,
                                          secret=self.cloud.password,
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

    def _list_machines__get_location(self, node):
        cluster = node.extra.get('cluster', '')
        host = node.extra.get('host', '')
        return cluster or host

    def list_vm_folders(self):
        all_folders = self.connection.ex_list_folders()
        vm_folders = [folder for folder in all_folders if folder[
            'type'] in {"VIRTUAL_MACHINE", "VirtualMachine"}]
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
        return self.connection.list_nodes(
            max_properties=self.cloud.max_properties_per_request)

    def _list_machines__get_size(self, node):
        """Return key of size_map dict for a specific node

        Subclasses MAY override this method.
        """
        return None

    def _list_machines__get_custom_size(self, node):
        # FIXME: resolve circular import issues
        from mist.api.clouds.models import CloudSize
        try:
            _size = CloudSize.objects.get(external_id=node.size.id)
        except me.DoesNotExist:
            _size = CloudSize(cloud=self.cloud,
                              external_id=str(node.size.id))
        _size.ram = node.size.ram
        _size.cpus = node.size.extra.get('cpus')
        _size.disk = node.size.disk
        name = ""
        if _size.cpus:
            name += f'{_size.cpus}vCPUs, '
        if _size.ram:
            name += f'{_size.ram}MB RAM, '
        if _size.disk:
            name += f'{_size.disk}GB disk.'
        _size.name = name
        _size.save()
        return _size

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(VSphereComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        machine.actions.create_snapshot = True
        if len(machine.extra.get('snapshots')):
            machine.actions.remove_snapshot = True
            machine.actions.revert_to_snapshot = True
        else:
            machine.actions.remove_snapshot = False
            machine.actions.revert_to_snapshot = False

    def _stop_machine(self, machine, machine_libcloud):
        return self.connection.stop_node(machine_libcloud)

    def _start_machine(self, machine, machine_libcloud):
        return self.connection.start_node(machine_libcloud)

    def _create_machine_snapshot(self, machine, machine_libcloud,
                                 snapshot_name, description='',
                                 dump_memory=False, quiesce=False):
        """Create a snapshot for a given machine"""
        return self.connection.ex_create_snapshot(
            machine_libcloud, snapshot_name, description,
            dump_memory=dump_memory, quiesce=quiesce)

    def _revert_machine_to_snapshot(self, machine, machine_libcloud,
                                    snapshot_name=None):
        """Revert a given machine to a previous snapshot"""
        return self.connection.ex_revert_to_snapshot(machine_libcloud,
                                                     snapshot_name)

    def _remove_machine_snapshot(self, machine, machine_libcloud,
                                 snapshot_name=None):
        """Removes a given machine snapshot"""
        return self.connection.ex_remove_snapshot(machine_libcloud,
                                                  snapshot_name)

    def _list_machine_snapshots(self, machine, machine_libcloud):
        return self.connection.ex_list_snapshots(machine_libcloud)


class VCloudComputeController(BaseComputeController):

    def _connect(self):
        host = dnat(self.cloud.owner, self.cloud.host)
        return get_driver(self.provider)(self.cloud.username,
                                         self.cloud.password, host=host,
                                         port=int(self.cloud.port)
                                         )

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(VCloudComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        if machine_libcloud.state is NodeState.PENDING:
            machine.actions.start = True
            machine.actions.stop = True

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        if machine.os_type != machine.extra.get('os_type'):
            machine.os_type = machine.extra.get('os_type')
            updated = True
        return updated


class OpenStackComputeController(BaseComputeController):

    def _connect(self):
        url = dnat(self.cloud.owner, self.cloud.url)
        return get_driver(Provider.OPENSTACK)(
            self.cloud.username,
            self.cloud.password,
            api_version='2.2',
            ex_force_auth_version='3.x_password',
            ex_tenant_name=self.cloud.tenant,
            ex_force_service_region=self.cloud.region,
            ex_force_base_url=self.cloud.compute_endpoint,
            ex_auth_url=url,
            ex_domain_name=self.cloud.domain or 'Default'
        )

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        return machine_libcloud.extra.get('created')  # iso8601 string

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(OpenStackComputeController,
              self)._list_machines__machine_actions(machine, machine_libcloud)
        machine.actions.rename = True
        machine.actions.resize = True

    def _resize_machine(self, machine, machine_libcloud, node_size, kwargs):
        try:
            self.connection.ex_resize(machine_libcloud, node_size)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

        try:
            sleep(50)
            machine_libcloud = self._get_machine_libcloud(machine)
            return self.connection.ex_confirm_resize(machine_libcloud)
        except Exception as exc:
            sleep(50)
            machine_libcloud = self._get_machine_libcloud(machine)
            try:
                return self.connection.ex_confirm_resize(machine_libcloud)
            except Exception as exc:
                raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
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

    def _list_sizes__get_cpu(self, size):
        return size.vcpus

    def _list_machines__get_size(self, node):
        return node.extra.get('flavorId')


class DockerComputeController(BaseComputeController):

    def __init__(self, *args, **kwargs):
        super(DockerComputeController, self).__init__(*args, **kwargs)
        self._dockerhost = None

    def _connect(self):
        host, port = dnat(self.cloud.owner, self.cloud.host, self.cloud.port)

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
            key_temp_file.write(self.cloud.key_file.encode())
            key_temp_file.close()
            cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            cert_temp_file.write(self.cloud.cert_file.encode())
            cert_temp_file.close()
            ca_cert = None
            if self.cloud.ca_cert_file:
                ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
                ca_cert_temp_file.write(self.cloud.ca_cert_file.encode())
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
                key=self.cloud.username,
                secret=self.cloud.password,
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
        return containers

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        return machine_libcloud.extra.get('created')  # unix timestamp

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        # todo this is not necessary
        super(DockerComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        if machine_libcloud.state in (ContainerState.REBOOTING,
                                      ContainerState.PENDING):
            machine.actions.start = False
            machine.actions.stop = False
            machine.actions.reboot = False
        elif machine_libcloud.state in (ContainerState.STOPPED,
                                        ContainerState.UNKNOWN):
            # We assume unknown state means stopped.
            machine.actions.start = True
            machine.actions.stop = False
            machine.actions.reboot = False
        elif machine_libcloud.state in (ContainerState.TERMINATED, ):
            machine.actions.start = False
            machine.actions.stop = False
            machine.actions.reboot = False
            machine.actions.destroy = False
            machine.actions.rename = False

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
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
        for attr, val in {'name': self.cloud.title,
                          'hostname': self.cloud.host,
                          'machine_type': 'container-host'}.items():
            if getattr(machine, attr) != val:
                setattr(machine, attr, val)
                changed = True
        if not machine.machine_id:
            machine.machine_id = machine.id
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

    def inspect_node(self, machine_libcloud):
        """
        Inspect a container
        """
        result = self.connection.connection.request(
            "/v%s/containers/%s/json" % (self.connection.version,
                                         machine_libcloud.id)).object

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
        # Fetch mist's recommended images
        images = [ContainerImage(id=image, name=name, path=None,
                                 version=None, driver=self.connection,
                                 extra={})
                  for image, name in list(config.DOCKER_IMAGES.items())]
        # Add starred images
        images += [ContainerImage(id=image, name=image, path=None,
                                  version=None, driver=self.connection,
                                  extra={})
                   for image in self.cloud.starred
                   if image not in config.DOCKER_IMAGES]
        # Fetch images from libcloud (supports search).
        if search:
            images += self.connection.ex_search_images(term=search)[:100]
        else:
            images += self.connection.list_images()
        return images

    def image_is_default(self, image_id):
        return image_id in config.DOCKER_IMAGES

    def _action_change_port(self, machine, machine_libcloud):
        """This part exists here for docker specific reasons. After start,
        reboot and destroy actions, docker machine instance need to rearrange
        its port. Finally save the machine in db.
        """
        # this exist here cause of docker host implementation
        if machine.machine_type == 'container-host':
            return
        container_info = self.inspect_node(machine_libcloud)

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

    def _get_machine_libcloud(self, machine, no_fail=False):
        """Return an instance of a libcloud node

        This is a private method, used mainly by machine action methods.
        """
        assert self.cloud == machine.cloud
        for node in self.connection.list_containers():
            if node.id == machine.machine_id:
                return node
        if no_fail:
            container = Container(id=machine.machine_id,
                                  name=machine.machine_id,
                                  image=machine.image_id,
                                  state=0,
                                  ip_addresses=[],
                                  driver=self.connection,
                                  extra={})
            container.public_ips = []
            container.private_ips = []
            container.size = None
            return container
        raise MachineNotFoundError(
            "Machine with machine_id '%s'." % machine.machine_id
        )

    def _start_machine(self, machine, machine_libcloud):
        ret = self.connection.start_container(machine_libcloud)
        self._action_change_port(machine, machine_libcloud)
        return ret

    def reboot_machine(self, machine):
        if machine.machine_type == 'container-host':
            return self.reboot_machine_ssh(machine)
        return super(DockerComputeController, self).reboot_machine(machine)

    def _reboot_machine(self, machine, machine_libcloud):
        self.connection.restart_container(machine_libcloud)
        self._action_change_port(machine, machine_libcloud)

    def _stop_machine(self, machine, machine_libcloud):
        return self.connection.stop_container(machine_libcloud)

    def _destroy_machine(self, machine, machine_libcloud):
        if machine_libcloud.state == ContainerState.RUNNING:
            self.connection.stop_container(machine_libcloud)
        return self.connection.destroy_container(machine_libcloud)

    def _list_sizes__fetch_sizes(self):
        return []


class LXDComputeController(BaseComputeController):
    """
    Compute controller for LXC containers
    """
    def __init__(self, *args, **kwargs):
        super(LXDComputeController, self).__init__(*args, **kwargs)
        self._lxchost = None
        self.is_lxc = True

    def _stop_machine(self, machine, machine_libcloud):
        """Stop the given machine"""
        return self.connection.stop_container(container=machine)

    def _start_machine(self, machine, machine_libcloud):
        """Start the given container"""
        return self.connection.start_container(container=machine)

    def _destroy_machine(self, machine, machine_libcloud):
        """Delet the given container"""

        from libcloud.container.drivers.lxd import LXDAPIException
        from libcloud.container.types import ContainerState
        try:

            if machine_libcloud.state == ContainerState.RUNNING:
                self.connection.stop_container(container=machine)

            container = self.connection.destroy_container(container=machine)
            return container
        except LXDAPIException as e:
            raise MistError(msg=e.message, exc=e)
        except Exception as e:
            raise MistError(exc=e)

    def _reboot_machine(self, machine, machine_libcloud):
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
            host = sanitize_host(self.cloud.host)
            if is_private_subnet(host):
                private_ips.append(host)
            else:
                public_ips.append(host)

            container.public_ips = public_ips
            container.private_ips = private_ips
            container.size = None
            container.image = container.image.name

        return containers

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        """Unix timestap of when the machine was created"""
        return machine_libcloud.extra.get('created')  # unix timestamp

    def _get_machine_libcloud(self, machine, no_fail=False):
        """Return an instance of a libcloud node

        This is a private method, used mainly by machine action methods.
        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        for node in self.connection.list_containers():
            if node.id == machine.machine_id:
                return node
        if no_fail:
            return Node(machine.machine_id, name=machine.machine_id,
                        state=0, public_ips=[], private_ips=[],
                        driver=self.connection)
        raise MachineNotFoundError(
            "Machine with machine_id '%s'." % machine.machine_id
        )

    def _connect(self):
        host, port = dnat(self.cloud.owner, self.cloud.host, self.cloud.port)

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
                key=self.cloud.username,
                secret=self.cloud.password,
                host=host, port=port)
        # open authentication.
        else:
            return get_container_driver(Container_Provider.LXD)(
                host=host, port=port)

    def _tls_authenticate(self, host, port):
        """Perform TLS authentication given the host and port"""

        # TLS authentication.

        key_temp_file = tempfile.NamedTemporaryFile(delete=False)
        key_temp_file.write(self.cloud.key_file.encode())
        key_temp_file.close()
        cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
        cert_temp_file.write(self.cloud.cert_file.encode())
        cert_temp_file.close()
        ca_cert = None

        if self.cloud.ca_cert_file:
            ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            ca_cert_temp_file.write(self.cloud.ca_cert_file.encode())
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


class LibvirtComputeController(BaseComputeController):

    def _connect(self):
        """Three supported ways to connect: local system, qemu+tcp, qemu+ssh"""

        import libcloud.compute.drivers.libvirt_driver
        libvirt_driver = libcloud.compute.drivers.libvirt_driver
        libvirt_driver.ALLOW_LIBVIRT_LOCALHOST = config.ALLOW_LIBVIRT_LOCALHOST

        if self.cloud.key:
            host, port = dnat(self.cloud.owner,
                              self.cloud.host, self.cloud.port)
            return get_driver(Provider.LIBVIRT)(host,
                                                hypervisor=self.cloud.host,
                                                user=self.cloud.username,
                                                ssh_key=self.cloud.key.private,
                                                ssh_port=int(port))
        else:
            host, port = dnat(self.cloud.owner, self.cloud.host, 5000)
            return get_driver(Provider.LIBVIRT)(host,
                                                hypervisor=self.cloud.host,
                                                user=self.cloud.username,
                                                tcp_port=int(port))

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(LibvirtComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        if machine.extra.get('tags', {}).get('type') == 'hypervisor':
            # Allow only reboot and tag actions for hypervisor.
            for action in ('start', 'stop', 'destroy', 'rename'):
                setattr(machine.actions, action, False)
        else:
            machine.actions.clone = True
            machine.actions.undefine = False
            if machine_libcloud.state is NodeState.TERMINATED:
                # In libvirt a terminated machine can be started.
                machine.actions.start = True
                machine.actions.undefine = True
            if machine_libcloud.state is NodeState.RUNNING:
                machine.actions.suspend = True
            if machine_libcloud.state is NodeState.SUSPENDED:
                machine.actions.resume = True

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False
        xml_desc = machine_libcloud.extra.get('xml_description')
        if xml_desc:
            escaped_xml_desc = escape(xml_desc)
            if machine.extra['xml_description'] != escaped_xml_desc:
                machine.extra['xml_description'] = escaped_xml_desc
                updated = True
            import xml.etree.ElementTree as ET
            root = ET.fromstring(unescape(xml_desc))
            devices = root.find('devices')
            disks = devices.findall('disk')
            for disk in disks:
                if disk.attrib.get('device', '') == 'cdrom':
                    image = disk.find('source').attrib.get('file', '')
                    if machine.image_id != image:
                        machine.image_id = image
                        updated = True

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
        hypervisor = machine.extra.get('hypervisor_name', '')
        if hypervisor:
            try:
                from mist.api.machines.models import Machine
                parent = Machine.objects.get(cloud=machine.cloud,
                                             name=hypervisor)
            except Machine.DoesNotExist:
                parent = None
            if machine.parent != parent:
                machine.parent = parent
                updated = True
        return updated

    def _list_machines__get_size(self, node):
        return None

    def _list_machines__get_custom_size(self, node):
        if not node.size:
            return
        from mist.api.clouds.models import CloudSize
        try:
            _size = CloudSize.objects.get(external_id=node.size.id)
        except me.DoesNotExist:
            _size = CloudSize(cloud=self.cloud,
                              external_id=node.size.id)
        _size.ram = node.size.ram
        _size.cpus = node.size.extra.get('cpus')
        name = ""
        if _size.cpus:
            name += '%s CPUs, ' % _size.cpus
        if _size.ram:
            name += '%dMB RAM' % (_size.ram / 1000)
        _size.name = name
        _size.save()

        return _size

    def _list_images__fetch_images(self, search=None):
        return self.connection.list_images(location=self.cloud.images_location)

    def _reboot_machine(self, machine, machine_libcloud):
        hypervisor = machine_libcloud.extra.get('tags', {}).get('type', None)
        if hypervisor == 'hypervisor':
            # issue an ssh command for the libvirt hypervisor
            try:
                hostname = machine_libcloud.public_ips[0] if \
                    machine_libcloud.public_ips else \
                    machine_libcloud.private_ips[0]
                command = '$(command -v sudo) shutdown -r now'
                # todo move it up
                from mist.api.methods import ssh_command
                ssh_command(self.cloud.owner, self.cloud.id,
                            machine_libcloud.id, hostname, command)
                return True
            except MistError as exc:
                log.error("Could not ssh machine %s", machine.name)
                raise
            except Exception as exc:
                log.exception(exc)
                # FIXME: Do not raise InternalServerError!
                raise InternalServerError(exc=exc)
        else:
            machine_libcloud.reboot()

    def _resume_machine(self, machine, machine_libcloud):
        self.connection.ex_resume_node(machine_libcloud)

    def _suspend_machine(self, machine, machine_libcloud):
        self.connection.ex_suspend_node(machine_libcloud)

    def _undefine_machine(self, machine, machine_libcloud):
        if machine.extra.get('active'):
            raise BadRequestError('Cannot undefine an active domain')
        self.connection.ex_undefine_node(machine_libcloud)

    def _clone_machine(self, machine, machine_libcloud, name, resume):
        self.connection.ex_clone_node(machine_libcloud, name, resume)

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('cpu')


class OnAppComputeController(BaseComputeController):

    def _connect(self):
        return get_driver(Provider.ONAPP)(key=self.cloud.username,
                                          secret=self.cloud.apikey,
                                          host=self.cloud.host,
                                          verify=self.cloud.verify)

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(OnAppComputeController, self)._list_machines__machine_actions(
            machine, machine_libcloud)
        machine.actions.resize = True
        if machine_libcloud.state is NodeState.RUNNING:
            machine.actions.suspend = True
        if machine_libcloud.state is NodeState.SUSPENDED:
            machine.actions.resume = True

    def _list_machines__machine_creation_date(self, machine, machine_libcloud):
        created_at = machine_libcloud.extra.get('created_at')
        created_at = iso8601.parse_date(created_at)
        created_at = pytz.UTC.normalize(created_at)
        return created_at

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        updated = False

        os_type = machine_libcloud.extra.get('operating_system', 'linux')
        # on a VM this has been freebsd and it caused list_machines to raise
        # exception due to validation of machine model
        if os_type not in ('unix', 'linux', 'windows', 'coreos'):
            os_type = 'linux'
        if os_type != machine.os_type:
            machine.os_type = os_type
            updated = True

        image_id = machine.extra.get('template_label') \
            or machine.extra.get('operating_system_distro')
        if image_id != machine.extra['image_id']:
            machine.extra['image_id'] = image_id
            updated = True

        if machine.extra.get('template_label'):
            machine.extra.pop('template_label', None)
            updated = True

        size = "%scpu, %sM ram" % \
            (machine.extra.get('cpus'), machine.extra.get('memory'))
        if size != machine.extra['size']:
            machine.extra['size'] = size
            updated = True

        return updated

    def _list_machines__cost_machine(self, machine, machine_libcloud):
        if machine_libcloud.state == NodeState.STOPPED:
            return machine_libcloud.extra.get('price_per_hour_powered_off',
                                              0), 0
        else:
            return machine_libcloud.extra.get('price_per_hour', 0), 0

    def _list_machines__get_custom_size(self, node):
        # FIXME: resolve circular import issues
        from mist.api.clouds.models import CloudSize
        _size = CloudSize(cloud=self.cloud,
                          external_id=str(node.extra.get('id')))
        _size.ram = node.extra.get('memory')
        _size.cpus = node.extra.get('cpus')
        _size.save()
        return _size

    def _resume_machine(self, machine, machine_libcloud):
        return self.connection.ex_resume_node(machine_libcloud)

    def _suspend_machine(self, machine, machine_libcloud):
        return self.connection.ex_suspend_node(machine_libcloud)

    def _resize_machine(self, machine, machine_libcloud, node_size, kwargs):
        # send only non empty valid args
        valid_kwargs = {}
        for param in kwargs:
            if param in ['memory', 'cpus', 'cpu_shares', 'cpu_units'] \
                    and kwargs[param]:
                valid_kwargs[param] = kwargs[param]
        try:
            return self.connection.ex_resize_node(machine_libcloud,
                                                  **valid_kwargs)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_locations__fetch_locations(self):
        """Get locations

        We will perform a few calls to get hypervisor_group_id
        paramater sent for create machine, and the max sizes to
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


class OtherComputeController(BaseComputeController):

    def _connect(self):
        return None

    def _list_machines__fetch_machines(self):
        return []

    def _list_machines__update_generic_machine_state(self, machine):
        """Update generic machine state (based on ping/ssh probes)

        It is only used in generic machines.
        """

        # Defaults
        machine.unreachable_since = None
        machine.state = config.STATES[NodeState.UNKNOWN]

        # If any of the probes has succeeded, then state is running
        if (
            machine.ssh_probe and not machine.ssh_probe.unreachable_since or
            machine.ping_probe and not machine.ping_probe.unreachable_since
        ):
            machine.state = config.STATES[NodeState.RUNNING]

        # If ssh probe failed, then unreachable since then
        if machine.ssh_probe and machine.ssh_probe.unreachable_since:
            machine.unreachable_since = machine.ssh_probe.unreachable_since
        # Else if ssh probe has never succeeded and ping probe failed,
        # then unreachable since then
        elif (not machine.ssh_probe and
              machine.ping_probe and machine.ping_probe.unreachable_since):
            machine.unreachable_since = machine.ping_probe.unreachable_since

    def _list_machines__generic_machine_actions(self, machine):
        """Update an action for a bare metal machine

        Bare metal machines only support remove, reboot and tag actions"""

        super(OtherComputeController,
              self)._list_machines__generic_machine_actions(machine)
        machine.actions.remove = True

    def _get_machine_libcloud(self, machine):
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

    def list_images(self, search=None):
        return []

    def list_sizes(self, persist=True):
        return []

    def list_locations(self, persist=True):
        return []


class KubeVirtComputeController(BaseComputeController):

    def _connect(self):
        host, port = dnat(self.cloud.owner,
                          self.cloud.host, self.cloud.port)
        try:
            socket.setdefaulttimeout(15)
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.connect((sanitize_host(host), int(port)))
            so.close()
        except:
            raise Exception("Make sure host is accessible "
                            "and kubernetes port is specified")

        verify = self.cloud.verify
        ca_cert = None
        if self.cloud.ca_cert_file:
                ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
                ca_cert_temp_file.write(self.cloud.ca_cert_file.encode())
                ca_cert_temp_file.close()
                ca_cert = ca_cert_temp_file.name

        # tls authentication
        if self.cloud.key_file and self.cloud.cert_file:
            key_temp_file = tempfile.NamedTemporaryFile(delete=False)
            key_temp_file.write(self.cloud.key_file.encode())
            key_temp_file.close()
            key_file = key_temp_file.name
            cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            cert_temp_file.write(self.cloud.cert_file.encode())
            cert_temp_file.close()
            cert_file = cert_temp_file.name

            return get_driver(Provider.KUBEVIRT)(secure=True,
                                                 host=host,
                                                 port=port,
                                                 key_file=key_file,
                                                 cert_file=cert_file,
                                                 ca_cert=ca_cert,
                                                 verify=verify)
        # token bearer authentication
        elif self.cloud.token_bearer_auth:
            if not key_file:
                raise ValueError("Missing the token, please provide it.")

            return get_driver(Provider.KUBEVIRT)(secure=True,
                                                 host=host,
                                                 port=port,
                                                 key_file=key_file,
                                                 ca_cert=ca_cert,
                                                 token_bearer_auth=True,
                                                 verify=verify
                                                 )
        # username/password auth
        elif self.cloud.username and self.cloud.password:
            key = self.cloud.username
            secret = self.cloud.password

            return get_driver(Provider.KUBEVIRT)(key=key,
                                                 secret=secret,
                                                 secure=True,
                                                 host=host,
                                                 port=port,
                                                 verify=verify)
        else:
            msg = '''Necessary parameters for authentication are missing.
            Either a key_file/cert_file pair or a username/pass pair
            or a bearer token.'''
            raise ValueError(msg)

    def _list_machines__machine_actions(self, machine, machine_libcloud):
        super(KubeVirtComputeController,
              self)._list_machines__machine_actions(
            machine, machine_libcloud)
        machine.actions.start = True
        machine.actions.stop = True
        machine.actions.reboot = True
        machine.actions.destroy = True

    def _reboot_machine(self, machine, machine_libcloud):
        return self.connection.reboot_node(machine_libcloud)

    def _start_machine(self, machine, machine_libcloud):
        return self.connection.start_node(machine_libcloud)

    def _stop_machine(self, machine, machine_libcloud):
        return self.connection.stop_node(machine_libcloud)

    def _destroy_machine(self, machine, machine_libcloud):
        res = self.connection.destroy_node(machine_libcloud)
        if res:
            if machine.extra.get('pvcs'):
                # FIXME: resolve circular import issues
                from mist.api.models import Volume
                volumes = Volume.objects.filter(cloud=self.cloud)
                for volume in volumes:
                    if machine.id in volume.attached_to:
                        volume.attached_to.remove(machine.id)

    def _list_machines__postparse_machine(self, machine, machine_libcloud):
        if not machine_libcloud.extra['pvcs']:
            return
        pvcs = machine_libcloud.extra['pvcs']
        # FIXME: resolve circular import issues
        from mist.api.models import Volume
        volumes = Volume.objects.filter(cloud=self.cloud, missing_since=None)
        for volume in volumes:
            if 'pvc' in volume.extra:
                if volume.extra['pvc']['name'] in pvcs:
                    if machine not in volume.attached_to:
                        volume.attached_to.append(machine)
                        volume.save()

    def _list_sizes__get_cpu(self, size):
        cpu = int(size.extra.get('cpus') or 1)
        if cpu > 1000:
            cpu = cpu / 1000
        elif cpu > 99:
            cpu = 1
        return cpu
