import re
import random
import base64
import mongoengine as me
import time
import requests
import datetime
import json

from random import randrange

from future.utils import string_types

from libcloud.compute.base import NodeSize, NodeImage, NodeLocation, Node
from libcloud.compute.base import StorageVolume

from libcloud.compute.types import Provider
from libcloud.container.types import Provider as Container_Provider
from libcloud.container.base import ContainerImage
from libcloud.compute.base import NodeAuthSSHKey
from libcloud.compute.base import NodeAuthPassword

from libcloud.common.types import MalformedResponseError

from tempfile import NamedTemporaryFile

import mist.api.tasks

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.keys.models import Key
from mist.api.networks.models import Network
from mist.api.networks.models import Subnet
from mist.api.users.models import Owner, Organization
from mist.api.auth.models import AuthToken

from mist.api.exceptions import PolicyUnauthorizedError
from mist.api.exceptions import MachineNameValidationError
from mist.api.exceptions import BadRequestError, MachineCreationError
from mist.api.exceptions import InternalServerError
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import VolumeNotFoundError
from mist.api.exceptions import NetworkNotFoundError, MistNotImplementedError

from mist.api.helpers import get_temp_file

from mist.api.methods import connect_provider
from mist.api.methods import notify_admin
from mist.api.networks.methods import list_networks
from mist.api.auth.methods import auth_context_from_auth_token

from mist.api.monitoring.methods import disable_monitoring

from mist.api.tag.methods import resolve_id_and_set_tags
from mist.api.tag.methods import get_tags_for_resource
from mist.api.tag.methods import remove_tags_from_resource

from mist.api import config

import logging

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)


def machine_name_validator(provider, name):
    """
    Validates machine names before creating a machine
    Provider specific
    """
    if not name and provider != Provider.EC2:
        raise MachineNameValidationError("machine name cannot be empty")
    if provider is Container_Provider.DOCKER:
        pass
    elif provider in [Provider.RACKSPACE_FIRST_GEN, Provider.RACKSPACE]:
        pass
    elif provider in [Provider.OPENSTACK]:
        pass
    elif provider is Provider.EC2:
        if len(name) > 255:
            raise MachineNameValidationError("machine name max "
                                             "chars allowed is 255")
    elif provider is Provider.GCE:
        if not re.search(r'^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$', name):
            raise MachineNameValidationError(
                "name must be 1-63 characters long, with the first "
                "character being a lowercase letter, and all following "
                "characters must be a dash, lowercase letter, or digit, "
                "except the last character, which cannot be a dash."
            )
    elif provider is Provider.SOFTLAYER:
        pass
    elif provider is Provider.DIGITAL_OCEAN:
        if not re.search(r'^[0-9a-zA-Z]+[0-9a-zA-Z-.]{0,}[0-9a-zA-Z]+$', name):
            raise MachineNameValidationError(
                "machine name may only contain ASCII letters "
                "or numbers, dashes and dots")
    elif provider is Provider.PACKET:
        if not re.search(r'^[0-9a-zA-Z-.]+$', name):
            raise MachineNameValidationError(
                "machine name may only contain ASCII letters "
                "or numbers, dashes and periods")
    elif provider == Provider.AZURE:
        pass
    elif provider == Provider.AZURE_ARM:
        if not re.search(r'^[0-9a-zA-Z\-]+$', name):
            raise MachineNameValidationError(
                "machine name may only contain ASCII letters "
                "or numbers and dashes")
    elif provider in [Provider.VCLOUD]:
        pass
    elif provider is Provider.LINODE:
        if len(name) < 3:
            raise MachineNameValidationError(
                "machine name should be at least 3 chars"
            )
        if not re.search(r'^[0-9a-zA-Z][0-9a-zA-Z-_]+[0-9a-zA-Z]$', name):
            raise MachineNameValidationError(
                "machine name may only contain ASCII letters or numbers, "
                "dashes and underscores. Must begin and end with letters "
                "or numbers, and be at least 3 characters long")
    elif provider == Provider.ONAPP:
        name = name.strip().replace(' ', '-')
        if not re.search(r'^[0-9a-zA-Z-.]+[0-9a-zA-Z.]$', name):
            raise MachineNameValidationError(
                "machine name may only contain ASCII letters "
                "or numbers, dashes and periods. Name should not "
                "end with a dash")
    return name


def list_machines(owner, cloud_id, cached=False):
    """List all machines in this cloud via API call to the provider."""
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    if cached:
        machines = cloud.ctl.compute.list_cached_machines()
    else:
        machines = cloud.ctl.compute.list_machines()
    return [machine.as_dict() for machine in machines]


def create_machine(auth_context, cloud_id, key_id, machine_name, location_id,
                   image_id, size, image_extra=None, disk=None,
                   image_name=None, size_name=None, location_name=None,
                   ips=None, monitoring=False, storage_account='',
                   machine_password='', resource_group='',
                   storage_account_type='', networks=[], subnetwork=None,
                   docker_env=[], docker_command=None,
                   ssh_port=22, script='', script_id='', script_params='',
                   job_id=None, job=None, docker_port_bindings={},
                   docker_exposed_ports={}, azure_port_bindings='',
                   hostname='', plugins=None, disk_size=None, disk_path=None,
                   post_script_id='', post_script_params='', cloud_init='',
                   subnet_id='', associate_floating_ip=False,
                   associate_floating_ip_subnet=None, project_id=None,
                   schedule={}, command=None, tags=None,
                   bare_metal=False, hourly=True,
                   softlayer_backend_vlan_id=None, machine_username='',
                   volumes=[], ip_addresses=[], expiration={},
                   sec_group='', folder=None, datastore=None, vnfs=[],
                   ephemeral=False, lxd_image_source=None,
                   description='',
                   ):
    """Creates a new virtual machine on the specified cloud.

    If the cloud is Rackspace it attempts to deploy the node with an ssh key
    provided in config. the method used is the only one working in the old
    Rackspace cloud. create_node(), from libcloud.compute.base, with 'auth'
    kwarg doesn't do the trick. Didn't test if you can upload some ssh related
    files using the 'ex_files' kwarg from openstack 1.0 driver.

    In Linode creation is a bit different. There you can pass the key file
    directly during creation. The Linode API also requires to set a disk size
    and doesn't get it from size.id. So, send size.disk from the client and
    use it in all cases just to avoid provider checking. Finally, Linode API
    does not support association between a machine and the image it came from.
    We could set this, at least for machines created through mist.api in
    ex_comment, lroot or lconfig. lroot seems more appropriate. However,
    liblcoud doesn't support linode.config.list at the moment, so no way to
    get them. Also, it will create inconsistencies for machines created
    through mist.api and those from the Linode interface.

    """
    # script: a command that is given once
    # script_id: id of a script that exists - for mist.core
    # script_params: extra params, for script_id
    # post_script_id: id of a script that exists - for mist.core. If script_id
    # or monitoring are supplied, this will run after both finish
    # post_script_params: extra params, for post_script_id

    log.info('Creating machine %s on cloud %s' % (machine_name, cloud_id))
    cloud = Cloud.objects.get(owner=auth_context.owner,
                              id=cloud_id, deleted=None)

    conn = connect_provider(cloud)
    machine_name = machine_name_validator(conn.type, machine_name)
    key = None
    if key_id:
        key = Key.objects.get(owner=auth_context.owner,
                              id=key_id, deleted=None)

    # if key_id not provided, search for default key
    if conn.type not in [Provider.LIBVIRT,
                         Container_Provider.DOCKER,
                         Provider.ONAPP,
                         Provider.AZURE_ARM]:
        if not key_id:
            key = Key.objects.get(owner=auth_context.owner,
                                  default=True, deleted=None)
            key_id = key.name
    if key:
        private_key = key.private
        public_key = key.public.replace('\n', '')
    else:
        public_key = None

    # For providers, which do not support pre-defined sizes, we expect `size`
    # to be a dict with all the necessary information regarding the machine's
    # size.
    if cloud.ctl.provider in ('vsphere', 'onapp', 'libvirt', 'lxd', 'gig_g8',):
        if not isinstance(size, dict):
            raise BadRequestError('Expected size to be a dict.')
        size_id = 'custom'
        size_ram = size.get('ram', 256)
        size_cpu = size.get('cpu', 1)
        size_disk_primary = size.get('disk_primary', 5)
        size_disk_swap = size.get('disk_swap', 1)
        # Required by OnApp only.
        boot = size.get('boot', True)
        build = size.get('build', True)
        cpu_priority = size.get('cpu_priority', 1)
        cpu_sockets = size.get('cpu_sockets', 1)
        cpu_threads = size.get('cpu_threads', 1)
        port_speed = size.get('port_speed', 0)
        hypervisor_group_id = size.get('hypervisor_group_id')
    else:
        if not isinstance(size, (string_types, int)):
            raise BadRequestError('Expected size to be an id.')
        size_id = size
    size = NodeSize(size_id, name=size_name, ram='', disk=disk,
                    bandwidth='', price='', driver=conn)

    image = NodeImage(image_id, name=image_name, extra=image_extra,
                      driver=conn)

    # transform location id to libcloud's NodeLocation object
    try:
        from mist.api.clouds.models import CloudLocation
        cloud_location = CloudLocation.objects.get(id=location_id)
        location = NodeLocation(cloud_location.external_id,
                                name=cloud_location.name,
                                country=cloud_location.country,
                                extra=cloud_location.extra,
                                driver=conn)
    except me.DoesNotExist:
        # make sure mongo is up-to-date
        cloud.ctl.compute.list_locations()
        try:
            from mist.api.clouds.models import CloudLocation
            cloud_location = CloudLocation.objects.get(id=location_id)
            location = NodeLocation(cloud_location.external_id,
                                    name=cloud_location.name,
                                    country=cloud_location.country,
                                    extra=cloud_location.extra,
                                    driver=conn)
        except me.DoesNotExist:
            location = NodeLocation(location_id, name=location_name,
                                    country='', driver=conn)

    # transform size id to libcloud's NodeSize object
    try:
        from mist.api.clouds.models import CloudSize
        cloud_size = CloudSize.objects.get(id=size_id)
        size = NodeSize(cloud_size.external_id,
                        name=cloud_size.name,
                        ram=cloud_size.ram,
                        disk=cloud_size.disk,
                        bandwidth=cloud_size.bandwidth,
                        price=cloud_size.extra.get('price'),
                        driver=conn)
    except me.DoesNotExist:
        # make sure mongo is up-to-date
        cloud.ctl.compute.list_sizes()
        try:
            cloud_size = CloudSize.objects.get(id=size_id)
            size = NodeSize(cloud_size.external_id,
                            name=cloud_size.name,
                            ram=cloud_size.ram,
                            disk=cloud_size.disk,
                            bandwidth=cloud_size.bandwidth,
                            price=cloud_size.extra.get('price'),
                            driver=conn)
        except me.DoesNotExist:
            # instantiate a dummy libcloud NodeSize
            size = NodeSize(size_id, name=size_name,
                            ram=0, disk=0, bandwidth=0,
                            price=0, driver=conn)

    cached_machines = [m.as_dict()
                       for m in cloud.ctl.compute.list_cached_machines()]

    if conn.type is Container_Provider.DOCKER:
        if public_key:
            node = _create_machine_docker(
                conn, machine_name, image_id, '',
                public_key=public_key,
                docker_env=docker_env,
                docker_command=docker_command,
                docker_port_bindings=docker_port_bindings,
                docker_exposed_ports=docker_exposed_ports
            )
            node_info = cloud.ctl.compute.inspect_node(node)
            try:
                ssh_port = int(
                    node_info.extra[
                        'network_settings']['Ports']['22/tcp'][0]['HostPort'])
            except:
                pass
        else:
            node = _create_machine_docker(
                conn, machine_name, image_id, script,
                docker_env=docker_env,
                docker_command=docker_command,
                docker_port_bindings=docker_port_bindings,
                docker_exposed_ports=docker_exposed_ports
            )
    elif conn.type is Container_Provider.LXD:

        node = _create_machine_lxd(conn=conn, machine_name=machine_name,
                                   image=image, parameters=lxd_image_source,
                                   start=True, cluster=None,
                                   ephemeral=ephemeral,
                                   size_cpu=size_cpu, size_ram=size_ram,
                                   volumes=volumes, networks=networks)
    elif conn.type in [Provider.RACKSPACE_FIRST_GEN, Provider.RACKSPACE]:
        node = _create_machine_rackspace(conn, public_key, machine_name, image,
                                         size, location, user_data=cloud_init)
    elif conn.type in [Provider.OPENSTACK]:
        node = _create_machine_openstack(conn, private_key, public_key,
                                         key.name, machine_name, image, size,
                                         location, networks, volumes,
                                         cloud_init)
    elif conn.type is Provider.EC2:
        locations = conn.list_locations()
        for loc in locations:
            if loc.id == location.id:
                ec2_location = loc
                break
        node = _create_machine_ec2(conn, key.name, public_key,
                                   machine_name, image, size, ec2_location,
                                   subnet_id, cloud_init, volumes,
                                   sec_group=sec_group)
    elif conn.name == 'Aliyun ECS':
        node = _create_machine_aliyun(conn, key.name, public_key,
                                      machine_name, image, size, location,
                                      subnet_id, cloud_init, volumes)
    elif conn.type is Provider.GCE:
        libcloud_sizes = conn.list_sizes(location=location_name)
        for libcloud_size in libcloud_sizes:
            if libcloud_size.id == size.id:
                size = libcloud_size
                break

        # FIXME: `networks` should always be an array, not a str like below
        node = _create_machine_gce(conn, key_id, private_key, public_key,
                                   machine_name, image, size, location,
                                   networks, subnetwork, volumes, cloud_init)
    elif conn.type is Provider.SOFTLAYER:
        node = _create_machine_softlayer(
            conn, key_id, private_key, public_key,
            machine_name, image, size,
            location, bare_metal, cloud_init,
            hourly, softlayer_backend_vlan_id
        )
    elif conn.type is Provider.GIG_G8:
        node = create_machine_g8(
            conn, machine_name, image, size_ram, size_cpu,
            size_disk_primary, public_key, description, networks,
            volumes, cloud_init
        )
        ssh_port = node.extra.get('ssh_port', 22)
    elif conn.type is Provider.ONAPP:
        node = _create_machine_onapp(
            conn, public_key,
            machine_name, image, size_ram,
            size_cpu, size_disk_primary, size_disk_swap,
            boot, build, cpu_priority, cpu_sockets,
            cpu_threads, port_speed,
            location, networks, hypervisor_group_id
        )
    elif conn.type is Provider.DIGITAL_OCEAN:
        node = _create_machine_digital_ocean(
            conn, cloud, key_id, private_key,
            public_key, machine_name,
            image, size, location, cloud_init, volumes)
    elif conn.type == Provider.AZURE:
        node = _create_machine_azure(
            conn, key_id, private_key,
            public_key, machine_name,
            image, size, location,
            cloud_init=cloud_init,
            cloud_service_name=None,
            azure_port_bindings=azure_port_bindings
        )
    elif conn.type == Provider.AZURE_ARM:
        image = conn.get_image(image_id, location)
        node = _create_machine_azure_arm(
            auth_context.owner, cloud_id, conn, public_key, machine_name,
            image, size, location, networks,
            storage_account, machine_password, resource_group,
            machine_username, volumes, storage_account_type,
            cloud_init
        )
    elif conn.type in [Provider.VCLOUD]:
        node = _create_machine_vcloud(conn, machine_name, image,
                                      size, public_key, networks)
    elif conn.type is Provider.VSPHERE:
        size.ram = size_ram
        size.extra['cpu'] = size_cpu
        size.disk = size_disk_primary
        node = _create_machine_vsphere(conn, machine_name, image,
                                       size, location, networks, folder,
                                       datastore)
    elif conn.type is Provider.LINODE and private_key:
        # FIXME: The orchestration UI does not provide all the necessary
        # parameters, thus we need to fetch the proper size and image objects.
        # This should be properly fixed when migrated to the controllers.
        if not image_extra:  # Missing: {'64bit': 1, 'pvops': 1}
            for image in conn.list_images():
                if int(image.id) == int(image_id):
                    image = image
                    break
        node = _create_machine_linode(conn, key_id, private_key, public_key,
                                      machine_name, image, size,
                                      location)
    elif conn.type == Provider.HOSTVIRTUAL:
        node = _create_machine_hostvirtual(conn, public_key,
                                           machine_name, image,
                                           size, location)
    elif conn.type == Provider.VULTR:
        node = _create_machine_vultr(conn, public_key, machine_name, image,
                                     size, location, cloud_init)
    elif conn.type is Provider.LIBVIRT:
        node = _create_machine_libvirt(conn, machine_name,
                                       disk_size=disk_size,
                                       ram=size_ram, cpu=size_cpu,
                                       image=image_id,
                                       disk_path=disk_path,
                                       networks=networks,
                                       public_key=public_key,
                                       cloud_init=cloud_init,
                                       vnfs=vnfs)
    elif conn.type == Provider.PACKET:
        node = _create_machine_packet(conn, public_key, machine_name, image,
                                      size, location, cloud_init, cloud,
                                      project_id, volumes, ip_addresses)
    elif conn.type == Provider.MAXIHOST:
        node = _create_machine_maxihost(conn, machine_name, image,
                                        size, location, public_key)
    else:
        raise BadRequestError("Provider unknown.")

    for i in range(0, 10):
        try:
            machine = Machine.objects.get(cloud=cloud, machine_id=node.id)
            break
        except me.DoesNotExist:
            if i < 6:
                time.sleep(i * 10)
                continue
            try:
                cloud.ctl.compute._list_machines()
            except Exception as e:
                if i > 8:
                    raise(e)
                else:
                    continue

    # Assign machine's owner/creator
    machine.assign_to(auth_context.user)

    # add schedule if expiration given
    if expiration:
        params = {
            'schedule_type': 'one_off',
            'description': 'Scheduled to run when machine expires',
            'schedule_entry': expiration.get('date'),
            'action': expiration.get('action'),
            'conditions': [{'type': 'machines', 'ids': [machine.id]}],
            'task_enabled': True,
            'notify': expiration.get('notify', ''),
            'notify_msg': expiration.get('notify_msg', '')
        }
        name = machine.name + '-expiration-' + str(randrange(1000))
        from mist.api.schedules.models import Schedule
        machine.expiration = Schedule.add(auth_context, name, **params)
        machine.save()

    if key is not None:  # Associate key.
        username = node.extra.get('username', '')
        machine.ctl.associate_key(key, username=username,
                                  port=ssh_port, no_connect=True)
    if tags:
        resolve_id_and_set_tags(auth_context. owner, 'machine', node.id, tags,
                                cloud_id=cloud_id)
    fresh_machines = cloud.ctl.compute._list_machines()
    cloud.ctl.compute.produce_and_publish_patch(cached_machines,
                                                fresh_machines,
                                                first_run=True)

    # Call post_deploy_steps for every provider FIXME: Refactor
    if conn.type == Provider.AZURE:
        # for Azure, connect with the generated password, deploy the ssh key
        # when this is ok, it calls post_deploy for script/monitoring
        mist.api.tasks.azure_post_create_steps.delay(
            auth_context.owner.id, cloud_id, node.id, monitoring, key_id,
            node.extra.get('username'), node.extra.get('password'), public_key,
            script=script,
            script_id=script_id, script_params=script_params, job_id=job_id,
            hostname=hostname, plugins=plugins, post_script_id=post_script_id,
            post_script_params=post_script_params, schedule=schedule, job=job,
        )
    elif conn.type == Provider.OPENSTACK:
        if associate_floating_ip:
            networks = list_networks(auth_context.owner, cloud_id)
            mist.api.tasks.openstack_post_create_steps.delay(
                auth_context.owner.id, cloud_id, node.id, monitoring, key_id,
                node.extra.get('username'), node.extra.get('password'),
                public_key, script=script, script_id=script_id,
                script_params=script_params,
                job_id=job_id, job=job, hostname=hostname, plugins=plugins,
                post_script_params=post_script_params,
                networks=networks, schedule=schedule,
            )
    elif conn.type == Provider.RACKSPACE_FIRST_GEN:
        # for Rackspace First Gen, cannot specify ssh keys. When node is
        # created we have the generated password, so deploy the ssh key
        # when this is ok and call post_deploy for script/monitoring
        mist.api.tasks.rackspace_first_gen_post_create_steps.delay(
            auth_context.owner.id, cloud_id, node.id, monitoring, key_id,
            node.extra.get('password'), public_key, script=script,
            script_id=script_id, script_params=script_params,
            job_id=job_id, job=job, hostname=hostname, plugins=plugins,
            post_script_id=post_script_id,
            post_script_params=post_script_params, schedule=schedule,
        )

    else:
        mist.api.tasks.post_deploy_steps.delay(
            auth_context.owner.id, cloud_id, node.id, monitoring,
            script=script, key_id=key_id, script_id=script_id,
            script_params=script_params, job_id=job_id, job=job, port=ssh_port,
            hostname=hostname, plugins=plugins, post_script_id=post_script_id,
            post_script_params=post_script_params, schedule=schedule,
        )

    ret = {'id': node.id,
           'name': node.name,
           'extra': node.extra,
           'job_id': job_id,
           }

    if isinstance(node, Node):
        ret.update({'public_ips': node.public_ips,
                    'private_ips': node.private_ips})
    else:
        # add public and private ips for docker container
        ret.update({'public_ips': [],
                    'private_ips': []})
    return ret


def create_machine_g8(conn, machine_name, image, ram, cpu, disk,
                      public_key, description, networks, volumes,
                      cloud_init):
    auth = None
    ex_expose_ssh = False
    if public_key:
        key = public_key.replace('\n', '')
        auth = NodeAuthSSHKey(pubkey=key)
        ex_expose_ssh = True

    try:
        mist_net = Network.objects.get(id=networks[0])
    except me.DoesNotExist:
        raise NetworkNotFoundError()

    try:
        libcloud_networks = conn.ex_list_networks()
    except MalformedResponseError as exc:
        if 'AccessDenied' in exc.body:
            raise MachineCreationError("G8 got exception 'Access Denied'. \
                Make sure your JWT token has not expired.")
    ex_network = None
    for libcloud_net in libcloud_networks:
        if mist_net.network_id == libcloud_net.id:
            ex_network = libcloud_net
            break

    ex_create_attr = {
        "memory": ram,
        "vcpus": cpu,
        "disk_size": disk
    }

    if volumes:
        disks = [volume.get('size') for volume in volumes]
        ex_create_attr.update({"data_disks": disks})

    if cloud_init:
        ex_create_attr.update({"user_data": cloud_init})

    try:
        node = conn.create_node(
            name=machine_name,
            image=image,
            ex_network=ex_network,
            ex_description=description,
            auth=auth,
            ex_create_attr=ex_create_attr,
            ex_expose_ssh=ex_expose_ssh
        )
    except Exception as e:
        raise MachineCreationError("Gig G8, got exception %s" % e, e)

    return node


def _create_machine_rackspace(conn, public_key, machine_name,
                              image, size, location, user_data):
    """Create a machine in Rackspace.
    """

    key = str(public_key).replace('\n', '')

    try:
        server_key = ''
        keys = conn.ex_list_keypairs()
        for k in keys:
            if key == k.public_key:
                server_key = k.name
                break
        if not server_key:
            server_key = conn.ex_import_keypair_from_string(name=machine_name,
                                                            key_material=key)
            server_key = server_key.name
    except:
        try:
            server_key = conn.ex_import_keypair_from_string(
                name='mistio' + str(random.randint(1, 100000)),
                key_material=key)
            server_key = server_key.name
        except AttributeError:
            # RackspaceFirstGenNodeDriver based on OpenStack_1_0_NodeDriver
            # has no support for keys. So don't break here, since
            # create_node won't include it anyway
            server_key = None

    try:
        node = conn.create_node(name=machine_name, image=image, size=size,
                                location=location, ex_keyname=server_key,
                                ex_userdata=user_data)
        return node
    except Exception as e:
        raise MachineCreationError("Rackspace, got exception %r" % e, exc=e)


def _create_machine_openstack(conn, private_key, public_key, key_name,
                              machine_name, image, size, location, networks,
                              volumes, user_data):
    """Create a machine in Openstack.
    """
    key = str(public_key).replace('\n', '')

    try:
        server_key = ''
        keys = conn.ex_list_keypairs()
        for k in keys:
            if key == k.public_key:
                server_key = k.name
                break
        if not server_key:
            server_key = conn.ex_import_keypair_from_string(name=key_name,
                                                            key_material=key)
            server_key = server_key.name
    except:
        server_key = conn.ex_import_keypair_from_string(
            name='mistio' + str(random.randint(1, 100000)),
            key_material=key)
        server_key = server_key.name

    # select the right OpenStack network object
    # FIXME This is a bit error-prone, since here we are expected to pass a
    # list of networks to libcloud, while in case of vSphere, `networks` is
    # a single ID.
    if not isinstance(networks, list):
        networks = [networks]
    chosen_networks = []
    cached_network_ids = [n.network_id for
                          n in Network.objects(id__in=networks)]
    try:
        for network in conn.ex_list_networks():
            if network.id in cached_network_ids:
                chosen_networks.append(network)
    except:
        chosen_networks = []

    blockdevicemappings = []
    with get_temp_file(private_key) as tmp_key_path:
        try:
            if volumes:
                if volumes[0].get('size'):
                    blockdevicemappings = [{
                        'boot_index': "0",
                        'delete_on_termination': bool(
                            volumes[0]['delete_on_termination']),
                        'source_type': 'image',
                        'uuid': str(image.id),
                        'destination_type': 'volume',
                        'volume_size': int(volumes[0]['size'])
                    }]
                else:
                    from mist.api.volumes.models import Volume
                    volume_id = volumes[0]['volume_id']
                    vol = Volume.objects.get(id=volume_id)
                    blockdevicemappings = [{
                        'delete_on_termination': bool(volumes[0][
                            'delete_on_termination']),
                        'volume_id': vol.external_id
                    }]
            node = conn.create_node(
                name=machine_name,
                image=image,
                size=size,
                location=location,
                ssh_key=tmp_key_path,
                ssh_alternate_usernames=['ec2-user', 'ubuntu'],
                max_tries=1,
                ex_keyname=server_key,
                networks=chosen_networks,
                ex_blockdevicemappings=blockdevicemappings,
                ex_userdata=user_data)
        except Exception as e:
            raise MachineCreationError("OpenStack, got exception %s" % e, e)
    return node


def _create_machine_aliyun(conn, key_name, public_key,
                           machine_name, image, size, location, subnet_id,
                           user_data, volumes=[], security_group_id=None):
    """Create a machine in Alibaba Aliyun ECS.
    """
    sec_gr_name = config.EC2_SECURITYGROUP.get('name', '')
    sec_gr_description = config.EC2_SECURITYGROUP.get('description', '')
    vpc_name = config.ECS_VPC.get('name', '')
    vpc_description = config.ECS_VPC.get('description', '')
    security_groups = conn.ex_list_security_groups()
    mist_sg = [sg for sg in security_groups if sg.name == sec_gr_name]

    if not len(mist_sg) or not mist_sg[0].vpc_id:
        filters = {'VpcName': vpc_name, 'Description': vpc_description}
        vpc_id = conn.ex_create_network(ex_filters=filters)
        # wait for vpc to be available
        timeout = time.time() + 30
        while time.time() < timeout:
            vpcs = conn.ex_list_networks(ex_filters={'VpcId': vpc_id})
            if vpcs[0].status == 'Available':
                break
            time.sleep(2)

        security_group_id = conn.ex_create_security_group(vpc_id=vpc_id)

        conn.ex_modify_security_group_by_id(security_group_id,
                                            name=sec_gr_name,
                                            description=sec_gr_description)
        conn.ex_authorize_security_group(security_group_id, 'Allow SSH',
                                         'tcp', '22/22', )
    else:
        vpc_id = mist_sg[0].vpc_id
        security_group_id = mist_sg[0].id

    switches = conn.ex_list_switches(ex_filters={'VpcId': vpc_id})
    if switches:
        ex_vswitch_id = switches[0].id
    else:
        ex_vswitch_id = conn.ex_create_switch('172.16.0.0/24',
                                              location.id, vpc_id)

    ex_data_disks = []
    ex_volumes = []
    for volume in volumes:
        if volume.get('volume_id'):
            try:
                from mist.api.volumes.models import Volume
                mist_vol = Volume.objects.get(id=volume.get('volume_id'))
                libcloud_disks = conn.list_volumes()
                for libcloud_disk in libcloud_disks:
                    if libcloud_disk.id == mist_vol.external_id:
                        ex_volumes.append(libcloud_disk)
                        break
            except me.DoesNotExist:
                # try to find disk using libcloud's id
                libcloud_disks = conn.list_volumes()
                for libcloud_disk in libcloud_disks:
                    if libcloud_disk.id == volume.get('volume_id'):
                        ex_volumes.append(libcloud_disk)
                        break
                raise VolumeNotFoundError()
        else:
            ex_data_disks.append(volume)

    kwargs = {
        'auth': NodeAuthSSHKey(pubkey=public_key.replace('\n', '')),
        'name': machine_name,
        'image': image,
        'size': size,
        'location': location,
        'max_tries': 1,
        'ex_keyname': key_name,
        'ex_userdata': user_data,
        'ex_security_group_id': security_group_id,
        'ex_io_optimized': True,
        'ex_allocate_public_ip_address': True,
        'ex_internet_charge_type': 'PayByTraffic',
        'ex_internet_max_bandwidth_out': 100
    }

    if ex_data_disks:
        kwargs.update({'ex_data_disks': ex_data_disks})

    if ex_vswitch_id:
        kwargs.update({'ex_vswitch_id': ex_vswitch_id})

    try:
        node = conn.create_node(**kwargs)
    except Exception as e:
        raise MachineCreationError("Aliyun ECS, got exception %s" % e, e)

    # wait for node to be running, in order to attach disks to it
    if ex_volumes:
        ready = False
        while not ready:
            lib_nodes = conn.list_nodes()
            for lib_node in lib_nodes:
                if lib_node.id == node.id and lib_node.state == 'running':
                    ready = True

        for volume in ex_volumes:
            conn.attach_volume(node, volume)

    return node


def _create_machine_ec2(conn, key_name, public_key,
                        machine_name, image, size, location, subnet_id,
                        user_data, volumes, sec_group=''):
    """Create a machine in Amazon EC2.
    """
    if not sec_group:
        # create security group
        sg_name = config.EC2_SECURITYGROUP.get('name', '')
        description = config.EC2_SECURITYGROUP.get('description', '')
        try:
            log.info("Attempting to create security group")
            conn.ex_create_security_group(
                name=sg_name, description=description)
            conn.ex_authorize_security_group_permissive(name=sg_name)
        except Exception as exc:
            if 'Duplicate' in str(exc):
                log.info('Security group already exists, not doing anything.')
            else:
                raise InternalServerError(
                    "Couldn't create security group", exc)
    else:
        sec_groups = conn.ex_list_security_groups()
        for sg in sec_groups:
            if sg['id'] == sec_group:
                sg_name = sg['name']
                break
        else:
            raise BadRequestError("Security group not found: %s" % sec_group)

    kwargs = {
        'auth': NodeAuthSSHKey(pubkey=public_key.replace('\n', '')),
        'name': machine_name,
        'image': image,
        'size': size,
        'location': location,
        'max_tries': 1,
        'ex_keyname': key_name,
        'ex_userdata': user_data
    }

    if subnet_id:
        try:
            subnet = Subnet.objects.get(id=subnet_id)
            subnet_id = subnet.subnet_id
        except Subnet.DoesNotExist:
            try:
                subnet = Subnet.objects.get(subnet_id=subnet_id)
                log.info('Got providers id instead of mist id, not \
                doing nothing.')
            except Subnet.DoesNotExist:
                raise NotFoundError('Subnet specified does not exist')

        subnets = conn.ex_list_subnets()
        for libcloud_subnet in subnets:
            if libcloud_subnet.id == subnet_id:
                subnet = libcloud_subnet
                break
        else:
            raise NotFoundError('Subnet specified does not exist')

        # if subnet is specified, then security group id
        # instead of security group name is needed
        if not sec_group:
            groups = conn.ex_list_security_groups()
            for group in groups:
                if group.get('name') == config.EC2_SECURITYGROUP.get('name',
                                                                     ''):
                    security_group_id = group.get('id')
                    break
        else:
            security_group_id = sec_group
        kwargs.update({
            'ex_subnet': subnet,
            'ex_security_group_ids': security_group_id})

    else:
        kwargs.update({
            'ex_securitygroup': sg_name})

    mappings = []
    ex_volumes = []
    for volume in volumes:
        if volume.get('volume_id'):
            try:
                from mist.api.volumes.models import Volume
                mist_vol = Volume.objects.get(id=volume.get('volume_id'))
                libcloud_disks = conn.list_volumes()
                for libcloud_disk in libcloud_disks:
                    if libcloud_disk.id == mist_vol.external_id:
                        ex_vol = {'volume': libcloud_disk,
                                  'device': volume.get('device')}
                        ex_volumes.append(ex_vol)
                        break
            except me.DoesNotExist:
                # try to find disk using libcloud's id
                libcloud_disks = conn.list_volumes()
                for libcloud_disk in libcloud_disks:
                    if libcloud_disk.id == volume.get('volume_id'):
                        ex_vol = {'volume': libcloud_disk,
                                  'device': volume.get('device')}
                        ex_volumes.append(ex_vol)
                        break
                raise VolumeNotFoundError()

        else:
            mapping = {}
            mapping.update({'Ebs': {'VolumeSize': int(volume.get('size'))}})
            if volume.get('name'):
                mapping.update({'DeviceName': volume.get('name')})
            if volume.get('ex_volume_type'):
                volume_type = {'VolumeType': volume.get('ex_volume_type')}
                mapping['Ebs'].update(volume_type)
            if volume.get('ex_iops'):
                mapping['Ebs'].update({'Iops': volume.get('ex_iops')})
            if volume.get('delete_on_termination'):
                delete_on_term = volume.get('delete_on_termination')
                mapping['Ebs'].update({'DeleteOnTermination': delete_on_term})

            mappings.append(mapping)

    kwargs.update({'ex_blockdevicemappings': mappings})

    try:
        node = conn.create_node(**kwargs)

    except Exception as e:
        raise MachineCreationError("EC2, got exception %s" % e, e)

    # wait for node to be running, in order to attach disks to it
    if ex_volumes:
        ready = False
        while not ready:
            lib_nodes = conn.list_nodes()
            for lib_node in lib_nodes:
                if lib_node.id == node.id and lib_node.state == 'running':
                    ready = True

        for volume in ex_volumes:
            conn.attach_volume(
                node, volume.get('volume'), volume.get('device'))

    return node


def _create_machine_softlayer(conn, key_name, private_key, public_key,
                              machine_name, image, size, location,
                              bare_metal, cloud_init, hourly,
                              softlayer_backend_vlan_id):
    """Create a machine in Softlayer.
    """
    key = str(public_key).replace('\n', '')
    try:
        server_key = ''
        keys = conn.list_key_pairs()
        for k in keys:
            if key == k.public_key:
                server_key = k.extra.get('id')
                break
        if not server_key:
            server_key = conn.import_key_pair_from_string(machine_name, key)
            server_key = server_key.extra.get('id')
    except:
        server_key = conn.import_key_pair_from_string(
            'mistio' + str(random.randint(1, 100000)), key
        )
        server_key = server_key.extra.get('id')

    if '.' in machine_name:
        domain = '.'.join(machine_name.split('.')[1:])
        name = machine_name.split('.')[0]
    else:
        domain = None
        name = machine_name

    # FIXME: SoftLayer allows only bash/script, no actual cloud-init
    # Also need to upload this on a public https url...
    if cloud_init:
        postInstallScriptUri = ''
    else:
        postInstallScriptUri = None

    try:
        node = conn.create_node(
            name=name,
            ex_domain=domain,
            image=image,
            size=size,
            location=location,
            sshKeys=server_key,
            bare_metal=bare_metal,
            postInstallScriptUri=postInstallScriptUri,
            ex_hourly=hourly,
            ex_backend_vlan=softlayer_backend_vlan_id
        )
    except Exception as e:
        raise MachineCreationError("Softlayer, got exception %s" % e, e)

    return node


def _create_machine_onapp(conn, public_key,
                          machine_name, image, size_ram,
                          size_cpu, size_disk_primary, size_disk_swap,
                          boot, build, cpu_priority, cpu_sockets,
                          cpu_threads, port_speed,
                          location, networks, hypervisor_group_id):
    """Create a machine in OnApp.

    """
    if public_key:
        # get user_id, push ssh key. This will be deployed on the new server
        try:
            res = conn.ex_list_profile_info()
            user_id = res['id']
            conn.create_key_pair(user_id, public_key)
        except:
            pass
    boot = 1 if boot else 0
    build = 1 if build else 0
    try:
        node = conn.create_node(
            machine_name,
            str(size_ram),
            str(size_cpu),
            cpu_priority,
            machine_name,
            image.id,
            str(size_disk_primary),
            str(size_disk_swap),
            ex_required_virtual_machine_build=build,
            ex_required_ip_address_assignment=1,
            ex_required_virtual_machine_startup=boot,
            ex_cpu_sockets=cpu_sockets,
            ex_cpu_threads=cpu_threads,
            ex_hypervisor_group_id=hypervisor_group_id,
            ex_primary_network_group_id=networks,
            rate_limit=port_speed
        )
    except Exception as e:
        raise MachineCreationError("OnApp, got exception %s" % e, e)

    return node


def _create_machine_maxihost(conn, machine_name, image_id, size,
                             location, public_key):
    key = str(public_key).replace('\n', '')
    ssh_keys = []
    server_key = ''
    keys = conn.list_key_pairs()
    for k in keys:
        if key == k.public_key:
            server_key = k
            break
    if not server_key:
        server_key = conn.create_key_pair(name=machine_name,
                                          public_key=public_key)

    ssh_keys.append(server_key.fingerprint)

    try:
        node = conn.create_node(machine_name, size, image_id,
                                location, ssh_keys)
    except ValueError as exc:
        raise MachineCreationError('Maxihost, exception %s' % exc)

    return node


def _create_machine_docker(conn, machine_name, image_id,
                           script=None, public_key=None,
                           docker_env={}, docker_command=None,
                           tty_attach=True, docker_port_bindings={},
                           docker_exposed_ports={}):
    """Create a machine in docker."""
    image = ContainerImage(id=image_id, name=image_id,
                           extra={}, driver=conn, path=None,
                           version=None)
    try:
        if public_key:
            environment = ['PUBLIC_KEY=%s' % public_key.strip()]
        else:
            environment = []

        if isinstance(docker_env, dict):
            # docker_env is a dict, and we must convert it ot be in the form:
            # [ "key=value", "key=value"...]
            docker_environment = ["%s=%s" % (key, value) for key, value in
                                  docker_env.items()]
            environment += docker_environment

        try:
            container = conn.deploy_container(
                machine_name, image,
                command=docker_command,
                environment=environment,
                tty=tty_attach,
                ports=docker_exposed_ports or {},
                port_bindings=docker_port_bindings or {}
            )
        except Exception as e:
            # if image not found, try to pull it
            if 'No such image' in str(e):
                try:
                    conn.install_image(image.name)
                    container = conn.deploy_container(
                        machine_name, image,
                        command=docker_command,
                        environment=environment,
                        tty=tty_attach,
                        ports=docker_exposed_ports,
                        port_bindings=docker_port_bindings
                    )
                except Exception as e:
                    raise Exception(e)
            else:
                raise Exception(e)

    except Exception as e:
        raise MachineCreationError("Docker, got exception %s" % e, e)

    return container


def _create_machine_lxd(conn, machine_name, image,
                        parameters, start=True, cluster=None,
                        ephemeral=False,
                        size_cpu=None, size_ram=None,
                        profiles=None, devices=None, instance_type=None,
                        volumes=None, networks=None):
    """
    Create a new LXC container on the machine described by the given
    conn argument. Currently we only support
    local image identified by its fingerprint

    :param conn: The connection to the machine to create the container
    :param machine_name: The name of the container
    :param image: a libcloud.NodeImage
    :param parameters: extra parameters for the ContainerImage
    :param start: Whether the container should be started at creation
    :param cluster: The cluster the container belongs to
    :param profiles: A list of profiles e.g ["default"]
    :param ephemeral: Whether to destroy the container on shutdown
    :param config: Config override e.g.  {"limits.cpu": "2"},
    :param devices: optional list of devices the container should have
    :param instance_type: An optional instance type to
    use as basis for limits e.g. "c2.micro"

    :return: libcloud.Container
    """

    from libcloud.container.drivers.lxd import LXDAPIException
    image = ContainerImage(id=image.id, name=image.name,
                           extra={}, driver=conn, path=None,
                           version=None)
    try:

        # default time out
        timeout = conn.default_time_out
        img_params = {
            "source": {
                "type": "image",
            }
        }
        if parameters is None:
            img_params["source"]["fingerprint"] = image.id
        else:
            # check if the image exists locally
            image_exists, _ = conn.ex_has_image(alias=parameters)

            if image_exists:
                # then the image exists locally
                # sp use this
                img_params["source"]["alias"] = parameters
            else:
                raise MistNotImplementedError()

        # by default no devices
        devices = {}

        # if we have a volume we need to create it also
        # simply attach it. Currently assume that the
        # volume is just given
        if volumes is not None\
                and len(volumes) != 0:
            # we requested volumes as well
            # if this is a new volume
            # we must create it otherwise we simply
            # append to the devices

            path = volumes[0].get('path', None)

            if path is None:
                raise MachineCreationError("You need to provide"
                                           " a path for the storage")

            pool_id = volumes[0].get('pool_id', None)

            if pool_id is None:

                # this means we attach an
                # existing volume
                volume_id = volumes[0].get('volume_id', None)

                if volume_id is None:
                    raise MachineCreationError("You need to provide"
                                               " a volume name to attach to")

                from mist.api.volumes.models import Volume

                volume = Volume.objects.get(id=volume_id)

                volume = {volume.name: {
                    "type": "disk",
                    "path": path,
                    "source": volume.name,
                    "pool": volume.extra["pool_id"]
                }}
            else:

                # this mean we create a new volume
                vol_config = {}
                definition = {"name": volumes[0]["name"], "type": "custom",
                              "size_type": "GB"}

                # keys are set according to
                # https://linuxcontainers.org/lxd/docs/master/storage
                if "block_filesystem" in volumes[0] and \
                        volumes[0]["block_filesystem"] != '':

                    vol_config["block.filesystem"] = \
                        volumes[0]["block_filesystem"]

                if "block_mount_options" in volumes[0] and \
                        volumes[0]["block_mount_options"] != '':

                    vol_config["block.mount_options"] = \
                        volumes[0]['block_mount_options']

                if "security_shifted" in volumes[0]:
                    vol_config["security.shifted"] = \
                        str(volumes[0]['security_shifted'])

                vol_config['size'] = volumes[0]["size"]

                definition["config"] = vol_config

                try:
                    # create the volume
                    volume = conn.create_volume(pool_id=volumes[0]["pool_id"],
                                                definition=definition)

                    # the volume to attach
                    volume = {volume.name: {
                        "type": "disk",
                        "path": path,
                        "source": volume.name,
                        "pool": volume.extra["pool_id"]
                    }}
                except Exception as e:
                    raise MachineCreationError("LXD volume creation, "
                                               "got exception %s" % e)

            if devices is not None:
                devices.update(volume)
            else:
                devices = volume

        if networks is not None\
                and len(networks) != 0:

            # we also want to attache a network
            network_id = networks

            from mist.api.networks.models import LXDNetwork

            network = LXDNetwork.objects.get(id=network_id)

            net_type = network.extra.get("type", "nic")
            net_nictype = network.extra.get("nictype", "bridged")
            net_parent = network.extra.get("parent", "lxdbr0")

            # add the network to the devices
            devices[network.name] = {
                "name": network.name,
                "type": net_type,
                "nictype": net_nictype,
                "parent": net_parent,
            }

        config = {}

        if size_cpu is not None:
            config['limits.cpu'] = str(size_cpu)

        if size_ram is not None:
            config['limits.memory'] = str(size_ram) + "MB"

        container = conn.deploy_container(name=machine_name, image=None,
                                          cluster=cluster,
                                          parameters=json.dumps(img_params),
                                          start=start,
                                          ex_ephemeral=ephemeral,
                                          ex_config=config,
                                          ex_instance_type=instance_type,
                                          ex_devices=devices,
                                          ex_profiles=profiles,
                                          ex_timeout=timeout)
        return container
    except LXDAPIException as e:
        raise MachineCreationError("Could not create "
                                   "LXD Machine: %s" % e.message)
    except Exception:
        raise


def _create_machine_digital_ocean(conn, cloud, key_name, private_key,
                                  public_key, machine_name, image, size,
                                  location, user_data, volumes):
    """Create a machine in Digital Ocean.
    """
    key = public_key.replace('\n', '')
    try:
        server_key = ''
        keys = conn.list_key_pairs()
        for k in keys:
            if key == k.public_key:
                server_key = k
                break
        if not server_key:
            server_key = conn.create_key_pair(machine_name, key)
    except:
        server_keys = [str(k.extra.get('id')) for k in keys]
    if not server_key:
        ex_ssh_key_ids = server_keys
    else:
        ex_ssh_key_ids = [str(server_key.extra.get('id'))]

    _volumes = []
    for volume in volumes:
        if volume.get('volume_id'):  # existing volume
            try:
                from mist.api.volumes.models import Volume
                mist_vol = Volume.objects.get(id=volume.get('volume_id'))
                _volumes.append(mist_vol.external_id)
            except me.DoesNotExist:
                # make sure mongo is up-to-date
                cloud.ctl.storage.list_volumes()
                try:
                    mist_vol = Volume.objects.get(id=volume.get('volume_id'))
                    _volumes.append(mist_vol.external_id)
                except me.DoesNotExist:
                    # try to find disk using libcloud's id
                    libcloud_disks = conn.list_volumes()
                    for libcloud_disk in libcloud_disks:
                        if libcloud_disk.id == volume.get('volume_id'):
                            _volumes.append(volume.get('volume_id'))
                            break
                    raise VolumeNotFoundError()

        else:   # new volume
            fs_type = volume.get('filesystem_type', '')
            new_volume = conn.create_volume(int(volume.get('size')),
                                            volume.get('name'),
                                            location=location,
                                            filesystem_type=fs_type)
            _volumes.append(new_volume.id)

    # check if location allows the private_networking setting
    private_networking = False
    try:
        locations = conn.list_locations()
        for loc in locations:
            if loc.id == location.id:
                if 'private_networking' in loc.extra:
                    private_networking = True
                break
    except:
        # do not break if this fails for some reason
        pass
    size.name = size.id  # conn.create_node will use size.name
    try:
        node = conn.create_node(
            name=machine_name,
            image=image,
            size=size,
            ex_ssh_key_ids=ex_ssh_key_ids,
            location=location,
            ex_create_attr={'private_networking': private_networking},
            ex_user_data=user_data,
            volumes=_volumes
        )
    except Exception as e:
        raise MachineCreationError(
            "Digital Ocean, got exception %s" % e, e
        )

    return node


def _create_machine_libvirt(conn, machine_name, disk_size, ram, cpu,
                            image, disk_path, networks,
                            public_key, cloud_init, vnfs=[]):
    """Create a machine in Libvirt.
    """
    # The libvirt drivers expects network names.
    from mist.api.networks.models import LibvirtNetwork
    if not isinstance(networks, list):
        networks = [networks]
    network_names = []
    for nid in (networks or []):
        if isinstance(nid, dict):
            network_id = nid.get('network_id', '')
        else:
            network_id = nid
        try:
            network_name = LibvirtNetwork.objects.get(id=network_id).name
        except LibvirtNetwork.DoesNotExist:
            log.error('LibvirtNetwork %s does not exist' % nid)
        else:
            if isinstance(nid, dict):
                nid.update({'network_name': network_name})
                network_names.append(nid)
            else:
                network_names.append(network_name)

    try:
        node = conn.create_node(
            name=machine_name,
            disk_size=disk_size,
            ram=ram,
            cpu=cpu,
            image=image,
            disk_path=disk_path,
            networks=network_names,
            public_key=public_key,
            cloud_init=cloud_init,
            vnfs=vnfs
        )

    except Exception as e:
        raise MachineCreationError("KVM, got exception %s" % e, e)

    return node


def _create_machine_hostvirtual(conn, public_key,
                                machine_name, image, size, location):
    """Create a machine in HostVirtual.
    """
    key = public_key.replace('\n', '')

    auth = NodeAuthSSHKey(pubkey=key)

    try:
        node = conn.create_node(
            name=machine_name,
            image=image,
            size=size,
            auth=auth,
            location=location
        )
    except Exception as e:
        raise MachineCreationError("HostVirtual, got exception %s" % e, e)

    return node


def _create_machine_packet(conn, public_key, machine_name, image,
                           size, location, cloud_init, cloud,
                           project_id=None, volumes=[], ip_addresses=[]):
    """Create a machine in Packet.net.
    """
    key = public_key.replace('\n', '')
    try:
        conn.create_key_pair('mistio', key)
    except:
        # key exists and will be deployed
        pass

    # if project_id is not specified, use the project for which the driver
    # has been initiated. If driver hasn't been initiated with a project,
    # then use the first one from the projects
    ex_project_id = None
    if not project_id:
        if conn.project_id:
            ex_project_id = conn.project_id
        else:
            try:
                ex_project_id = conn.projects[0].id
            except IndexError:
                raise BadRequestError(
                    "You don't have any projects on packet.net"
                )
    else:
        for project_obj in conn.projects:
            if project_id in [project_obj.name, project_obj.id]:
                ex_project_id = project_obj.id
                break
        if not ex_project_id:
            raise BadRequestError("Project id is invalid")
    ex_disk = None
    disk_size = ''
    if volumes:
        if volumes[0].get('volume_id'):  # will try to attach to existing disk
            # transform disk id to libcloud's StorageVolume object
            try:
                from mist.api.volumes.models import Volume
                volume = Volume.objects.get(id=volumes[0].get('volume_id'))
                ex_disk = StorageVolume(id=volume.external_id,
                                        name=volume.name,
                                        size=volume.size, driver=conn)
            except me.DoesNotExist:
                # make sure mongo is up-to-date
                cloud.ctl.storage.list_volumes()
                try:
                    volume = Volume.objects.get(id=volumes[0].get('volume_id'))
                    ex_disk = StorageVolume(id=volume.external_id,
                                            name=volume.name,
                                            size=volume.size, driver=conn)
                except me.DoesNotExist:
                    # try to find disk using libcloud's id
                    libcloud_disks = conn.list_volumes()
                    for libcloud_disk in libcloud_disks:
                        if libcloud_disk.id == volumes[0].get('volume_id'):
                            ex_disk = libcloud_disk
                            break
                    raise VolumeNotFoundError()
        else:
            disk_size = int(volumes[0].get('size'))

    try:
        node = conn.create_node(
            name=machine_name,
            size=size,
            image=image,
            location=location,
            ex_project_id=ex_project_id,
            ip_addresses=ip_addresses,
            cloud_init=cloud_init,
            disk=ex_disk,
            disk_size=disk_size
        )
    except Exception as e:
        raise MachineCreationError("Packet.net, got exception %s" % e, e)

    return node


def _create_machine_vultr(conn, public_key, machine_name, image,
                          size, location, cloud_init):
    """Create a machine in Vultr.
    """
    key = public_key.replace('\n', '')

    try:
        server_key = ''
        keys = conn.list_key_pairs()
        for k in keys:
            if key == k.ssh_key.replace('\n', ''):
                server_key = k
                break
        if not server_key:
            server_key = conn.create_key_pair(machine_name, key)
    except:
        server_key = conn.create_key_pair('mistio' + str(
            random.randint(1, 100000)), key)

    try:
        server_key = server_key.id
    except:
        pass

    ex_create_attr = {}
    if cloud_init:
        ex_create_attr['userdata'] = cloud_init

    try:
        node = conn.create_node(
            name=machine_name,
            size=size,
            image=image,
            location=location,
            ex_ssh_key_ids=[server_key],
            ex_create_attr=ex_create_attr
        )
    except Exception as e:
        raise MachineCreationError("Vultr, got exception %s" % e, e)

    return node


def _create_machine_azure_arm(owner, cloud_id, conn, public_key, machine_name,
                              image, size, location, networks,
                              storage_account, machine_password,
                              resource_group, machine_username, volumes,
                              storage_account_type, cloud_init):
    """Create a machine Azure ARM.

    Here there is no checking done, all parameters are expected to be
    sanitized by create_machine.

    """
    if public_key:
        public_key = public_key.replace('\n', '')

    if 'microsoft' in image.name.lower():
        k = NodeAuthPassword(machine_password)
    else:
        k = NodeAuthSSHKey(public_key)

    resource_groups = conn.ex_list_resource_groups()
    ex_resource_group = None
    for lib_resource_group in resource_groups:
        if lib_resource_group.id == resource_group:
            ex_resource_group = lib_resource_group.name
            break

    if ex_resource_group is None:
        try:
            conn.ex_create_resource_group(resource_group, location)
            ex_resource_group = resource_group
            # add delay cause sometimes the group is not yet ready
            time.sleep(5)
        except Exception as exc:
            raise InternalServerError("Couldn't create resource group. \
                %s" % exc)

    storage_accounts = conn.ex_list_storage_accounts()
    ex_storage_account = None
    for lib_storage_account in storage_accounts:
        if lib_storage_account.id == storage_account:
            ex_storage_account = lib_resource_group.name
            break

    if ex_storage_account is None:
        try:
            conn.ex_create_storage_account(storage_account,
                                           ex_resource_group,
                                           'Storage', location)
            ex_storage_account = storage_account
            # w8 for storage account state to become succedeed
            timeout = time.time() + 30
            st_account_ready = False
            while time.time() < timeout and not st_account_ready:
                st_accounts = conn.ex_list_storage_accounts()
                for st_account in st_accounts:
                    state = st_account.extra.get('provisioningState')
                    if st_account.name == ex_storage_account and \
                       state == 'Succeeded':
                        st_account_ready = True
                        break
        except Exception as exc:
            raise InternalServerError("Couldn't create storage account. \
                %s" % exc)
    if not isinstance(networks, list):
        networks = [networks]
    network = networks[0]
    if network.get('id'):
        try:
            mist_net = Network.objects.get(id=network.get('id'))
        except me.DoesNotExist:
            raise NetworkNotFoundError()

        libcloud_networks = conn.ex_list_networks()
        ex_network = None
        for libcloud_net in libcloud_networks:
            if mist_net.network_id == libcloud_net.id:
                ex_network = libcloud_net
                break
    elif network.get('name'):   # create network

        # create a security group and open ports
        securityRules = [
            {
                "name": "allowSSHInbound",
                "properties": {
                    "protocol": "*",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "destinationPortRange": "22",
                    "sourcePortRange": "*",
                    "priority": 200,
                    "direction": "Inbound"
                }
            },
            {
                "name": "allowRDPInbound",
                "properties": {
                    "protocol": "*",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "destinationPortRange": "3389",
                    "sourcePortRange": "*",
                    "priority": 201,
                    "direction": "Inbound"
                }
            },
            {
                "name": "allowMonitoringOutbound",
                "properties": {
                    "protocol": "*",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "destinationPortRange": "25826",
                    "sourcePortRange": "*",
                    "priority": 202,
                    "direction": "Outbound"
                }
            }
        ]
        try:
            sg = conn.ex_create_network_security_group(
                network.get('name'),
                ex_resource_group,
                location=location,
                securityRules=securityRules
            )
            # add delay cause sometimes the group is not yet ready
            time.sleep(3)
        except Exception as exc:
            raise InternalServerError("Couldn't create security group \
                %s" % exc)

        # create the new network
        try:
            ex_network = conn.ex_create_network(network.get('name'),
                                                ex_resource_group,
                                                location=location,
                                                networkSecurityGroup=sg.id)
        except Exception as exc:
            raise InternalServerError("Couldn't create new network", exc)

    ex_subnet = conn.ex_list_subnets(ex_network)[0]

    try:
        ex_ip = conn.ex_create_public_ip(machine_name,
                                         ex_resource_group,
                                         location)
    except Exception as exc:
        raise InternalServerError("Couldn't create new ip", exc)

    try:
        ex_nic = conn.ex_create_network_interface(machine_name, ex_subnet,
                                                  ex_resource_group,
                                                  location=location,
                                                  public_ip=ex_ip)
    except Exception as exc:
        raise InternalServerError("Couldn't create network interface", exc)

    data_disks = []
    for volume in volumes:
        if volume.get('volume_id'):  # existing volume
            from mist.api.volumes.models import Volume
            try:
                mist_vol = Volume.objects.get(id=volume.get('volume_id'))
            except me.DoesNotExist:
                # should we throw the exception?
                raise VolumeNotFoundError()
            data_disks.append({'id': mist_vol.external_id})

        else:  # new volume
            data_disks.append(volume)

    try:
        node = conn.create_node(
            name=machine_name,
            size=size,
            image=image,
            auth=k,
            ex_resource_group=ex_resource_group,
            ex_storage_account=ex_storage_account,
            ex_nic=ex_nic,
            location=location,
            ex_user_name=machine_username,
            ex_use_managed_disks=True,
            ex_data_disks=data_disks,
            ex_storage_account_type=storage_account_type,
            ex_customdata=cloud_init
        )
    except Exception as e:
        try:
            # try to get the message only out of the XML response
            msg = re.search(r"(<Message>)(.*?)(</Message>)", e.value)
            if not msg:
                msg = re.search(r"(Message: ')(.*?)(', Body)", e.value)
            if msg:
                msg = msg.group(2)
        except:
            msg = e
        raise MachineCreationError('Azure, got exception %s' % msg)

    return node


def _create_machine_azure(conn, key_name, private_key, public_key,
                          machine_name, image, size, location, cloud_init,
                          cloud_service_name, azure_port_bindings):
    """Create a machine Azure.

    Here there is no checking done, all parameters are expected to be
    sanitized by create_machine.

    """
    public_key.replace('\n', '')

    port_bindings = []
    if azure_port_bindings and type(azure_port_bindings) in [str, str]:
        # we receive something like: http tcp 80:80, smtp tcp 25:25,
        # https tcp 443:443
        # and transform it to [{'name':'http', 'protocol': 'tcp',
        # 'local_port': 80, 'port': 80},
        # {'name':'smtp', 'protocol': 'tcp', 'local_port': 25, 'port': 25}]

        for port_binding in azure_port_bindings.split(','):
            try:
                port_dict = port_binding.split()
                port_name = port_dict[0]
                protocol = port_dict[1]
                ports = port_dict[2]
                local_port = ports.split(':')[0]
                port = ports.split(':')[1]
                binding = {'name': port_name, 'protocol': protocol,
                           'local_port': local_port, 'port': port}
                port_bindings.append(binding)
            except:
                pass

    try:
        node = conn.create_node(
            name=machine_name,
            size=size,
            image=image,
            location=location,
            ex_cloud_service_name=cloud_service_name,
            endpoint_ports=port_bindings,
            custom_data=base64.b64encode(cloud_init)
        )
    except Exception as e:
        try:
            # try to get the message only out of the XML response
            msg = re.search(r"(<Message>)(.*?)(</Message>)", e.value)
            if not msg:
                msg = re.search(r"(Message: ')(.*?)(', Body)", e.value)
            if msg:
                msg = msg.group(2)
        except:
            msg = e
        raise MachineCreationError('Azure, got exception %s' % msg)

    return node


def _create_machine_vcloud(conn, machine_name, image,
                           size, public_key, networks):
    """Create a machine vCloud.

    Here there is no checking done, all parameters are expected to be
    sanitized by create_machine.

    """
    key = public_key.replace('\n', '')
    # we have the option to pass a guest customisation
    # script as ex_vm_script. We'll pass
    # the ssh key there

    deploy_script = NamedTemporaryFile(delete=False)
    deploy_script.write(
        'mkdir -p ~/.ssh && echo "%s" >> ~/.ssh/authorized_keys '
        '&& chmod -R 700 ~/.ssh/' % key)
    deploy_script.close()

    # select the right network object
    ex_network = None
    try:
        if networks:
            network = networks[0]
            available_networks = conn.ex_list_networks()
            available_networks_ids = [net.id for net in available_networks]
            if network in available_networks_ids:
                ex_network = network
    except:
        pass

    try:
        node = conn.create_node(
            name=machine_name,
            image=image,
            size=size,
            ex_vm_script=deploy_script.name,
            ex_vm_network=ex_network,
            ex_vm_fence='bridged',
            ex_vm_ipmode='DHCP'
        )
    except Exception as e:
        raise MachineCreationError("vCloud, got exception %s" % e, e)

    return node


def _create_machine_vsphere(conn, machine_name, image,
                            size, location, network, folder,
                            datastore):
    """Create a machine in vSphere.

    """
    # get location as object from database
    try:
        from mist.api.networks.models import VSphereNetwork
        network = VSphereNetwork.objects.get(id=network)
    except me.DoesNotExist:
        network = None
    if network:
        network.id = network.network_id
    try:
        node = conn.create_node(
            name=machine_name,
            image=image,
            size=size,
            location=location,
            ex_network=network,
            ex_folder=folder,
            ex_datastore=datastore
        )
    except Exception as e:
        raise MachineCreationError("vSphere, got exception %s" % e, e)

    return node


def _create_machine_gce(conn, key_name, private_key, public_key, machine_name,
                        image, size, location, network, subnetwork, volumes,
                        cloud_init):
    """Create a machine in GCE.

    Here there is no checking done, all parameters are expected to be
    sanitized by create_machine.

    """
    key = public_key.replace('\n', '')

    metadata = {  # 'startup-script': script,
        'sshKeys': 'user:%s' % key}
    # metadata for ssh user, ssh key and script to deploy
    if cloud_init:
        metadata['startup-script'] = cloud_init

    try:
        network = Network.objects.get(id=network).name
    except me.DoesNotExist:
        network = 'default'

    ex_disk = None
    disk_size = 10
    if volumes:
        if volumes[0].get('volume_id'):
            from mist.api.volumes.models import Volume
            volume_id = volumes[0]['volume_id']
            volume = Volume.objects.get(id=volume_id)
            ex_disk_id = volume.external_id

            # try to find disk using libcloud's id
            libcloud_disks = conn.list_volumes()
            for libcloud_disk in libcloud_disks:
                if libcloud_disk.id == ex_disk_id:
                    ex_disk = libcloud_disk
                    break

        else:
            disk_size = volumes[0].get('size')

    try:
        node = conn.create_node(
            name=machine_name,
            image=image,
            size=size,
            location=location,
            ex_metadata=metadata,
            ex_network=network,
            ex_subnetwork=subnetwork,
            ex_boot_disk=ex_disk,
            disk_size=disk_size
        )
    except Exception as e:
        raise MachineCreationError(
            "Google Compute Engine, got exception %s" % e, e)

    return node


def _create_machine_linode(conn, key_name, private_key, public_key,
                           machine_name, image, size, location):
    """Create a machine in Linode.

    Here there is no checking done, all parameters are expected to be
    sanitized by create_machine.

    """

    auth = NodeAuthSSHKey(public_key)

    with get_temp_file(private_key) as tmp_key_path:
        try:
            node = conn.create_node(
                name=machine_name,
                image=image,
                size=size,
                location=location,
                auth=auth,
                ssh_key=tmp_key_path,
                ex_private=True
            )
        except Exception as e:
            raise MachineCreationError("Linode, got exception %s" % e, e)
    return node


def destroy_machine(user, cloud_id, machine_id):
    """Destroys a machine on a certain cloud.

    After destroying a machine it also deletes all key associations. However,
    it doesn't undeploy the key. There is no need to do it because the
    machine will be destroyed.
    """
    log.info('Destroying machine %s in cloud %s' % (machine_id, cloud_id))

    machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)

    if not machine.monitoring.hasmonitoring:
        machine.ctl.destroy()
        return

    # if machine has monitoring, disable it. the way we disable depends on
    # whether this is a standalone io installation or not
    try:
        disable_monitoring(user, cloud_id, machine_id, no_ssh=True)
    except Exception as exc:
        log.warning("Didn't manage to disable monitoring, maybe the "
                    "machine never had monitoring enabled. Error: %r", exc)

    machine.ctl.destroy()


# SEC
def filter_machine_ids(auth_context, cloud_id, machine_ids):

    if not isinstance(machine_ids, set):
        machine_ids = set(machine_ids)

    if auth_context.is_owner():
        return machine_ids

    # NOTE: We can trust the RBAC Mappings in order to fetch the latest list of
    # machines for the current user, since mongo has been updated by either the
    # Poller or the above `list_machines`.

    try:
        auth_context.check_perm('cloud', 'read', cloud_id)
    except PolicyUnauthorizedError:
        return set()

    allowed_ids = set(auth_context.get_allowed_resources(rtype='machines'))
    return machine_ids & allowed_ids


# SEC
def filter_list_machines(auth_context, cloud_id, machines=None, perm='read',
                         cached=False):
    """Returns a list of machines.

    In case of non-Owners, the QuerySet only includes machines found in the
    RBAC Mappings of the Teams the current user is a member of.
    """
    assert cloud_id

    if machines is None:
        machines = list_machines(auth_context.owner, cloud_id, cached=cached)
    if not machines:  # Exit early in case the cloud provider returned 0 nodes.
        return []
    if auth_context.is_owner():
        return machines

    machine_ids = set(machine['id'] for machine in machines)
    allowed_machine_ids = filter_machine_ids(auth_context, cloud_id,
                                             machine_ids)
    return [machine for machine in machines
            if machine['id'] in allowed_machine_ids]


def run_pre_action_hooks(machine, action, user):
    # Look for configured post action hooks for this cloud
    cloud_id = machine.cloud.id
    cloud_pre_action_hooks = config.PRE_ACTION_HOOKS and \
        config.PRE_ACTION_HOOKS.get('cloud', {}).get(cloud_id, {}).get(
            action, [])
    return run_action_hooks(cloud_pre_action_hooks, machine, user)


def run_post_action_hooks(machine, action, user, result):
    # Look for configured post action hooks for this cloud
    cloud_id = machine.cloud.id
    cloud_post_action_hooks = config.POST_ACTION_HOOKS and \
        config.POST_ACTION_HOOKS.get('cloud', {}).get(cloud_id, {}).get(
            action, [])
    return run_action_hooks(cloud_post_action_hooks, machine, user)


def run_action_hooks(action_hooks, machine, user):
    cloud_id = machine.cloud.id
    for hook in action_hooks:
        hook_type = hook.get('type') or 'webhook'
        if hook_type == 'webhook':
            url = hook.get('url').replace(
                '{cloud_id}', cloud_id).replace(
                    '{machine_id}', machine.machine_id).replace(
                        '{machine_name}', machine.name).replace(
                            '{user_email}', user.email)
            payload = hook.get('payload')
            for k in payload:
                payload[k] = payload[k].replace(
                    '{cloud_id}', cloud_id).replace(
                        '{machine_id}', machine.machine_id).replace(
                            '{machine_name}', machine.name).replace(
                                '{user_email}', user.email)
            ret = requests.request(
                hook.get('method'), url,
                data=payload,
                headers=hook.get('headers'))
            if ret.status_code >= 300:
                msg = 'Webhook for cloud %s failed with response %s %s' % (
                    cloud_id, ret.status_code, ret.text)
                log.error(msg)
                notify_admin(msg, team='dev')
            if hook.get('stop_propagation'):
                return False
        elif hook_type == 'set_tags_azure_arm':
            try:
                machine.cloud.ctl.compute.connection.ex_create_tags(
                    machine.extra['id'].encode(), tags=hook.get('tags', {}),
                    replace=hook.get('replace'))
            except Exception as e:
                msg = 'Post action hook set_tags_azure_arm for cloud %s'\
                      ' failed: %r' % (cloud_id, e)
                log.error(msg)
                notify_admin(msg, team='dev')
        else:
            log.error('Unknown hook type `%s`' % hook_type)
    return True


def machine_safe_expire(owner_id, machine):
    # untag machine
    owner = Owner.objects.get(id=owner_id)  # FIXME: try-except
    existing_tags = get_tags_for_resource(owner, machine)
    if existing_tags:
        remove_tags_from_resource(owner, machine, existing_tags)
    # unown machine
    machine.owned_by = None

    # create new schedule that will destroy the machine
    # in SAFE_EXPIRATION_DURATION secs
    for team in owner.teams:
        if team.name == 'Owners':
            user = team.members[0]
            org = Organization.objects.get(teams=team)
            break
    auth_token = AuthToken(user_id=user.id, org=org)
    auth_context = auth_context_from_auth_token(auth_token)

    _delta = datetime.timedelta(0, config.SAFE_EXPIRATION_DURATION)
    schedule_entry = datetime.datetime.utcnow() + _delta
    schedule_entry = schedule_entry.strftime('%Y-%m-%d %H:%M:%S')

    params = {
        'schedule_type': 'one_off',
        'description': 'Safe expiration schedule',
        'schedule_entry': schedule_entry,
        'action': 'destroy',
        'conditions': [{'type': 'machines', 'ids': [machine.id]}],
        'task_enabled': True,
    }
    _name = machine.name + '-safe-expiration-' + \
        str(randrange(1000))
    from mist.api.schedules.models import Schedule
    machine.expiration = Schedule.add(auth_context, _name,
                                      **params)
    machine.save()
