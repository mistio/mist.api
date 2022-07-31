"""Cloud Main Controllers

Main controllers implement common cloud operations, such as add, update,
disable, that mainly affect mist, instead of interacting with the remote cloud
itself. These operations are mostly the same for all different clouds.

A cloud controller is initialized given a cloud. Most of the time it will be
accessed through a cloud model, using the `ctl` abbreviation, like this:

    cloud = mist.api.clouds.models.Cloud.objects.get(id=cloud_id)
    cloud.ctl.enable()

The main controller also acts as a gateway to specific controllers. For
example, one may do

    print cloud.ctl.compute.list_machines()

See `mist.api.clouds.controllers.main.base` for more information.

"""


import datetime
import uuid
import json
import socket
import logging

import mongoengine as me

from libcloud.utils.networking import is_private_subnet

from libcloud.compute.base import NodeState

from mist.api.exceptions import MistError
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import CloudExistsError
from mist.api.exceptions import CloudUnauthorizedError
from mist.api.exceptions import ServiceUnavailableError
from mist.api.exceptions import MachineUnauthorizedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.helpers import sanitize_host, check_host
from mist.api.helpers import amqp_owner_listening

from mist.api.keys.models import Key

from mist.api.helpers import rename_kwargs
from mist.api.clouds.controllers.main.base import BaseMainController
from mist.api.clouds.controllers.compute import controllers as compute_ctls
from mist.api.clouds.controllers.container import controllers as container_ctls
from mist.api.clouds.controllers.network import controllers as network_ctls
from mist.api.clouds.controllers.dns import controllers as dns_ctls
from mist.api.clouds.controllers.storage import controllers as storage_ctls
from mist.api.clouds.controllers.objectstorage import controllers as objectstorage_ctls  # noqa: E501

from mist.api import config

if config.HAS_VPN:
    from mist.vpn.methods import to_tunnel
else:
    from mist.api.dummy.methods import to_tunnel

log = logging.getLogger(__name__)


class AmazonMainController(BaseMainController):

    provider = 'ec2'
    ComputeController = compute_ctls.AmazonComputeController
    NetworkController = network_ctls.AmazonNetworkController
    DnsController = dns_ctls.AmazonDNSController
    StorageController = storage_ctls.AmazonStorageController
    ObjectStorageController = objectstorage_ctls.AmazonS3ObjectStorageController  # noqa: E501
    ContainerController = container_ctls.AmazonContainerController

    def _add__preparse_kwargs(self, kwargs):
        # Autofill apisecret from other Amazon Cloud.
        apikey = kwargs.get('apikey')
        apisecret = kwargs.get('apisecret')
        if apikey and apisecret == 'getsecretfromdb':
            amazon_clouds = type(self.cloud).objects(owner=self.cloud.owner,
                                                     deleted=None)
            if amazon_clouds:
                for amazon_cloud in amazon_clouds:
                    if amazon_cloud.apikey == apikey:
                        kwargs['apisecret'] = amazon_cloud.apisecret.value
                        break


class AlibabaMainController(AmazonMainController):

    provider = 'aliyun_ecs'
    ComputeController = compute_ctls.AlibabaComputeController
    StorageController = storage_ctls.AlibabaStorageController
    NetworkController = network_ctls.AlibabaNetworkController
    DnsController = None
    ObjectStorageController = None
    ContainerController = None


class DigitalOceanMainController(BaseMainController):

    provider = 'digitalocean'
    ComputeController = compute_ctls.DigitalOceanComputeController
    DnsController = dns_ctls.DigitalOceanDNSController
    StorageController = storage_ctls.DigitalOceanStorageController


class MaxihostMainController(BaseMainController):

    provider = 'maxihost'
    ComputeController = compute_ctls.MaxihostComputeController


class LinodeMainController(BaseMainController):

    provider = 'linode'
    ComputeController = compute_ctls.LinodeComputeController
    DnsController = dns_ctls.LinodeDNSController
    StorageController = storage_ctls.LinodeStorageController

    def _update__preparse_kwargs(self, kwargs):
        apikey = kwargs.get('apikey')
        if apikey is not None:
            # Update API Version to 4
            kwargs['apiversion'] = None


class OnAppMainController(BaseMainController):
    provider = 'onapp'
    ComputeController = compute_ctls.OnAppComputeController


class RackSpaceMainController(BaseMainController):

    provider = 'rackspace'
    ComputeController = compute_ctls.RackSpaceComputeController
    DnsController = dns_ctls.RackSpaceDNSController

    def _add__preparse_kwargs(self, kwargs):
        username = kwargs.get('username')
        apikey = kwargs.get('apikey')
        if apikey == 'getsecretfromdb':
            cloud = type(self.cloud).objects(owner=self.cloud.owner,
                                             username=username,
                                             deleted=None).first()
            if cloud is not None:
                kwargs['apikey'] = cloud.apikey.value


class SoftLayerMainController(BaseMainController):

    provider = 'softlayer'
    ComputeController = compute_ctls.SoftLayerComputeController
    DnsController = dns_ctls.SoftLayerDNSController


class AzureMainController(BaseMainController):

    provider = 'azure'
    ComputeController = compute_ctls.AzureComputeController
    StorageController = storage_ctls.AzureStorageController


class AzureArmMainController(BaseMainController):

    provider = 'azure_arm'
    ComputeController = compute_ctls.AzureArmComputeController
    NetworkController = network_ctls.AzureArmNetworkController
    StorageController = storage_ctls.AzureArmStorageController


class GoogleMainController(BaseMainController):

    provider = 'gce'
    ComputeController = compute_ctls.GoogleComputeController
    NetworkController = network_ctls.GoogleNetworkController
    DnsController = dns_ctls.GoogleDNSController
    StorageController = storage_ctls.GoogleStorageController
    ContainerController = container_ctls.GoogleContainerController

    def _update__preparse_kwargs(self, kwargs):
        private_key = kwargs.get('private_key', self.cloud.private_key)
        email = kwargs.get('email', self.cloud.email)
        if not email:
            # Support both ways to authenticate a service account,
            # by either using a project id and json key file (highly
            # recommended) and also by specifying email, project id and private
            # key file.
            try:
                creds = json.loads(private_key)
                kwargs['email'] = creds['client_email']
                kwargs['private_key'] = creds['private_key']
            except:
                raise MistError("Specify both 'email' and 'private_key' "
                                "params, or 'private_key' as a json file.")


class HostVirtualMainController(BaseMainController):

    provider = 'hostvirtual'
    ComputeController = compute_ctls.HostVirtualComputeController


class EquinixMetalMainController(BaseMainController):

    provider = 'equinixmetal'
    ComputeController = compute_ctls.EquinixMetalComputeController


class VultrMainController(BaseMainController):

    provider = 'vultr'
    ComputeController = compute_ctls.VultrComputeController
    DnsController = dns_ctls.VultrDNSController
    StorageController = storage_ctls.VultStorageController
    NetworkController = network_ctls.VultrNetworkController


class VSphereMainController(BaseMainController):

    provider = 'vsphere'
    ComputeController = compute_ctls.VSphereComputeController
    NetworkController = network_ctls.VSphereNetworkController

    def _update__preparse_kwargs(self, kwargs):
        host = kwargs.get('host', self.cloud.host)
        if host:
            kwargs['host'] = sanitize_host(host)
            check_host(kwargs['host'])


class OpenStackMainController(BaseMainController):

    provider = 'openstack'
    ComputeController = compute_ctls.OpenStackComputeController
    NetworkController = network_ctls.OpenStackNetworkController
    StorageController = storage_ctls.OpenstackStorageController
    ObjectStorageController = objectstorage_ctls.OpenstackObjectStorageController   # noqa: E501

    def _update__preparse_kwargs(self, kwargs):
        rename_kwargs(kwargs, 'auth_url', 'url')
        rename_kwargs(kwargs, 'tenant_name', 'tenant')
        rename_kwargs(kwargs, 'domain_name', 'domain')
        url = kwargs.get('url', self.cloud.url)
        if url:
            if url.endswith('/v2.0/'):
                url = url.split('/v2.0/')[0]
            elif url.endswith('/v2.0'):
                url = url.split('/v2.0')[0]
            kwargs['url'] = url.rstrip('/')
            check_host(sanitize_host(kwargs['url']))


class VexxhostMainController(OpenStackMainController):
    provider = 'vexxhost'
    ComputeController = compute_ctls.VexxhostComputeController
    NetworkController = network_ctls.VexxhostNetworkController
    StorageController = storage_ctls.VexxhostStorageController
    ObjectStorageController = objectstorage_ctls.VexxhostObjectStorageController   # noqa: E501


class DockerMainController(BaseMainController):

    provider = 'docker'
    ComputeController = compute_ctls.DockerComputeController

    def _update__preparse_kwargs(self, kwargs):
        kwargs.pop('authentication', None)
        rename_kwargs(kwargs, 'docker_port', 'port')
        rename_kwargs(kwargs, 'docker_host', 'host')
        rename_kwargs(kwargs, 'auth_user', 'username')
        rename_kwargs(kwargs, 'auth_password', 'password')
        host = kwargs.get('host', self.cloud.host)
        if host:
            host = sanitize_host(host)
            check_host(host)


class LXDMainController(BaseMainController):
    """
    Main controller class for LXC containers
    """

    provider = 'lxd'
    ComputeController = compute_ctls.LXDComputeController
    StorageController = storage_ctls.LXDStorageController
    NetworkController = network_ctls.LXDNetworkController

    def _update__preparse_kwargs(self, kwargs):
        host = kwargs.get('host', self.cloud.host)
        if host:
            host = sanitize_host(host)
            check_host(host)


class LibvirtMainController(BaseMainController):

    provider = 'libvirt'
    ComputeController = compute_ctls.LibvirtComputeController
    NetworkController = network_ctls.LibvirtNetworkController

    def _add__preparse_kwargs(self, kwargs):
        rename_kwargs(kwargs, 'machine_hostname', 'host')
        rename_kwargs(kwargs, 'machine_name', 'alias')
        rename_kwargs(kwargs, 'machine_user', 'username')
        rename_kwargs(kwargs, 'machine_key', 'key')
        rename_kwargs(kwargs, 'ssh_port', 'port')
        if kwargs.get('host'):
            kwargs['host'] = sanitize_host(kwargs['host'])
            check_host(kwargs['host'])
        if kwargs.get('key'):
            try:
                kwargs['key'] = Key.objects.get(owner=self.cloud.owner,
                                                id=kwargs['key'],
                                                deleted=None)
            except Key.DoesNotExist:
                raise NotFoundError("Key does not exist.")

    # TODO: fail_on_error True or False by default?
    def add(self, fail_on_error=True, fail_on_invalid_params=False, **kwargs):
        self.cloud.hosts = []
        from mist.api.machines.models import Machine
        if not kwargs.get('hosts'):
            raise RequiredParameterMissingError('hosts')
        try:
            self.cloud.save()
        except me.ValidationError as exc:
            raise BadRequestError({'msg': str(exc),
                                   'errors': exc.to_dict()})
        except me.NotUniqueError:
            raise CloudExistsError("Cloud with name %s already exists"
                                   % self.cloud.name)
        total_errors = {}

        for _host in kwargs['hosts']:
            self._add__preparse_kwargs(_host)
            errors = {}
            for key in list(_host.keys()):
                if key not in ('host', 'alias', 'username', 'port', 'key',
                               'images_location'):
                    error = "Invalid parameter %s=%r." % (key, _host[key])
                    if fail_on_invalid_params:
                        self.cloud.delete()
                        raise BadRequestError(error)
                    else:
                        log.warning(error)
                        _host.pop(key)

            for key in ('host', 'key'):
                if key not in _host or not _host.get(key):
                    error = "Required parameter missing: %s" % key
                    errors[key] = error
                    if fail_on_error:
                        self.cloud.delete()
                        raise RequiredParameterMissingError(key)
                    else:
                        log.warning(error)
                        total_errors.update({key: error})

            if not errors:
                try:
                    ssh_port = int(_host.get('port', 22))
                except (ValueError, TypeError):
                    ssh_port = 22

                images_location = _host.get('images_location',
                                            '/var/lib/libvirt/images')
                extra = {
                    'images_location': images_location,
                    'tags': {'type': 'hypervisor'},
                    'username': _host.get('username')
                }
                # Create and save machine entry to database.
                machine = Machine(
                    cloud=self.cloud,
                    external_id=_host.get('host').replace('.', '-'),
                    name=_host.get('alias') or _host.get('host'),
                    ssh_port=ssh_port,
                    last_seen=datetime.datetime.utcnow(),
                    hostname=_host.get('host'),
                    state=NodeState.RUNNING.value,
                    machine_type='hypervisor',
                    extra=extra
                )
                # Sanitize inputs.
                host = sanitize_host(_host.get('host'))
                check_host(_host.get('host'))
                machine.hostname = host

                if is_private_subnet(socket.gethostbyname(_host.get('host'))):
                    machine.private_ips = [_host.get('host')]
                else:
                    machine.public_ips = [_host.get('host')]

                try:
                    machine.save(write_concern={'w': 1, 'fsync': True})
                    self.cloud.hosts.append(machine.id)
                except me.NotUniqueError:
                    error = 'Duplicate machine entry. Maybe the same \
                            host has been added twice?'
                    if fail_on_error:
                        self.cloud.delete()
                        raise MistError(error)
                    else:
                        total_errors.update({_host.get('host'): error})
                        continue

                # associate key and attempt to connect
                try:
                    machine.ctl.associate_key(_host.get('key'),
                                              username=_host.get('username'),
                                              port=ssh_port)
                except MachineUnauthorizedError as exc:
                    log.error("Could not connect to host %s."
                              % _host.get('host'))
                    machine.delete()
                    if fail_on_error:
                        self.cloud.delete()
                        raise CloudUnauthorizedError(exc)
                except ServiceUnavailableError as exc:
                    log.error("Could not connect to host %s."
                              % _host.get('host'))
                    machine.delete()
                    if fail_on_error:
                        self.cloud.delete()
                        raise MistError("Couldn't connect to host '%s'."
                                        % _host.get('host'))

        # check if host was added successfully
        # if not, delete the cloud and raise
        if Machine.objects(cloud=self.cloud):
            if amqp_owner_listening(self.cloud.owner.id):
                old_machines = [m.as_dict() for m in
                                self.cloud.ctl.compute.list_cached_machines()]
                new_machines = self.cloud.ctl.compute.list_machines()
                self.cloud.ctl.compute.produce_and_publish_patch(
                    old_machines, new_machines)

            self.cloud.errors = total_errors

        else:
            self.cloud.delete()
            raise BadRequestError(total_errors)

        self.add_polling_schedules()

    def update(self, fail_on_error=True, fail_on_invalid_params=True,
               add=False, **kwargs):
        # FIXME: Add update support, need to clean up kvm 'host' from libcloud,
        # and especially stop using cloud.host as the machine id ffs.
        if not add:
            raise BadRequestError("Update action is not currently supported "
                                  "for Libvirt/KVM clouds.")
        super(LibvirtMainController, self).update(
            fail_on_error=fail_on_error,
            fail_on_invalid_params=fail_on_invalid_params,
            **kwargs
        )

    def add_machine(self, host, ssh_user='root', ssh_port=22, ssh_key=None,
                    **kwargs):
        try:
            ssh_port = int(ssh_port)
        except (ValueError, TypeError):
            ssh_port = 22

        if not ssh_key:
            raise RequiredParameterMissingError('machine_key')

        try:
            ssh_key = Key.objects.get(owner=self.cloud.owner, id=ssh_key,
                                      deleted=None)
        except Key.DoesNotExist:
            raise NotFoundError("Key does not exist.")

        images_location = kwargs.get('images_location',
                                     '/var/lib/libvirt/images')
        extra = {
            'images_location': images_location,
            'tags': {'type': 'hypervisor'},
            'username': ssh_user
        }
        old_machines = [m.as_dict() for m in
                        self.cloud.ctl.compute.list_cached_machines()]
        from mist.api.machines.models import Machine
        # Create and save machine entry to database.
        # first check if the host has already been added to the cloud
        try:
            machine = Machine.objects.get(cloud=self.cloud,
                                          external_id=host.replace('.', '-'))
            machine.name = kwargs.get('name') or host
            machine.ssh_port = ssh_port
            machine.extra = extra
            machine.last_seen = datetime.datetime.utcnow()
            machine.missing_since = None
        except me.DoesNotExist:
            machine = Machine(
                cloud=self.cloud,
                name=kwargs.get('name') or host,
                hostname=host,
                external_id=host.replace('.', '-'),
                ssh_port=ssh_port,
                extra=extra,
                state=NodeState.RUNNING.value,
                last_seen=datetime.datetime.utcnow(),
            )

        # Sanitize inputs.
        host = sanitize_host(host)
        check_host(host)
        machine.hostname = host

        if is_private_subnet(socket.gethostbyname(host)):
            machine.private_ips = [host]
        else:
            machine.public_ips = [host]

        machine.save(write_concern={'w': 1, 'fsync': True})

        # associate key and attempt to connect
        try:
            machine.ctl.associate_key(ssh_key,
                                      username=ssh_user,
                                      port=ssh_port)
        except MachineUnauthorizedError as exc:
            log.error("Could not connect to host %s."
                      % host)
            machine.delete()
            raise CloudUnauthorizedError(exc)
        except ServiceUnavailableError as exc:
            log.error("Could not connect to host %s."
                      % host)
            machine.delete()
            raise MistError("Couldn't connect to host '%s'."
                            % host)
        self.cloud.hosts.append(machine.id)
        self.cloud.save()

        # Update RBAC Mappings given the list of nodes seen for the first time.
        new_machines = self.cloud.ctl.compute.list_cached_machines()
        if new_machines:
            self.cloud.owner.mapper.update(new_machines, asynchronous=False)

        if amqp_owner_listening(self.cloud.owner.id):
            self.cloud.ctl.compute.produce_and_publish_patch(
                old_machines, new_machines)

        from mist.api.poller.models import ListMachinesPollingSchedule
        try:
            schedule = ListMachinesPollingSchedule.objects.get(
                cloud=self.cloud)
        except ListMachinesPollingSchedule.DoesNotExist:
            log.error(
                "List Machines Polling Schedule does not exist for cloud %s",
                self.cloud)
        else:
            schedule.run_immediately = True
            schedule.add_interval(10, ttl=180)
            schedule.save()

        return machine

    def enable(self):
        from mist.api.machines.models import Machine
        for id in self.cloud.hosts:
            host_machine = Machine.objects.get(id=id)
            host_machine.missing_since = None
            host_machine.save()
        super(LibvirtMainController, self).enable()


class OtherMainController(BaseMainController):

    provider = 'other'
    ComputeController = compute_ctls.OtherComputeController

    def disable(self):
        """ For OtherServer clouds we do not want to set the missing_since
        on the cloud machines when we disable the cloud because we are using
        the missing_since field to remove them.

        Setting the cloud enabled field to False is enough to not return
        them during listing machine actions because we are not using
        the cloud on listings.
        """
        self.cloud.enabled = False
        self.cloud.save()

    # FIXME: make sure that errors are properly shown to the user
    # FIXME: make sure that cloud is not added in the db if no
    # host is successfully added ffs
    def add(self, fail_on_error=True, fail_on_invalid_params=True, **kwargs):
        """Add new Cloud to the database

        This is the only cloud controller subclass that overrides the `add`
        method of `BaseMainController`.

        This is only expected to be called by `Cloud.add` classmethod to create
        a cloud. Fields `owner` and `name` are already populated in
        `self.cloud`. The `self.cloud` model is not yet saved.

        If appropriate kwargs are passed, this can currently also act as a
        shortcut to also add machines on this cloud.

        """
        # Attempt to save.
        try:
            self.cloud.save()
        except me.ValidationError as exc:
            raise BadRequestError({'msg': str(exc),
                                   'errors': exc.to_dict()})
        except me.NotUniqueError:
            raise CloudExistsError("Cloud with name %s already exists"
                                   % self.cloud.name)

        if kwargs:
            errors = []
            if 'machines' in kwargs:  # new api: list of multiple machines
                for machine_kwargs in kwargs['machines']:
                    machine_name = machine_kwargs.pop('machine_name', '')
                    try:
                        self.add_machine_wrapper(
                            machine_name, fail_on_error=fail_on_error,
                            fail_on_invalid_params=fail_on_invalid_params,
                            **machine_kwargs
                        )
                    except Exception as exc:
                        errors.append(str(exc))
            else:  # old api, single machine
                try:
                    self.add_machine_wrapper(
                        self.cloud.name, fail_on_error=fail_on_error,
                        fail_on_invalid_params=fail_on_invalid_params, **kwargs
                    )
                except Exception as exc:
                    errors.append(str(exc))
                    if fail_on_error:
                        self.cloud.delete()
                    raise
        self.cloud.save()
        self.cloud.errors = errors  # just an attribute, not a field

    def update(self, fail_on_error=True, fail_on_invalid_params=True,
               **kwargs):
        raise BadRequestError("OtherServer clouds don't support `update`. "
                              "Only name can be changed, using `rename`. "
                              "To change machine details, one must edit the "
                              "machines themselves, not the cloud.")

    def add_machine_wrapper(self, name, fail_on_error=True,
                            fail_on_invalid_params=True, monitoring=False,
                            **kwargs):
        """Wrapper around add_machine for kwargs backwards compatibility

        FIXME: This wrapper should be deprecated

        """

        # Sanitize params.
        rename_kwargs(kwargs, 'machine_hostname', 'host')
        rename_kwargs(kwargs, 'machine_user', 'ssh_user')
        rename_kwargs(kwargs, 'machine_key', 'ssh_key')
        rename_kwargs(kwargs, 'machine_port', 'ssh_port')
        rename_kwargs(kwargs, 'remote_desktop_port', 'rdp_port')
        if kwargs.get('operating_system') == 'windows':
            kwargs['os_type'] = 'windows'
        else:
            kwargs['os_type'] = 'unix'
        kwargs.pop('operating_system', None)
        errors = {}
        for key in list(kwargs.keys()):
            if key not in ('host', 'ssh_user', 'ssh_port', 'ssh_key',
                           'os_type', 'rdp_port'):
                error = "Invalid parameter %s=%r." % (key, kwargs[key])
                if fail_on_invalid_params:
                    errors[key] = error
                else:
                    log.warning(error)
                    kwargs.pop(key)
        if 'host' not in kwargs:
            errors['host'] = "Required parameter host missing"
            log.error(errors['host'])

        if not name:
            name = kwargs['host']

        if errors:
            log.error("Invalid parameters %s." % list(errors.keys()))
            raise BadRequestError({
                'msg': "Invalid parameters %s." % list(errors.keys()),
                'errors': errors,
            })

        # Add the machine.
        machine = self.add_machine(name, fail_on_error=fail_on_error, **kwargs)

        # Enable monitoring.
        if monitoring:
            from mist.api.monitoring.methods import enable_monitoring
            from mist.api.machines.models import KeyMachineAssociation
            enable_monitoring(
                self.cloud.owner, self.cloud.id, machine.id,
                no_ssh=not (machine.os_type == 'unix' and
                            KeyMachineAssociation.objects(
                                machine=machine).count())
            )

        return machine

    def add_machine(self, name='', host='',
                    ssh_user='root', ssh_port=22, ssh_key=None,
                    os_type='unix', rdp_port=3389, images_location='',
                    fail_on_error=True):
        """Add machine to this dummy Cloud

        This is a special method that exists only on this Cloud subclass.
        """

        old_machines = [m.as_dict() for m in
                        self.cloud.ctl.compute.list_cached_machines()]

        # FIXME: Move ssh command to Machine controller once it is migrated.
        from mist.api.methods import ssh_command

        try:
            ssh_port = int(ssh_port)
        except (ValueError, TypeError):
            ssh_port = 22
        try:
            rdp_port = int(rdp_port)
        except (ValueError, TypeError):
            rdp_port = 3389
        if ssh_key:
            ssh_key = Key.objects.get(owner=self.cloud.owner, id=ssh_key,
                                      deleted=None)

        from mist.api.machines.models import Machine
        # Create and save machine entry to database.
        machine = Machine(
            cloud=self.cloud,
            name=name or host,
            external_id=uuid.uuid4().hex,
            os_type=os_type,
            ssh_port=ssh_port,
            rdp_port=rdp_port,
            last_seen=datetime.datetime.utcnow()
        )
        if host:
            # Sanitize inputs.
            host = sanitize_host(host)
            check_host(host)
            machine.hostname = host

            if is_private_subnet(socket.gethostbyname(host)):
                machine.private_ips = [host]
            else:
                machine.public_ips = [host]
        machine.save(write_concern={'w': 1, 'fsync': True})

        # Attempt to connect.
        if os_type == 'unix' and ssh_key:
            if not ssh_user:
                ssh_user = 'root'
            # Try to connect. If it works, it will create the association.
            try:
                if not host:
                    raise BadRequestError("You have specified an SSH key but "
                                          "machine hostname is empty.")
                to_tunnel(self.cloud.owner, host)  # May raise VPNTunnelError
                ssh_command(
                    self.cloud.owner, self.cloud.id, machine.id, host,
                    'uptime', key_id=ssh_key.id, username=ssh_user,
                    port=ssh_port
                )
            except MachineUnauthorizedError as exc:
                if fail_on_error:
                    machine.delete()
                raise CloudUnauthorizedError(exc)
            except ServiceUnavailableError as exc:
                if fail_on_error:
                    machine.delete()
                raise MistError("Couldn't connect to host '%s'." % host)
            except:
                if fail_on_error:
                    machine.delete()
                raise

        # Update RBAC Mappings given the list of nodes seen for the first time.
        new_machines = self.cloud.ctl.compute.list_cached_machines()
        if new_machines:
            self.cloud.owner.mapper.update(new_machines, asynchronous=False)

        if amqp_owner_listening(self.cloud.owner.id):
            self.cloud.ctl.compute.produce_and_publish_patch(
                old_machines, new_machines)

        return machine


class _KubernetesBaseMainController(BaseMainController):
    StorageController = storage_ctls.KubernetesStorageController

    def _update__preparse_kwargs(self, kwargs):
        kwargs.pop('authentication', None)
        host = kwargs.get('host', self.cloud.host)
        if host:
            host = sanitize_host(host)
            check_host(host)


class KubernetesMainController(_KubernetesBaseMainController):
    provider = 'kubernetes'
    ComputeController = compute_ctls.KubernetesComputeController


class KubeVirtMainController(_KubernetesBaseMainController):
    provider = 'kubevirt'
    ComputeController = compute_ctls.KubeVirtComputeController


class OpenShiftMainController(_KubernetesBaseMainController):
    provider = 'openshift'
    ComputeController = compute_ctls.OpenShiftComputeController


class CloudSigmaMainController(BaseMainController):
    provider = 'cloudsigma'
    ComputeController = compute_ctls.CloudSigmaComputeController
    StorageController = storage_ctls.CloudSigmaStorageController
