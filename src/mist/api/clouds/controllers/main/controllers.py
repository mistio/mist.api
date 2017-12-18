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


import uuid
import json
import socket
import logging

import mongoengine as me

from libcloud.utils.networking import is_private_subnet

from mist.api.exceptions import MistError
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import CloudExistsError
from mist.api.exceptions import CloudUnauthorizedError
from mist.api.exceptions import ServiceUnavailableError
from mist.api.exceptions import MachineUnauthorizedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.helpers import sanitize_host, check_host

from mist.api.keys.models import Key
from mist.api.machines.models import Machine

from mist.api.helpers import rename_kwargs
from mist.api.clouds.controllers.main.base import BaseMainController
from mist.api.clouds.controllers.compute import controllers as compute_ctls
from mist.api.clouds.controllers.network import controllers as network_ctls
from mist.api.clouds.controllers.dns import controllers as dns_ctls

try:
    from mist.core.vpn.methods import to_tunnel
    from mist.core.methods import enable_monitoring
except ImportError:
    from mist.api.dummy.methods import to_tunnel
    from mist.api.dummy.methods import enable_monitoring


log = logging.getLogger(__name__)


class AmazonMainController(BaseMainController):

    provider = 'ec2'
    ComputeController = compute_ctls.AmazonComputeController
    NetworkController = network_ctls.AmazonNetworkController
    DnsController = dns_ctls.AmazonDNSController

    def _add__preparse_kwargs(self, kwargs):
        # Autofill apisecret from other Amazon Cloud.
        apikey = kwargs.get('apikey')
        apisecret = kwargs.get('apisecret')
        if apikey and apisecret == 'getsecretfromdb':
            cloud = type(self.cloud).objects(owner=self.cloud.owner,
                                             apikey=apikey,
                                             deleted=None).first()
            if cloud is not None:
                kwargs['apisecret'] = cloud.apisecret


class DigitalOceanMainController(BaseMainController):

    provider = 'digitalocean'
    ComputeController = compute_ctls.DigitalOceanComputeController
    DnsController = dns_ctls.DigitalOceanDNSController


class LinodeMainController(BaseMainController):

    provider = 'linode'
    ComputeController = compute_ctls.LinodeComputeController
    DnsController = dns_ctls.LinodeDNSController


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
                kwargs['apikey'] = cloud.apikey


class SoftLayerMainController(BaseMainController):

    provider = 'softlayer'
    ComputeController = compute_ctls.SoftLayerComputeController
    DnsController = dns_ctls.SoftLayerDNSController


class NephoScaleMainController(BaseMainController):

    provider = 'nephoscale'
    ComputeController = compute_ctls.NephoScaleComputeController


class AzureMainController(BaseMainController):

    provider = 'azure'
    ComputeController = compute_ctls.AzureComputeController


class AzureArmMainController(BaseMainController):

    provider = 'azure_arm'
    ComputeController = compute_ctls.AzureArmComputeController
    NetworkController = network_ctls.AzureArmNetworkController


class GoogleMainController(BaseMainController):

    provider = 'gce'
    ComputeController = compute_ctls.GoogleComputeController
    NetworkController = network_ctls.GoogleNetworkController
    DnsController = dns_ctls.GoogleDNSController

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


class PacketMainController(BaseMainController):

    provider = 'packet'
    ComputeController = compute_ctls.PacketComputeController


class VultrMainController(BaseMainController):

    provider = 'vultr'
    ComputeController = compute_ctls.VultrComputeController
    DnsController = dns_ctls.VultrDNSController


class VSphereMainController(BaseMainController):

    provider = 'vsphere'
    ComputeController = compute_ctls.VSphereComputeController

    def _update__preparse_kwargs(self, kwargs):
        host = kwargs.get('host', self.cloud.host)
        if host:
            kwargs['host'] = sanitize_host(host)
            check_host(kwargs['host'])


class VCloudMainController(BaseMainController):

    provider = 'vcloud'
    ComputeController = compute_ctls.VCloudComputeController

    def _update__preparse_kwargs(self, kwargs):
        username = kwargs.get('username', self.cloud.username) or ''
        organization = kwargs.pop('organization')

        if not organization:
            if '@' not in username:
                raise RequiredParameterMissingError('organization')
        else:
            if '@' in username:
                username = username.split('@')[0]
            kwargs['username'] = '%s@%s' % (username, organization)
        host = kwargs.get('host', self.cloud.host)
        if host:
            kwargs['host'] = sanitize_host(host)
            check_host(kwargs['host'])


class OpenStackMainController(BaseMainController):

    provider = 'openstack'
    ComputeController = compute_ctls.OpenStackComputeController
    NetworkController = network_ctls.OpenStackNetworkController

    def _update__preparse_kwargs(self, kwargs):
        rename_kwargs(kwargs, 'auth_url', 'url')
        rename_kwargs(kwargs, 'tenant_name', 'tenant')
        url = kwargs.get('url', self.cloud.url)
        if url:
            if url.endswith('/v2.0/'):
                url = url.split('/v2.0/')[0]
            elif url.endswith('/v2.0'):
                url = url.split('/v2.0')[0]
            kwargs['url'] = url.rstrip('/')
            check_host(sanitize_host(kwargs['url']))


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


class LibvirtMainController(BaseMainController):

    provider = 'libvirt'
    ComputeController = compute_ctls.LibvirtComputeController

    def _add__preparse_kwargs(self, kwargs):
        rename_kwargs(kwargs, 'machine_hostname', 'host')
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

    def add(self, fail_on_error=True, fail_on_invalid_params=True, **kwargs):
        """This is a hack to associate a key with the VM hosting this cloud"""
        super(LibvirtMainController, self).add(
            fail_on_error=fail_on_error,
            fail_on_invalid_params=fail_on_invalid_params,
            add=True, **kwargs
        )
        # FIXME: Don't use self.cloud.host as machine_id, this prevents us from
        # changing the cloud's host.
        # FIXME: Add type field to differentiate between actual vm's and the
        # host.

        try:
            machine = Machine.objects.get(cloud=self.cloud,
                                          machine_id=self.cloud.host)
        except me.DoesNotExist:
            machine = Machine.objects(cloud=self.cloud,
                                      machine_id=self.cloud.host).save()
        if self.cloud.key:
            machine.ctl.associate_key(self.cloud.key,
                                      username=self.cloud.username,
                                      port=self.cloud.port)

    def update(self, fail_on_error=True, fail_on_invalid_params=True,
               add=False, **kwargs):
        # FIXME: Add update support, need to clean up kvm 'host' from libcloud,
        # and especially stop using cloud.host as the machine id ffs.
        if not add:
            raise BadRequestError("Update action is not currently support for "
                                  "Libvirt/KVM clouds.")
        super(LibvirtMainController, self).update(
            fail_on_error=fail_on_error,
            fail_on_invalid_params=fail_on_invalid_params,
            **kwargs
        )


class OtherMainController(BaseMainController):

    provider = 'bare_metal'
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

    def add(self, fail_on_error=True, fail_on_invalid_params=True, **kwargs):
        """Add new Cloud to the database

        This is the only cloud controller subclass that overrides the `add`
        method of `BaseMainController`.

        This is only expected to be called by `Cloud.add` classmethod to create
        a cloud. Fields `owner` and `title` are already populated in
        `self.cloud`. The `self.cloud` model is not yet saved.

        If appropriate kwargs are passed, this can currently also act as a
        shortcut to also add machines on this cloud.

        """
        # Attempt to save.
        try:
            self.cloud.save()
        except me.ValidationError as exc:
            raise BadRequestError({'msg': exc.message,
                                   'errors': exc.to_dict()})
        except me.NotUniqueError:
            raise CloudExistsError("Cloud with name %s already exists"
                                   % self.cloud.title)

        if kwargs:
            errors = []
            if 'machines' in kwargs:  # new api: list of multitple machines
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
                        self.cloud.title, fail_on_error=fail_on_error,
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
                              "Only title can be changed, using `rename`. "
                              "To change machine details, one must edit the "
                              "machines themselves, not the cloud.")

    def add_machine_wrapper(self, name, fail_on_error=True,
                            fail_on_invalid_params=True, monitoring=False,
                            **kwargs):
        """Wrapper around add_machine for kwargs backwards compatibity

        FIXME: This wrapper should be deprecated

        """

        # Sanitize params.
        rename_kwargs(kwargs, 'machine_ip', 'host')
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
        for key in kwargs.keys():
            if key not in ('host', 'ssh_user', 'ssh_port', 'ssh_key',
                           'os_type', 'rdp_port'):
                error = "Invalid parameter %s=%r." % (key, kwargs[key])
                if fail_on_invalid_params:
                    errors[key] = error
                else:
                    log.warning(error)
                    kwargs.pop(key)
        if not name:
            errors['name'] = "Required parameter name missing"
            log.error(errors['name'])
        if 'host' not in kwargs:
            errors['host'] = "Required parameter host missing"
            log.error(errors['host'])

        if errors:
            log.error("Invalid parameters %s." % errors.keys())
            raise BadRequestError({
                'msg': "Invalid parameters %s." % errors.keys(),
                'errors': errors,
            })

        # Add the machine.
        machine = self.add_machine(name, fail_on_error=fail_on_error, **kwargs)

        # Enable monitoring.
        if monitoring:
            enable_monitoring(
                self.cloud.owner, self.cloud.id, machine.machine_id,
                no_ssh=not (machine.os_type == 'unix' and
                            machine.key_associations)
            )

        return machine

    def add_machine(self, name, host='',
                    ssh_user='root', ssh_port=22, ssh_key=None,
                    os_type='unix', rdp_port=3389, fail_on_error=True):
        """Add machine to this dummy Cloud

        This is a special method that exists only on this Cloud subclass.
        """
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

        # Create and save machine entry to database.
        machine = Machine(
            cloud=self.cloud,
            name=name,
            machine_id=uuid.uuid4().hex,
            os_type=os_type,
            ssh_port=ssh_port,
            rdp_port=rdp_port
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
        machine.save()

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
                    self.cloud.owner, self.cloud.id, machine.machine_id, host,
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
        return machine
