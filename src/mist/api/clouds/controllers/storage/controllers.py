"""Definition of cloud-specific volume subcontroller classes.

This file should only contain subclasses of `BaseStorageController`.

"""

import logging
import time


from mist.api.clouds.controllers.storage.base import BaseStorageController

from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError

from libcloud.common.types import LibcloudError
from libcloud.compute.base import NodeLocation

log = logging.getLogger(__name__)


class GoogleStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.machines.models import Machine
        from mist.api.clouds.models import CloudLocation

        # Find the volume's location.
        try:
            volume.location = CloudLocation.objects.get(
                name=libcloud_volume.extra.get('zone', ''),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            volume.location = None

        # Find the machines to which the volume is attached.
        volume.attached_to = []
        for libcloud_name in libcloud_volume.extra.get('users') or []:
            try:
                name = libcloud_name.split('/')[-1]
            except IndexError:
                log.error('Failed to parse machine name: %s', libcloud_name)
                continue
            try:
                machine = Machine.objects.get(name=name, cloud=self.cloud,
                                              missing_since=None)
                volume.attached_to.append(machine)
            except Machine.DoesNotExist:
                log.error('%s attached to unknown machine "%s"', volume, name)

    def _create_volume__prepare_args(self, kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.clouds.models import CloudLocation
        if not kwargs.get('location'):
            raise RequiredParameterMissingError('location')
        try:
            location = CloudLocation.objects.get(id=kwargs['location'])
        except CloudLocation.DoesNotExist:
            raise NotFoundError("Location with id '%s'." % kwargs['location'])
        kwargs['location'] = location.name


class AmazonStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.machines.models import Machine
        from mist.api.clouds.models import CloudLocation
        # Find the volume's location.
        try:
            volume.location = CloudLocation.objects.get(
                name=libcloud_volume.extra.get('zone', ''),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            volume.location = None

        # Find the machine to which the volume is attached. NOTE that a just
        # a single instance is always returned.
        volume.attached_to = []
        machine_id = libcloud_volume.extra.get('instance_id', '')
        if machine_id:
            try:
                machine = Machine.objects.get(
                    machine_id=machine_id, cloud=self.cloud, missing_since=None
                )
                volume.attached_to = [machine]
            except Machine.DoesNotExist:
                log.error('%s attached to unknown machine "%s"', volume,
                          machine_id)

    def _create_volume__prepare_args(self, kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.clouds.models import CloudLocation
        if not kwargs.get('location'):
            raise RequiredParameterMissingError('location')
        try:
            location = CloudLocation.objects.get(id=kwargs['location'])
        except CloudLocation.DoesNotExist:
            raise NotFoundError("Location with id '%s'." % kwargs['location'])
        kwargs['location'] = location.name

    def _attach_volume(self, libcloud_volume, libcloud_node, **kwargs):
        if not kwargs.get('device'):
            raise RequiredParameterMissingError('device')
        self.cloud.ctl.compute.connection.attach_volume(libcloud_node,
                                                        libcloud_volume,
                                                        kwargs['device'])


class DigitalOceanStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.machines.models import Machine
        from mist.api.clouds.models import CloudLocation

        # Find the volume's location.
        try:
            volume.location = CloudLocation.objects.get(
                name=libcloud_volume.extra.get('region', {}).get('name'),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            volume.location = None

        # Find the machines to which the volume is attached.
        volume.attached_to = []
        for machine_id in libcloud_volume.extra.get('droplet_ids', []):
            try:
                machine = Machine.objects.get(
                    machine_id=str(machine_id), cloud=self.cloud,
                    missing_since=None
                )
                volume.attached_to.append(machine)
            except Machine.DoesNotExist:
                log.error('%s attached to unknown machine "%s"', volume,
                          machine_id)

    def _create_volume__prepare_args(self, kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.clouds.models import CloudLocation
        if not kwargs.get('location'):
            raise RequiredParameterMissingError('location')
        try:
            location = CloudLocation.objects.get(id=kwargs['location'])
        except CloudLocation.DoesNotExist:
            _location = kwargs['location']
            try:
                location = CloudLocation.objects.get(external_id=_location)
            except CloudLocation.DoesNotExist:
                raise NotFoundError("Location with id '%s'." % _location)
        node_location = NodeLocation(id=location.external_id,
                                     name=location.name,
                                     country=location.country, driver=None)
        kwargs['location'] = node_location


class OpenstackStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.machines.models import Machine
        from mist.api.clouds.models import CloudLocation

        # Find the volume's location.
        try:
            volume.location = CloudLocation.objects.get(
                name=libcloud_volume.extra.get('location', ''),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            volume.location = None

        # Find the machines to which the volume is attached.
        volume.attached_to = []
        for attachment in libcloud_volume.extra.get('attachments', []):
            machine_id = attachment.get('server_id')
            try:
                machine = Machine.objects.get(machine_id=machine_id,
                                              cloud=self.cloud)
                volume.attached_to.append(machine)
            except Machine.DoesNotExist:
                log.error('%s attached to unknown machine "%s"', volume,
                          machine_id)


class AzureStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.clouds.models import CloudLocation

        # Find the volume's location.
        try:
            volume.location = CloudLocation.objects.get(
                name=libcloud_volume.extra.get('location', ''),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            volume.location = None

    def _create_volume__prepare_args(self, volume, libcloud_volume):
        raise BadRequestError('Volume provisioning is not supported')


class AzureArmStorageController(BaseStorageController):
    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        # # FIXME Imported here due to circular dependency issues.
        from mist.api.clouds.models import CloudLocation
        from mist.api.machines.models import Machine

        # Find the volume's location.
        try:
            volume.location = CloudLocation.objects.get(
                external_id=libcloud_volume.extra.get('location', ''),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            volume.location = None

        # Find the machine the volume is attached to.
        volume.attached_to = []
        owner_id = libcloud_volume.extra.get('properties').get('ownerId')

        if owner_id:
            # Azure ARM has two ids... one stored as node.id,
            # one stored in extra when creating a machine node.id
            # is returned, here however ownerId is the node.extra('id')
            machines = Machine.objects.filter(cloud=self.cloud,
                                              missing_since=None)
            for machine in machines:
                # use .lower() because arm is inconsistent in using lowercase
                if machine.extra.get('id').lower() == owner_id.lower():
                    volume.attached_to.append(machine)
                    break

            if not volume.attached_to:
                log.error('%s attached to unknown machine "%s"', volume,
                          owner_id)

    def _list_volumes__volume_actions(self, volume, libcloud_volume):
        super(AzureArmStorageController, self)._list_volumes__volume_actions(
            volume, libcloud_volume)
        # need to figure whether this is os disk or not
        owner_id = libcloud_volume.extra.get('properties').get('ownerId')

        if owner_id:
            volume.actions.delete = False
            from mist.api.machines.models import Machine
            machines = Machine.objects.filter(cloud=self.cloud,
                                              missing_since=None)
            for machine in machines:
                # use .lower() because arm is inconsistent in using lowercase
                if machine.extra.get('id').lower() == owner_id.lower():
                    storage_profile = machine.extra.get('storageProfile')
                    os_disk_name = storage_profile.get('osDisk').get('name')
                    if os_disk_name == volume.name:  # os disk
                        volume.actions.detach = False
                    break

    def _create_volume__prepare_args(self, kwargs):
        if not kwargs.get('resource_group'):
            raise RequiredParameterMissingError('resource_group')
        if not kwargs.get('location'):
            raise RequiredParameterMissingError('location')

        # FIXME Imported here due to circular dependency issues.
        from mist.api.clouds.models import CloudLocation
        try:
            location = CloudLocation.objects.get(id=kwargs['location'])
        except CloudLocation.DoesNotExist:
            raise NotFoundError("Location with id '%s'." % kwargs['location'])
        node_location = NodeLocation(id=location.external_id,
                                     name=location.name,
                                     country=location.country, driver=None)
        kwargs['location'] = node_location
        resource_group = kwargs.pop('resource_group')
        conn = self.cloud.ctl.compute.connection
        resource_groups = conn.ex_list_resource_groups()
        ex_resource_group = None
        for lib_resource_group in resource_groups:
            if lib_resource_group.id == resource_group:
                ex_resource_group = lib_resource_group.name
                break

        # if not found, create it
        if ex_resource_group is None:
            try:
                conn.ex_create_resource_group(resource_group,
                                              node_location)
                ex_resource_group = resource_group
                # add delay cause sometimes the group is not yet ready
                time.sleep(5)
            except Exception as exc:
                raise LibcloudError("Couldn't create resource group. \
                    %s" % exc)
        kwargs['ex_resource_group'] = ex_resource_group
        account_type = kwargs.pop('storage_account_type', 'Standard_LRS')
        kwargs['ex_storage_account_type'] = account_type


class AlibabaStorageController(BaseStorageController):
    def _create_volume__prepare_args(self, kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.clouds.models import CloudLocation
        kwargs['ex_description'] = kwargs.pop('description', '')
        kwargs['ex_disk_category'] = kwargs.pop('disk_category', 'cloud')
        try:
            location = CloudLocation.objects.get(id=kwargs['location'])
            kwargs['ex_zone_id'] = location.external_id
        except CloudLocation.DoesNotExist:
            raise NotFoundError("Location with id '%s'." % kwargs['location'])

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.machines.models import Machine
        from mist.api.clouds.models import CloudLocation

        # Find the volume's location.
        try:
            volume.location = CloudLocation.objects.get(
                name=libcloud_volume.extra.get('zone_id', ''),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            volume.location = None

        # Find the machine to which the volume is attached. NOTE that a just
        # a single instance is always returned.
        volume.attached_to = []
        machine_id = libcloud_volume.extra.get('instance_id', '')
        if machine_id:
            try:
                machine = Machine.objects.get(
                    machine_id=machine_id, cloud=self.cloud, missing_since=None
                )
                volume.attached_to = [machine]
            except Machine.DoesNotExist:
                log.error('%s attached to unknown machine "%s"', volume,
                          machine_id)

    def _list_volumes__volume_actions(self, volume, libcloud_volume):
        super(AlibabaStorageController, self)._list_volumes__volume_actions(
            volume, libcloud_volume)
        # need to figure whether this is os disk or not
        if libcloud_volume.extra.get('instance_id', ''):
            volume.actions.delete = False
            if libcloud_volume.extra.get('type') == 'system':
                volume.actions.detach = False


class PacketStorageController(BaseStorageController):
    def _create_volume__prepare_args(self, kwargs):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.clouds.models import CloudLocation

        if not kwargs.get('location'):
            raise RequiredParameterMissingError('location')
        try:
            location = CloudLocation.objects.get(id=kwargs['location'])
        except CloudLocation.DoesNotExist:
            raise NotFoundError("Location with id '%s'." % kwargs['location'])
        kwargs['location'] = location.external_id

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.machines.models import Machine
        from mist.api.clouds.models import CloudLocation

        # Find the volume's location.
        try:
            external_location_id = volume.extra['facility']['href'].split(
                '/')[-1]
            volume.location = CloudLocation.objects.get(
                cloud=volume.cloud,
                external_id=external_location_id)
        except CloudLocation.DoesNotExist:
            volume.location = None

        # Find the machines to which the volume is attached.
        volume.attached_to = []
        libcloud_connection = volume.cloud.ctl.compute.connection
        for attachment in libcloud_volume.extra.get('attachments', []):
            attachment_id = attachment.get('href').split('/')[-1]
            attachment_data = libcloud_connection.ex_describe_attachment(
                attachment_id)
            external_volume_id = attachment_data['volume']['href'].split(
                '/')[-1]
            assert external_volume_id == volume.external_id
            machine_id = attachment_data['device']['href'].split('/')[-1]
            try:
                machine = Machine.objects.get(machine_id=machine_id,
                                              cloud=self.cloud)
                volume.attached_to.append(machine)
            except Machine.DoesNotExist:
                log.error('%s attached to unknown machine "%s"', volume,
                          machine_id)


class LXDStorageController(BaseStorageController):
    """
    Storage controller for LXC containers
    """

    def _list_volumes__fetch_volumes(self):
        """Return the original list of libcloud Volume objects
        """

        # get a list of the storage pools
        connection = self.cloud.ctl.compute.connection
        storage_pools = connection.ex_list_storage_pools(detailed=False)
        volumes = []

        for pool in storage_pools:

            vols = connection.ex_list_storage_pool_volumes(pool_id=pool.name,
                                                           detailed=True)

            for vol in vols:
                volumes.append(vol)
        return volumes

    def _create_volume__prepare_args(self, kwargs):
        """
        Parses keyword arguments on behalf of `self.create_volume`.

        Creates the parameter structure required by the libcloud method
        that handles volume creation.

        """

        kwargs["definition"] = {"name": kwargs.pop("name"),
                                "type": "custom",
                                "config": {"size": kwargs["size"],
                                           "size_type": "GB",
                                           "block.filesystem": 'ext4'}}

    def _delete_volume(self, libcloud_volume):
        connection = self.cloud.ctl.compute.connection
        pid = libcloud_volume.extra["pool_id"]
        type = libcloud_volume.extra["type"]
        name = libcloud_volume.name
        connection.ex_delete_storage_pool_volume(pool_id=pid,
                                                 type=type,
                                                 name=name)
