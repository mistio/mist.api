"""Definition of cloud-specific volume subcontroller classes.

This file should only contain subclasses of `BaseStorageController`.

"""

import logging

from mist.api.clouds.controllers.storage.base import BaseStorageController

from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError

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
            raise NotFoundError("Location with id '%s'." % kwargs['location'])
        kwargs['location'] = location.external_id


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
            # Azure ARM has two ids... one stored as node.id, one stored in extra
            # when creating a machine node.id is returned, here however what is
            # returned as ownerId is the node.extra('id')
            machines = Machine.objects.filter(cloud=self.cloud, missing_since=None)
            for machine in machines:
                if machine.extra.get('id') == owner_id:
                    volume.attached_to.append(machine)
                    break

            if not volume.attached_to:
                log.error('%s attached to unknown machine "%s"', volume, owner_id)


    def _create_volume__prepare_args(self, kwargs):
        if not kwargs.get('resource_group'):
            raise RequiredParameterMissingError('resource_group')
        kwargs['ex_resource_group'] = kwargs.pop('resource_group')
        # FIXME Imported here due to circular dependency issues.
        from mist.api.clouds.models import CloudLocation
        if not kwargs.get('location'):
            raise RequiredParameterMissingError('location')
        try:
            location = CloudLocation.objects.get(id=kwargs['location'])
        except CloudLocation.DoesNotExist:
            raise NotFoundError("Location with id '%s'." % kwargs['location'])
        node_location = NodeLocation(id=location.external_id,
                                     name=location.name,
                                     country=location.country, driver=None)
        kwargs['location'] = node_location


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
