"""Definition of cloud-specific volume subcontroller classes.

This file should only contain subclasses of `BaseStorageController`.

"""

import logging

from mist.api.clouds.controllers.storage.base import BaseStorageController

from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import NotFoundError


log = logging.getLogger(__name__)


class GoogleStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.machines.models import Machine
        from mist.api.clouds.models import CloudLocation

        # Find the volume's location.
        try:
            volume.location = CloudLocation.objects(
                name=libcloud_volume.extra.get('zone', ''),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            log.warning('No location "%s" in %s', location_name, self.cloud)
            volume.location = None

        # Find the machines to which the volume is attached.
        volume.attached_to = []
        for libcloud_name in libcloud_volume.extra.get('users', []):
            try:
                name = libcloud_name.split('/')[-1]
            except IndexError:
                log.error('Failed to parse machine name: %s', libcloud_name)
                continue
            try:
                machine = Machine.objects.get(name=name, cloud=self.cloud)
                attached_to.append(machine)
            except Machine.DoesNotExist:
                log.error('%s attached to unknown machine "%s"', volume, name)
                pass

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
            volume.location = CloudLocation.objects(
                name=libcloud_volume.extra.get('zone', ''),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            log.warning('No location "%s" in %s', location_name, self.cloud)
            volume.location = None

        # Find the machine to which the volume is attached. NOTE that a just
        # a single instance is always returned.
        volume.attached_to = []
        machine_id = libcloud_volume.extra.get('instance_id', '')
        if machine_id:
            try:
                machine = Machine.objects.get(machine_id=machine_id,
                                              cloud=self.cloud)
                volume.attached_to = [machine]
            except Machine.DoesNotExist:
                log.error('%s attached to unknown machine "%s"', volume, name)
                pass

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
            volume.location = CloudLocation.objects(
                name=libcloud_volume.extra.get('region', {}).get('name'),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            log.warning('No location "%s" in %s', location_name, self.cloud)
            volume.location = None

        # Find the machines to which the volume is attached.
        volume.attached_to = []
        for machine_id in libcloud_volume.extra.get('droplet_ids', []):
            try:
                machine = Machine.objects.get(machine_id=machine_id,
                                              cloud=self.cloud)
                volume.attached_to.append(machine)
            except Machine.DoesNotExist:
                log.error('%s attached to unknown machine "%s"', volume, name)
                pass

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
            volume.location = CloudLocation.objects(
                name=libcloud_volume.extra.get('location', ''),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            log.warning('No location "%s" in %s', location_name, self.cloud)
            volume.location = None

        # Find the machines to which the volume is attached.
        volume.attached_to = []
        for attachment in libcloud_volume.extra.get('attachments', []):
            machine_id = attachment.get('serverId')
            try:
                machine = Machine.objects.get(machine_id=machine_id,
                                              cloud=self.cloud)
                volume.attached_to.append(machine)
            except Machine.DoesNotExist:
                log.error('%s attached to unknown machine "%s"', volume, name)
                pass


class AzureStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        # FIXME Imported here due to circular dependency issues.
        from mist.api.machines.models import Machine
        from mist.api.clouds.models import CloudLocation

        # Find the volume's location.
        try:
            volume.location = CloudLocation.objects(
                name=libcloud_volume.extra.get('location', ''),
                cloud=self.cloud, missing_since=None
            )
        except CloudLocation.DoesNotExist:
            log.warning('No location "%s" in %s', location_name, self.cloud)
            volume.location = None

    def _create_volume__prepare_args(self, volume, libcloud_volume):
        raise BadRequestError('Volume provisioning is not supported')
