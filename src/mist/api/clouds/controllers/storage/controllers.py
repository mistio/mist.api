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
        volume.state = libcloud_volume.extra.get('status', '')
        volume.location = libcloud_volume.extra.get('zone', '')
        volume.disk_type = libcloud_volume.extra.get('type', '')
        machine_names = libcloud_volume.extra.get('users')
        volume.attached_to = []
        if machine_names:
            for machine_name in machine_names:
                from mist.api.machines.models import Machine
                try:
                    machine = Machine.objects.get(name=machine_name.split('/')[-1], cloud=self.cloud)
                except Machine.DoesNotExist:
                    pass
                else:
                    if machine.missing_since == None and machine not in volume.attached_to:
                        volume.attached_to.append(machine)

    def _create_volume__prepare_args(self, kwargs):
        if kwargs.get('location') is None:
            raise RequiredParameterMissingError('location')

        # FIXME
        from mist.api.clouds.models import CloudLocation
        try:
            location = CloudLocation.objects.get(id=kwargs['location'])
        except CloudLocation.DoesNotExist:
            raise NotFoundError(
                "Location with id '%s'." % kwargs['location']
            )
        kwargs['location'] = location.name


class AmazonStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        volume.state = libcloud_volume.state
        volume.location = libcloud_volume.extra.get('zone', '')
        volume.volume_type = libcloud_volume.extra.get('volume_type', '')
        volume.iops = libcloud_volume.extra.get('iops', '')
        volume.attached_to = []
        # always returns one instance
        machine_id = libcloud_volume.extra.get('instance_id', '')
        if machine_id:
            from mist.api.machines.models import Machine
            try:
                machine = Machine.objects.get(machine_id=machine_id, cloud=self.cloud)
            except Machine.DoesNotExist:
                pass
            else:
                if machine.missing_since == None and machine not in volume.attached_to:
                    volume.attached_to.append(machine)

    def _create_volume__prepare_args(self, kwargs):
        if kwargs.get('location') is None:
            raise RequiredParameterMissingError('location')
        # FIXME: circular import
        from mist.api.clouds.models import CloudLocation
        try:
            location = CloudLocation.objects.get(id=kwargs['location'])
        except CloudLocation.DoesNotExist:
            raise NotFoundError(
                "Location with id '%s'." % kwargs['location']
            )
        kwargs['location'] = location.name

    def _attach_volume(self, libcloud_volume, libcloud_node, **kwargs):
        device = kwargs['device']
        self.cloud.ctl.compute.connection.attach_volume(libcloud_node,
                                                        libcloud_volume,
                                                        device)


class DigitalOceanStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        volume.location = libcloud_volume.extra.get('region').get('name')
        volume.attached_to = []
        machine_ids = libcloud_volume.extra.get('droplet_ids')
        for machine_id in machine_ids:
            from mist.api.machines.models import Machine
            try:
                machine = Machine.objects.get(machine_id=machine_id, cloud=self.cloud)
            except Machine.DoesNotExist:
                pass
            else:
                if machine.missing_since == None and machine not in volume.attached_to:
                    volume.attached_to.append(machine)

    def _create_volume__prepare_args(self, kwargs):
        if kwargs.get('location') is None:
            raise RequiredParameterMissingError('location')
        # FIXME
        from mist.api.clouds.models import CloudLocation
        try:
            location = CloudLocation.objects.get(id=kwargs['location'])
        except CloudLocation.DoesNotExist:
            raise NotFoundError(
                "Location with id '%s'." % kwargs['location']
            )
        kwargs['location'] = location.external_id


class OpenstackStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        volume.state = libcloud_volume.state
        volume.location = libcloud_volume.extra.get('location', '')
        volume.attached_to = []

        attachments = libcloud_volume.extra.get('attachments', '')
        for attachment in attachments:
            machine_id = attachment.get('serverId')
            from mist.api.machines.models import Machine
            try:
                machine = Machine.objects.get(machine_id=machine_id, cloud=self.cloud)
            except Machine.DoesNotExist:
                pass
            else:
                if machine.missing_since == None and machine not in volume.attached_to:
                    volume.attached_to.append(machine)


class AzureStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        volume.location = libcloud_volume.extra.get('location', '')
