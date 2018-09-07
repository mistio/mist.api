"""Definition of cloud-specific volume subcontroller classes.

This file should only contain subclasses of `BaseStorageController`.

"""

import logging

from mist.api.clouds.controllers.storage.base import BaseStorageController

from mist.api.exceptions import RequiredParameterMissingError


log = logging.getLogger(__name__)


class GoogleStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        volume.state = libcloud_volume.extra.get('status', '')
        volume.location = libcloud_volume.extra.get('zone', '')
        volume.disk_type = libcloud_volume.extra.get('type', '')

    def _create_volume__prepare_args(self, kwargs, location):
        if kwargs.get('location') is None:
            raise RequiredParameterMissingError('location')
	kwargs['location'] = location.name

class AmazonStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        volume.state = libcloud_volume.state
        volume.location = libcloud_volume.extra.get('zone', '')
        volume.volume_type = libcloud_volume.extra.get('volume_type', '')
        volume.iops = libcloud_volume.extra.get('iops', '')

    def _create_volume__prepare_args(self, kwargs, location):
        if kwargs.get('location') is None:
            raise RequiredParameterMissingError('location')

    def _attach_volume(self, libcloud_volume, libcloud_node, **kwargs):
        device = kwargs['device']
        self.cloud.ctl.compute.connection.attach_volume(libcloud_node,
                                                        libcloud_volume,
                                                        device)


class DigitalOceanStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        volume.location = libcloud_volume.extra.get('region').get('name')


class OpenstackStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        volume.state = libcloud_volume.state
        volume.location = libcloud_volume.extra.get('location', '')


class AzureStorageController(BaseStorageController):

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
        volume.location = libcloud_volume.extra.get('location', '')
