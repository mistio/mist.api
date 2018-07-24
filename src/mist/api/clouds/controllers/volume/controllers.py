"""Definition of cloud-specific volume subcontroller classes.

This file should only contain subclasses of `BaseVolumeController`.

"""

import logging

from mist.api.clouds.controllers.volume.base import BaseVolumeController

from mist.api.exceptions import RequiredParameterMissingError


log = logging.getLogger(__name__)


class GoogleVolumeController(BaseVolumeController):

	def _list_volumes__postparse_volume(self, volume, libcloud_volume):
		volume.state = libcloud_volume.extra.get('status', '')
		volume.location = libcloud_volume.extra.get('zone', '')
		volume.disk_type = libcloud_volume.extra.get('type', '')

	def _create_volume__prepare_args(self, kwargs):
		if kwargs.get('location') is None:
			raise RequiredParameterMissingError('location')


class AmazonVolumeController(BaseVolumeController):

	def _list_volumes__postparse_volume(self, volume, libcloud_volume):
		volume.state = libcloud_volume.state
		volume.location = libcloud_volume.extra.get('zone', '')
		volume.volume_type =  libcloud_volume.extra.get('volume_type', '')
		volume.iops = libcloud_volume.extra.get('iops', '')

	def _create_volume__prepare_args(self, kwargs):
		if kwargs.get('location') is None:
			raise RequiredParameterMissingError('location')


class DigitalOceanVolumeController(BaseVolumeController):
	
	def _list_volumes__postparse_volume(self, volume, libcloud_volume):
		volume.location = libcloud_volume.extra.get('region').get('name')


class OpenstackVolumeController(BaseVolumeController):

	def _list_volumes__postparse_volume(self, volume, libcloud_volume):
		volume.state = libcloud_volume.state
		volume.location = libcloud_volume.extra.get('location', '')
		volume.type = libcloud_volume.extra.get('volume_type')
		

class AzureVolumeController(BaseVolumeController):

	def _list_volumes__postparse_volume(self, volume, libcloud_volume):
		volume.location = libcloud_volume.extra.get('location', '')
