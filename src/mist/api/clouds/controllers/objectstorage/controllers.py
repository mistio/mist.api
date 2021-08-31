"""Definition of cloud-specific volume subcontroller classes.

This file should only contain subclasses of `BaseStorageController`.

"""

import logging

from libcloud.storage.providers import get_driver
from libcloud.storage.types import Provider


from mist.api.clouds.controllers.objectstorage.base import BaseObjectStorageController  # noqa: E501

from mist.api import config

if config.HAS_VPN:
    from mist.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat


log = logging.getLogger(__name__)


class OpenstackObjectStorageController(BaseObjectStorageController):
    def _connect(self, **kwargs):
        url = dnat(self.cloud.owner, self.cloud.url)

        return get_driver(Provider.OPENSTACK_SWIFT)(
            self.cloud.username,
            self.cloud.password,
            ex_force_auth_version='3.x_password',
            ex_tenant_name=self.cloud.tenant,
            ex_auth_url=url,
        )


class VexxhostObjectStorageController(OpenstackObjectStorageController):
    pass


class AmazonS3ObjectStorageController(BaseObjectStorageController):
    def _connect(self, **kwargs):
        return get_driver(Provider.S3)(
            self.cloud.apikey,
            self.cloud.apisecret,
            region=self.cloud.region
        )
