"""Definition of cloud-specific volume subcontroller classes.

This file should only contain subclasses of `BaseStorageController`.

"""

import logging

from libcloud.storage.providers import get_driver
from libcloud.storage.types import Provider
from mist.api.clouds.controllers.objectstorage.base import BaseObjectStorageController  # noqa: E501
from mist.api.helpers import bucket_to_dict
from mist.api import config
from libcloud.storage.base import Container

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
            self.cloud.password.value,
            ex_force_auth_version='3.x_password',
            ex_tenant_name=self.cloud.tenant,
            ex_auth_url=url,
        )

    def _list_buckets__fetch_buckets(self):
        """Perform the actual API call to get list of buckets"""
        return self.connection.list_containers()

    def _list_buckets__fetch_bucket_content(self, name,
                                            bucket_id,
                                            prefix='',
                                            delimiter='',
                                            maxkeys=100):
        """Perform the actual libcloud call to get the content of the bucket"""
        bucket = self.connection.get_container(name)
        return [bucket_to_dict(bucket_content, bucket_id)
                for bucket_content in self.connection.list_container_objects(
                    bucket,
                    prefix,
                    ex_delimiter=delimiter,
                    ex_maxkeys=maxkeys)]


class VexxhostObjectStorageController(OpenstackObjectStorageController):
    pass


class AmazonS3ObjectStorageController(BaseObjectStorageController):
    def _connect(self, **kwargs):
        from boto3.session import Session
        return Session(
            aws_access_key_id=self.cloud.apikey,
            aws_secret_access_key=self.cloud.apisecret.value,
            region_name=self.cloud.region
        )

    def _list_buckets__fetch_buckets(self):
        """Perform the actual libcloud call to get list of nodes"""
        return [
            Container(
                name=bucket.name,
                extra={
                    'creation_date': bucket.creation_date.isoformat()
                },
                #  Dummy entry, won't actually be used
                driver=get_driver(Provider.S3_AP_NORTHEAST)
            )
            for bucket in self.connection.resource('s3').buckets.iterator()
        ]

    def _list_buckets__fetch_bucket_content(self, name,
                                            bucket_id,
                                            prefix='',
                                            delimiter='',
                                            maxkeys=100,
                                            continuation_token=None):
        kwargs = {}
        if continuation_token:
            kwargs['ContinuationToken'] = continuation_token
        response = self.connection.client('s3').list_objects_v2(
            Bucket=name,
            Prefix=prefix,
            Delimiter=delimiter,
            MaxKeys=maxkeys,
            **kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise Exception
        content = response.get('Contents', []).copy()
        content.extend(response.get('CommonPrefixes', []))
        return self._to_object_list(content, name, bucket_id)

    def _to_object_list(self, response, bucket_name, bucket_id):

        objects = []
        for obj in response:
            # if the object is a subdir, the other fields won't be populated
            name = obj.get("Key", obj.get("Prefix"))
            size = int(obj.get("Size", 0))
            hash = obj.get("ETag", '')
            try:
                extra = {
                    "StorageClass": obj.get("StorageClass"),
                    "last_modified": obj.get("LastModified").isoformat()
                }
            except AttributeError:
                extra = {}

            objects.append(
                dict(
                    name=name,
                    size=size,
                    hash=hash,
                    extra=extra,
                    meta_data=None,
                    container={
                        'name': bucket_name,
                        'id': bucket_id
                    },
                )
            )
        return objects
