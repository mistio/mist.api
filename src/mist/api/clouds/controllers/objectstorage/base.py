import copy
import logging
import jsonpatch
import datetime
import mist.api.exceptions
import json
import mongoengine.errors

from libcloud.common.types import LibcloudError
from mist.api.clouds.controllers.base import BaseController
from mist.api.concurrency.models import PeriodicTaskInfo

from mist.api.helpers import bucket_to_dict
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening

log = logging.getLogger(__name__)


class BaseObjectStorageController(BaseController):

    def list_buckets(self, persist=True):
        """Return list of buckets for cloud

        A list of buckets is fetched from libcloud, data is processed, stored
        on bucket models, and a list of bucket models is returned.

        Subclasses SHOULD NOT override or extend this method.

        This method wraps `_list_buckets` which contains the core
        implementation.

        """

        task_key = 'cloud:list_buckets:%s' % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        first_run = False if task.last_success else True
        with task.task_runner(persist=persist):
            cached_buckets = {'%s-%s' % (s.id, s.name): s.as_dict()
                              for s in self.list_cached_buckets()}

        buckets = self._list_buckets()

        buckets_dict = [b.as_dict() for b in buckets]
        if cached_buckets or buckets:
            # Publish patches to rabbitmq.
            new_buckets = {'%s-%s' % (s['id'], s['name']): s
                           for s in buckets_dict}
            patch = jsonpatch.JsonPatch.from_diff(cached_buckets,
                                                  new_buckets).patch
            if patch:
                if not first_run and self.cloud.observation_logs_enabled:
                    from mist.api.logs.methods import log_observations
                    log_observations(self.cloud.owner.id, self.cloud.id,
                                     'buckets', patch, cached_buckets,
                                     new_buckets)
                if amqp_owner_listening(self.cloud.owner.id):
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_buckets',
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})
        return buckets

    def _list_buckets(self):
        """Lists all buckets present on the Cloud.

        Fetches all Buckets via libcloud, applies
        cloud-specific processing, and syncs the state of the database
        with the state of the Cloud.

        Subclasses SHOULD NOT override or extend this method.


        There are instead a number of methods that are called
        from this method, to allow subclasses to modify
        the data according to the specific of their cloud type.
        These methods currently are:

            `self._list_buckets__fetch_buckets`
            `self._list_buckets__fetch_bucket_content`
            `self._list_buckets__append_content`
            `self._list_buckets__postparse_store`

        More private methods may be added in the future. Subclasses that
        require special handling should override this, by default, dummy
        method.
        """
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.objectstorage.models import Bucket

        try:
            libcloud_buckets = self._list_buckets__fetch_buckets()
        except ConnectionError as e:
            raise mist.api.exceptions.CloudUnavailableError(e)
        except Exception as exc:
            log.exception("Error while running list_buckets on %s",
                          self.cloud)
            raise mist.api.exceptions.CloudUnavailableError(exc)

        buckets, new_buckets = [], []
        for libcloud_bucket in libcloud_buckets:
            try:
                bucket = Bucket.objects.get(
                    cloud=self.cloud,
                    name=libcloud_bucket.name)
            except Bucket.DoesNotExist:
                bucket = Bucket(
                    cloud=self.cloud,
                    name=libcloud_bucket.name)
                new_buckets.append(bucket)

            bucket.extra = copy.copy(libcloud_bucket.extra)

            # Attach bucket content
            try:
                """
                self._list_buckets__fetch_bucket returns all buckets
                regardless their location whereas
                self._list_buckets__fetch_bucket_content throws
                an error when the location of the bucket
                does not match the connection location. So skip this bucket
                and do not show it in the list of the buckets
                """
                content = self._list_buckets__fetch_bucket_content(
                    libcloud_bucket)
                self._list_buckets__append_content(bucket, content)

            except LibcloudError:
                continue

            # Apply cloud-specific processing.
            try:
                self._list_buckets__postparse_bucket(bucket, libcloud_bucket)
            except Exception as exc:
                log.exception('Error post-parsing %s: %s', bucket, exc)

            # Ensure JSON-encoding.
            for key, value in bucket.extra.items():
                try:
                    json.dumps(value)
                except TypeError:
                    bucket.extra[key] = str(value)

            try:
                bucket.save()
            except mongoengine.errors.ValidationError as exc:
                log.error("Error updating %s: %s", bucket, exc.to_dict())
                raise mist.api.exceptions.BadRequestError(
                    {"msg": str(exc), "errors": exc.to_dict()}
                )
            except mongoengine.errors.NotUniqueError as exc:
                log.error("Bucket %s is not unique: %s", bucket.name, exc)
                raise mist.api.exceptions.BucketExistsError()

            buckets.append(bucket)

        # Set missing_since for buckets returned by libcloud.
        Bucket.objects(
            cloud=self.cloud, name__nin=[b.name for b in buckets],
            missing_since=None
        ).update(missing_since=datetime.datetime.utcnow())
        Bucket.objects(
            cloud=self.cloud, id__in=[b.name for b in buckets]
        ).update(missing_since=None)

        # Update RBAC Mappings given the list of new storage.
        self.cloud.owner.mapper.update(new_buckets, asynchronous=False)

        return buckets

    def _list_buckets__fetch_buckets(self):
        """Perform the actual libcloud call to get list of nodes"""
        return self.connection.list_containers()

    def _list_buckets__fetch_bucket_content(self, bucket, path=''):
        """Perform the actual libcloud call to get the content of the node"""
        return [bucket_to_dict(bucket_content)
                for bucket_content in self.connection.list_container_objects(
                    bucket,
                    path)]

    def list_cached_buckets(self):
        """Returns storage stored in database for a specific cloud"""
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.objectstorage.models import Bucket
        return Bucket.objects(cloud=self.cloud, missing_since=None)

    def list_bucket_content(self, name, path):
        container = self.connection.get_container(name)
        return self._list_buckets__fetch_bucket_content(container, path)

    def _list_buckets__postparse_bucket(self, bucket, libcloud_bucket):
        """Parses a libcloud storage object on behalf of `self._list_storage`.

        Any subclass that needs to perform custom parsing of a storage object
        returned by libcloud SHOULD override this private method.

        This method is expected to edit the storage objects in place and not
        return anything.

        Subclasses MAY override this method.

        :param bucket: A bucket mongoengine model. The model may not have yet
                        been saved in the database.
        :param libcloud_bucket: A libcloud bucket object.
        """
        return

    def _list_buckets__append_content(self, bucket, content):
        """Add bucket content to the bucket dict

        Any subclass that wishes to specially handle its allowed actions, can
        implement this internal method.

        store: A storage mongoengine model. The model may not have yet
            been saved in the database.
        content: A list of a libcloud storage content, as
            returned by libcloud's list_container_objects.
        This method is expected to edit `store` in place and not return
        anything.

        Subclasses MAY extend this method.
        """
        from mist.api.objectstorage.models import BucketItem

        bucket.content = [BucketItem(**item) for item in content]
