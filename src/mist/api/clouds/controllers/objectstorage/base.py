import logging
import jsonpatch
import datetime
import mist.api.exceptions
import mongoengine.errors

from mist.api.clouds.controllers.base import BaseController
from mist.api.concurrency.models import PeriodicTaskInfo

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
            provider_buckets = self._list_buckets__fetch_buckets()
        except ConnectionError as e:
            raise mist.api.exceptions.CloudUnavailableError(e)
        except Exception as exc:
            log.exception("Error while running list_buckets on %s",
                          self.cloud)
            raise mist.api.exceptions.CloudUnavailableError(exc)

        buckets, new_buckets = [], []
        for provider_bucket in provider_buckets:
            try:
                bucket = Bucket.objects.get(
                    cloud=self.cloud,
                    name=provider_bucket.name)
            except Bucket.DoesNotExist:
                bucket = Bucket(
                    cloud=self.cloud,
                    name=provider_bucket.name,
                    extra=provider_bucket.extra
                )
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

                new_buckets.append(bucket)

            # Apply cloud-specific processing.
            try:
                self._list_buckets__postparse_bucket(bucket, provider_bucket)
            except Exception as exc:
                log.exception('Error post-parsing %s: %s', bucket, exc)

            buckets.append(bucket)
        now = datetime.datetime.utcnow()
        # Set missing_since for buckets returned by libcloud.
        Bucket.objects(
            cloud=self.cloud, name__nin=[b.name for b in buckets],
            missing_since=None
        ).update(
            missing_since=datetime.datetime.utcnow(),
            content=[]
        )
        Bucket.objects(
            cloud=self.cloud, name__in=[b.name for b in buckets]
        ).update(
            missing_since=None,
            content=[]
        )

        # Update RBAC Mappings given the list of new storage.
        if new_buckets:
            self.cloud.owner.mapper.update(new_buckets, asynchronous=False)

        return buckets

    def _list_buckets__fetch_buckets(self):
        """Perform the actual API call to get list of buckets"""
        raise NotImplementedError

    def _list_buckets__fetch_bucket_content(self, name, prefix='',
                                            delimiter='',
                                            maxkeys=100):
        """Perform the actual API call to get the content of the bucket"""
        raise NotImplementedError

    def list_bucket_content(self, name, path, bucket_id,
                            delimiter='', maxkeys=100):
        """
        Performs the  API call to list bucket content.
        :param name: The bucket's name
        :type name: str

        :param path: The bucket path to show. In each call the response will
                     include the current level and NOT deeper levels.
        :type path: str

        :param delimiter: The character that defines the tree-like structure.
                          By default forward slash /
        :type delimiter: str

        :param maxkeys:   Sets the maximum number of keys returned in the
                          response. By default the action returns up to 1,000
                          key names. The response might contain fewer keys but
                          will never contain more.
        :type maxkeys: int
        """

        if not delimiter:
            delimiter = '/'  # Default delim is fwd slash
        # path should be of the form lvl/lvl2/..
        if path:
            # ensure prefix ends with delim,
            prefix = path.rstrip(delimiter) + delimiter
        else:
            # Don't add delim in case path='' (root)
            prefix = path

        return [obj for obj in self._list_buckets__fetch_bucket_content(
            name=name, bucket_id=bucket_id, prefix=prefix,
            delimiter=delimiter, maxkeys=maxkeys)
            if obj['name'] != prefix]

    def list_cached_buckets(self):
        """Returns storage stored in database for a specific cloud"""
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.objectstorage.models import Bucket
        return Bucket.objects(cloud=self.cloud, missing_since=None)

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
