import copy
import logging
import jsonpatch
import datetime
import mist.api.exceptions
import json
import mongoengine.errors


from mist.api.clouds.controllers.base import BaseController
from mist.api.concurrency.models import PeriodicTaskInfo

from mist.api.helpers import objectstorage_to_dict
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening

log = logging.getLogger(__name__)


# TODO check comments to replace volume -> storage


class BaseObjectStorageController(BaseController):

    def list_storage(self, persist=True):
        """Return list of volumes for cloud

        A list of volumes is fetched from libcloud, data is processed, stored
        on volume models, and a list of volume models is returned.

        Subclasses SHOULD NOT override or extend this method.

        This method wraps `_list_volumes` which contains the core
        implementation.

        """

        task_key = 'cloud:list_object_storage:%s' % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        first_run = False if task.last_success else True
        with task.task_runner(persist=persist):
            cached_storage = {'%s-%s' % (s.id, s.name): s.as_dict()
                              for s in self.list_cached_storage()}

            storage = self._list_storage()

        storage_dict = [s.as_dict() for s in storage]
        if cached_storage or storage:
            # Publish patches to rabbitmq.
            new_storage = {'%s-%s' % (s['id'], s['name']): s
                           for s in storage_dict}
            patch = jsonpatch.JsonPatch.from_diff(cached_storage,
                                                  new_storage).patch
            if patch:
                if not first_run and self.cloud.observation_logs_enabled:
                    from mist.api.logs.methods import log_observations
                    log_observations(self.cloud.owner.id, self.cloud.id,
                                     'objectstorage', patch, cached_storage,
                                     new_storage)
                if amqp_owner_listening(self.cloud.owner.id):
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_objectstorage',
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})
        return storage

    def _list_storage(self):
        """Lists all volumes present on the Cloud.

        Fetches all Volumes via libcloud, applies cloud-specific processing,
        and syncs the state of the database with the state of the Cloud.

        Subclasses SHOULD NOT override or extend this method.


        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specific of
        their cloud type. These methods currently are:

            `self._list_volumes__postparse_storage`
            `self._list_storage__fetch_storage_content`

        More private methods may be added in the future. Subclasses that
        require special handling should override this, by default, dummy
        method.
        """
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.objectstorage.models import ObjectStorage

        try:
            libcloud_storage = self._list_storage__fetch_storage()
        except ConnectionError as e:
            raise mist.api.exceptions.CloudUnavailableError(e)
        except Exception as exc:
            log.exception("Error while running list_storages on %s", self.cloud)
            raise mist.api.exceptions.CloudUnavailableError(exc)

        storage, new_storage = [], []
        for libcloud_store in libcloud_storage:
            try:
                store = ObjectStorage.objects.get(cloud=self.cloud,
                                                  name=libcloud_store.name)
            except ObjectStorage.DoesNotExist:
                store = ObjectStorage(cloud=self.cloud,
                                      name=libcloud_store.name)
                new_storage.append(store)

            store.extra = copy.copy(libcloud_store.extra)

            # Attach storage content
            content = self._list_storage__fetch_storage_content(libcloud_store)

            self._list_storage__append_content(store, content)

            log.error('CONTENT %s', content)

            store.content = content


            # Apply cloud-specific processing.
            try:
                self._list_storage__postparse_store(store, libcloud_store)
            except Exception as exc:
                log.exception('Error post-parsing %s: %s', store, exc)


            # Ensure JSON-encoding.
            for key, value in store.extra.items():
                try:
                    json.dumps(value)
                except TypeError:
                    store.extra[key] = str(value)

            try:
                store.save()
            except mongoengine.errors.ValidationError as exc:
                log.error("Error updating %s: %s", store, exc.to_dict())
                raise mist.api.exceptions.BadRequestError(
                    {"msg": str(exc), "errors": exc.to_dict()}
                )
            except mongoengine.errors.NotUniqueError as exc:
                log.error("Volume %s is not unique: %s", store.name, exc)
                raise mist.api.exceptions.VolumeExistsError()

            storage.append(store)

        # Set missing_since for object storage not returned by libcloud.
        ObjectStorage.objects(
            cloud=self.cloud, name__nin=[s.name for s in storage],
            missing_since=None
        ).update(missing_since=datetime.datetime.utcnow())
        ObjectStorage.objects(
            cloud=self.cloud, id__in=[s.name for s in storage]
        ).update(missing_since=None)


        # Update RBAC Mappings given the list of new storage.
        self.cloud.owner.mapper.update(new_storage, asynchronous=False)

        return storage

    def _list_storage__fetch_storage(self):
        """Perform the actual libcloud call to get list of nodes"""
        return self.connection.list_containers()


    def _list_storage__fetch_storage_content(self, storage, path=''):
        """Perform the actual libcloud call to get the content of the node"""
        return [objectstorage_to_dict(store_content)
                for store_content in self.connection.list_container_objects(storage, path)]


    def list_cached_storage(self):
        """Returns volumes stored in database for a specific cloud"""
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.objectstorage.models import ObjectStorage
        return ObjectStorage.objects(cloud=self.cloud, missing_since=None)


    def list_storage_content(self, name):
        container = self.connection.get_container(name)
        content = self.connection.list_container_objects(container, '')

        objects = {}

        for obj in content:
            objects[obj.name] = objectstorage_to_dict(obj)

        return objects

    def create_storage(self, name):
        return self.connection.create_container(name)

    def delete_storage(self, name):
        container = self.connection.get_container(name)
        return self.connection.delete_container(container)

    def _list_storage__postparse_store(self, store, libcloud_store):
        #TODO
        """Parses a libcloud volume object on behalf of `self._list_volumes`.

        Any subclass that needs to perform custom parsing of a volume object
        returned by libcloud SHOULD override this private method.

        This method is expected to edit the volume objects in place and not
        return anything.

        Subclasses MAY override this method.

        :param volume: A volume mongoengine model. The model may not have yet
                        been saved in the database.
        :param libcloud_volume: A libcloud volume object.
        """
        return

    def _list_storage__append_content(self, store, content):
        #TODO
        """Add metadata on the volume dict on the allowed actions

        Any subclass that wishes to specially handle its allowed actions, can
        implement this internal method.

        volume: A volume mongoengine model. The model may not have yet
            been saved in the database.
        libcloud_volume: An instance of a libcloud volume, as
            returned by libcloud's list_volumes.
        This method is expected to edit `volume` in place and not return
        anything.

        Subclasses MAY extend this method.
        """
        from mist.api.objectstorage.models import ObjectStorageItem
        for item in content:
            log.error('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA %s', item)
            store.content.append(ObjectStorageItem(item))




