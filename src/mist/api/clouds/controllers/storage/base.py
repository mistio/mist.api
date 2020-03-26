import logging
import copy
import json
import time
import datetime
import jsonpatch
import mongoengine.errors

from requests import ConnectionError

import mist.api.exceptions

from mist.api.clouds.utils import LibcloudExceptionHandler
from mist.api.clouds.controllers.base import BaseController

from mist.api.concurrency.models import PeriodicTaskInfo

from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening


log = logging.getLogger(__name__)


class BaseStorageController(BaseController):
    """Abstract base class for volume-specific subcontrollers.

    This base controller factors out all the steps common to all or most
    clouds into a base class, and defines an interface for provider
    or technology specific cloud controllers.

    Subclasses are meant to extend or override methods of this base class to
    account for differences between different cloud types.

    Care should be taken when considering to add new methods to a subclass.
    All controllers should have the same interface, to the degree this is
    feasible. That is to say, don't add a new method to a subclass unless
    there is a very good reason to do so.

    The following convention is followed:

    Any methods and attributes that don't start with an underscore are the
    controller's public API.

    In the `BaseStorageController`, these public methods will contain all steps
    for volume object management which are common to all cloud types.In almost
    all cases, subclasses SHOULD NOT override or extend the public methods of
    `BaseStorageController`. To account for cloud/subclass specific behaviour,
    one is expected to override the internal/private methods of the
    `BaseStorageController`.

    Any methods and attributes that start with an underscore are the
    controller's internal/private API.

    To account for cloud/subclass specific behaviour, the public methods of
    `BaseStorageController` call a number of private methods. These methods
    will always start with an underscore. When an internal method is only ever
    used in the process of one public method, it is prefixed as such to make
    identification and purpose more obvious.

    For each different cloud type, a subclass needs to be defined. To provide
    cloud specific processing, hook the code on the appropriate private method.
    Each method defined here documents its intended purpose and use.
    """
    def list_volumes(self, persist=True):
        """Return list of volumes for cloud

        A list of volumes is fetched from libcloud, data is processed, stored
        on volume models, and a list of volume models is returned.

        Subclasses SHOULD NOT override or extend this method.

        This method wraps `_list_volumes` which contains the core
        implementation.

        """
        task_key = 'cloud:list_volumes:%s' % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        first_run = False if task.last_success else True
        with task.task_runner(persist=persist):
            cached_volumes = {'%s-%s' % (v.id, v.external_id): v.as_dict()
                              for v in self.list_cached_volumes()}

            volumes = self._list_volumes()

        volumes_dict = [v.as_dict() for v in volumes]
        if cached_volumes or volumes:
            # Publish patches to rabbitmq.
            new_volumes = {'%s-%s' % (v['id'], v['external_id']): v
                           for v in volumes_dict}
            patch = jsonpatch.JsonPatch.from_diff(cached_volumes,
                                                  new_volumes).patch
            if patch:
                if not first_run and self.cloud.observation_logs_enabled:
                    from mist.api.logs.methods import log_observations
                    log_observations(self.cloud.owner.id, self.cloud.id,
                                     'volume', patch, cached_volumes,
                                     new_volumes)
                if amqp_owner_listening(self.cloud.owner.id):
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_volumes',
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})
        return volumes

    @LibcloudExceptionHandler(mist.api.exceptions.VolumeListingError)
    def _list_volumes(self):
        """Lists all volumes present on the Cloud.

        Fetches all Volumes via libcloud, applies cloud-specific processing,
        and syncs the state of the database with the state of the Cloud.

        Subclasses SHOULD NOT override or extend this method.


        There are instead a number of methods that are called from this method,
        to allow subclasses to modify the data according to the specific of
        their cloud type. These methods currently are:

            `self._list_volumes__postparse_volume`

        More private methods may be added in the future. Subclasses that
        require special handling should override this, by default, dummy
        method.
        """
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.volumes.models import Volume

        try:
            libcloud_volumes = self._list_volumes__fetch_volumes()
        except ConnectionError as e:
            raise mist.api.exceptions.CloudUnavailableError(e)
        except Exception as exc:
            log.exception("Error while running list_volumes on %s", self.cloud)
            raise mist.api.exceptions.CloudUnavailableError(exc)

        volumes, new_volumes = [], []
        for libcloud_volume in libcloud_volumes:
            try:
                volume = Volume.objects.get(cloud=self.cloud,
                                            external_id=libcloud_volume.id)
            except Volume.DoesNotExist:
                volume = Volume(cloud=self.cloud,
                                external_id=libcloud_volume.id)
                new_volumes.append(volume)

            volume.name = libcloud_volume.name
            volume.size = libcloud_volume.size
            volume.extra = copy.copy(libcloud_volume.extra)
            volume.missing_since = None

            # Apply cloud-specific processing.
            try:
                self._list_volumes__postparse_volume(volume, libcloud_volume)
            except Exception as exc:
                log.exception('Error post-parsing %s: %s', volume, exc)

            # Update with available volume actions.
            try:
                self._list_volumes__volume_actions(volume, libcloud_volume)
            except Exception as exc:
                log.exception("Error while finding volume actions "
                              "for volume %s:%s for %s",
                              volume.id, libcloud_volume.name, self.cloud)

            # Ensure JSON-encoding.
            for key, value in volume.extra.items():
                try:
                    json.dumps(value)
                except TypeError:
                    volume.extra[key] = str(value)

            try:
                volume.save()
            except mongoengine.errors.ValidationError as exc:
                log.error("Error updating %s: %s", volume, exc.to_dict())
                raise mist.api.exceptions.BadRequestError(
                    {"msg": str(exc), "errors": exc.to_dict()}
                )
            except mongoengine.errors.NotUniqueError as exc:
                log.error("Volume %s is not unique: %s", volume.name, exc)
                raise mist.api.exceptions.VolumeExistsError()

            volumes.append(volume)

        # Set missing_since for volumes not returned by libcloud.
        Volume.objects(
            cloud=self.cloud, id__nin=[v.id for v in volumes],
            missing_since=None
        ).update(missing_since=datetime.datetime.utcnow())

        # Update RBAC Mappings given the list of new volumes.
        self.cloud.owner.mapper.update(new_volumes, asynchronous=False)

        return volumes

    def list_cached_volumes(self):
        """Returns volumes stored in database for a specific cloud"""
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.volumes.models import Volume
        return Volume.objects(cloud=self.cloud, missing_since=None)

    def _list_volumes__fetch_volumes(self):
        """Return the original list of libcloud Volume objects"""
        return self.cloud.ctl.compute.connection.list_volumes()

    @LibcloudExceptionHandler(mist.api.exceptions.VolumeCreationError)
    def create_volume(self, **kwargs):
        """Create a new volume.

        This method parses and validates the arguments provided , performs
        the necessary libcloud call, and returns the created volume object
        after invoking `self.list_volumes` to update the db.

        Subclasses SHOULD NOT override or extend this method.

        Instead, there is a private method that is called from this method, to
        allow subclasses to modify the data according to the specific of their
        cloud type. This method currently is:

            `self._create_volume__prepare_args`

        Subclasses that require special handling should override this, by
        default, dummy method. More private methods may be added in the future.

        :param kwargs: A dict of parameters required for volume creation.
        """
        for param in ('size', ):
            if not kwargs.get(param):
                raise mist.api.exceptions.RequiredParameterMissingError(param)

        # Cloud-specific kwargs pre-processing.
        self._create_volume__prepare_args(kwargs)

        # Create the volume.
        try:
            libvol = self.cloud.ctl.compute.connection.create_volume(**kwargs)
        except Exception as exc:
            log.exception('Error creating volume in %s: %r', self.cloud, exc)
            raise mist.api.exceptions.CloudUnavailableError(exc=exc)

        # Invoke `self.list_volumes` to update the UI and return the Volume
        # object at the API. Try 3 times before failing
        for _ in range(3):
            for volume in self.list_volumes():
                # ARM is inconsistent when it comes to lowercase...
                if volume.external_id.lower() == libvol.id.lower():
                    return volume
            time.sleep(5)
        raise mist.api.exceptions.VolumeListingError()

    def _create_volume__prepare_args(self, kwargs):
        """Parses keyword arguments on behalf of `self.create_volume`.

        Creates the parameter structure required by the libcloud method
        that handles volume creation.

        Subclasses MAY override this method.
        """
        return

    def _list_volumes__postparse_volume(self, volume, libcloud_volume):
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

    def _list_volumes__volume_actions(self, volume, libcloud_volume):
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
        volume.actions.tag = True
        if volume.attached_to:
            volume.actions.detach = True
            volume.actions.attach = False
            volume.actions.delete = False
        else:
            volume.actions.attach = True
            volume.actions.delete = True
            volume.actions.detach = False

    @LibcloudExceptionHandler(mist.api.exceptions.VolumeDeletionError)
    def delete_volume(self, volume):
        """Deletes a volume.

        Subclasses SHOULD NOT override or extend this method.

        If a subclass needs to override the way volumes are deleted, it
        should override the private method `_delete_volume` instead.
        """
        assert volume.cloud == self.cloud
        libcloud_volume = self.get_libcloud_volume(volume)
        self._delete_volume(libcloud_volume)
        self.list_volumes()

    def _delete_volume(self, libcloud_volume):
        self.cloud.ctl.compute.connection.destroy_volume(libcloud_volume)

    @LibcloudExceptionHandler(mist.api.exceptions.VolumeAttachmentError)
    def attach_volume(self, volume, machine, **kwargs):
        """Attaches a volume to a node.

        Subclasses SHOULD NOT override or extend this method.

        If a subclass needs to override the way volumes are deleted, it
        should override the private method `_attach_volume` instead.
        """
        assert volume.cloud == self.cloud
        assert machine.cloud == self.cloud
        libcloud_volume = self.get_libcloud_volume(volume)
        libcloud_node = self.cloud.ctl.compute._get_machine_libcloud(machine)
        self._attach_volume(libcloud_volume, libcloud_node, **kwargs)

    def _attach_volume(self, libcloud_volume, libcloud_node, **kwargs):
        self.cloud.ctl.compute.connection.attach_volume(libcloud_node,
                                                        libcloud_volume)
        self.list_volumes()

    @LibcloudExceptionHandler(mist.api.exceptions.VolumeAttachmentError)
    def detach_volume(self, volume, machine):
        """Detaches a volume to a node.

        Subclasses SHOULD NOT override or extend this method.

        If a subclass needs to override the way volumes are deleted, it
        should override the private method `_detach_volume` instead.
        """
        assert volume.cloud == self.cloud
        assert machine.cloud == self.cloud
        libcloud_volume = self.get_libcloud_volume(volume)
        libcloud_node = self.cloud.ctl.compute._get_machine_libcloud(machine)
        self._detach_volume(libcloud_volume, libcloud_node)

    def _detach_volume(self, libcloud_volume, libcloud_node):
        try:
            self.cloud.ctl.compute.connection.detach_volume(
                libcloud_volume, ex_node=libcloud_node)
        except TypeError:
            self.cloud.ctl.compute.connection.detach_volume(libcloud_volume)
        self.list_volumes()

    def get_libcloud_volume(self, volume):
        """Returns an instance of a libcloud volume.

        This method receives a Volume mongoengine object and queries libcloud
        for the corresponding volume instance.

        Subclasses SHOULD NOT override this method.
        """
        volumes = self._list_volumes__fetch_volumes()
        for vol in volumes:
            if vol.id == volume.external_id:
                return vol
        raise mist.api.exceptions.VolumeNotFoundError(
            'Volume %s with external_id %s' % (volume.name, volume.external_id)
        )

    def list_storage_classes(self):
        raise NotImplementedError()
