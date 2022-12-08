"""Definition of base main controllers for clouds

This currently contains only BaseMainController. It includes basic
functionality common to all clouds, such as add, update, rename, disable etc.

The main controller also acts as a gateway to specific controllers. For
example, one may do

    cloud.ctl.enable()
    cloud.ctl.compute.list_machines()

Cloud specific main controllers are in
`mist.api.clouds.controllers.main.controllers`.

"""

import logging
import datetime

import mongoengine as me

from mist.api.exceptions import MistError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import CloudExistsError
from mist.api.exceptions import InternalServerError
from mist.api.exceptions import CloudUnavailableError
from mist.api.exceptions import CloudUnauthorizedError
from mist.api.exceptions import SSLError

from mist.api.helpers import rename_kwargs
from mist.api.clouds.controllers.network.base import BaseNetworkController

from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.container.base import BaseContainerController
from mist.api.clouds.controllers.dns.base import BaseDNSController
from mist.api.clouds.controllers.storage.base import BaseStorageController
from mist.api.clouds.controllers.objectstorage.base import BaseObjectStorageController  # noqa: E501

from mist.api.secrets.models import VaultSecret, SecretValue
from mist.api.secrets.methods import maybe_get_secret_from_arg

from mist.api import config


log = logging.getLogger(__name__)

__all__ = [
    "BaseMainController",
]


class BaseMainController(object):
    """Base main controller class for all cloud types

    BaseMainController defines common cloud operations, such as add, update,
    disable, that mainly affect mist, instead of interacting with the remote
    cloud itself. These operations are mostly the same for all different
    clouds.

    Main controllers act as a gateway to specific controllers. For example, one
    may do

        cloud.ctl.enable()
        cloud.ctl.compute.list_machines()

    For this to work, subclasses must define the appropriate subcontroller
    class, by defining for example a `ComputeController` attribute with a
    subclass of mist.api.clouds.controllers.compute.base.BaseComputeController.

    For specific clouds, main controllers are defined in
    `mist.api.clouds.controllers.main.controllers`.

    Subclasses are meant to extend or override methods of this base class to
    account for differencies between different cloud types.

    Care should be taken when considering to add new methods to a subclass.
    All controllers should have the same interface, to the degree this is
    feasible. That is to say, don't add a new method to a subclass unless
    there is a very good reason to do so.

    Any methods and attributes that don't start with an underscore are the
    controller's public API.

    In the `BaseMainController`, these public methods will in most cases
    contain a basic implementation that works for most clouds, along with the
    proper logging and error handling. In almost all cases, subclasses SHOULD
    NOT override or extend the public methods of `BaseMainController`. To
    account for cloud/subclass specific behaviour, one is expected to override
    the internal/private methods of `BaseMainController`.

    """

    ComputeController = None
    ContainerController = None
    NetworkController = None
    DnsController = None
    StorageController = None
    ObjectStorageController = None

    def __init__(self, cloud):
        """Initialize main cloud controller given a cloud

        Most times one is expected to access a controller from inside the
        cloud, like this:

            cloud = mist.api.clouds.models.Cloud.objects.get(id=cloud_id)
            print cloud.ctl.disable()

        Subclasses SHOULD NOT override this method.

        If a subclass has to initialize a certain instance attribute, it MAY
        extend this method instead.

        """

        self.cloud = cloud
        self._conn = None

        # Initialize compute controller.
        assert issubclass(self.ComputeController, BaseComputeController)
        self.compute = self.ComputeController(self)

        # Initialize container controller.
        if self.ContainerController is not None:
            assert issubclass(self.ContainerController,
                              BaseContainerController)
            self.container = self.ContainerController(self)

        # Initialize DNS controller.
        if self.DnsController is not None:
            assert issubclass(self.DnsController, BaseDNSController)
            self.dns = self.DnsController(self)

        # Initialize network controller.
        if self.NetworkController is not None:
            assert issubclass(self.NetworkController, BaseNetworkController)
            self.network = self.NetworkController(self)

        # Initialize storage controller.
        if self.StorageController is not None:
            assert issubclass(self.StorageController, BaseStorageController)
            self.storage = self.StorageController(self)

        # Initialize Object store controller.
        if self.ObjectStorageController is not None:
            assert issubclass(self.ObjectStorageController,
                              BaseObjectStorageController)
            self.objectstorage = self.ObjectStorageController(self)

    def add(self, user=None, fail_on_error=True, fail_on_invalid_params=True,
            **kwargs):
        """Add new Cloud to the database

        This is only expected to be called by `Cloud.add` classmethod to create
        a cloud. Fields `owner` and `name` are already populated in
        `self.cloud`. The `self.cloud` model is not yet saved.

        Params:
        fail_on_error: If True, then a connection to the cloud will be
            established and if it fails, a `CloudUnavailableError` or
            `CloudUnauthorizedError` will be raised and the cloud will be
            deleted.
        fail_on_invalid_params: If True, then invalid keys in `kwargs` will
            raise an Error.

        Subclasses SHOULD NOT override or extend this method.

        If a subclass has to perform special parsing of `kwargs`, it can
        override `self._add__preparse_kwargs`.

        """
        # Transform params with extra underscores for compatibility.
        rename_kwargs(kwargs, 'api_key', 'apikey')
        rename_kwargs(kwargs, 'api_secret', 'apisecret')
        rename_kwargs(kwargs, 'privateKey', 'private_key')
        rename_kwargs(kwargs, 'projectId', 'project_id')
        rename_kwargs(kwargs, 'tlsKey', 'key_file')
        rename_kwargs(kwargs, 'tlsCert', 'cert_file')
        rename_kwargs(kwargs, 'tlsCaCert', 'ca_cert_file')

        # Cloud specific argument preparsing cloud-wide argument
        self.cloud.dns_enabled = kwargs.pop('dns', False) or \
            kwargs.pop('dns_enabled', False) is True
        self.cloud.object_storage_enabled = kwargs.pop(
            'objectstorage', False) or kwargs.pop(
            'objects_storage', False) or kwargs.pop(
            'object_storage_enabled', False) is True
        self.cloud.container_enabled = kwargs.pop('container', False) or \
            kwargs.pop('container_enabled', False) is True
        self.cloud.observation_logs_enabled = True
        self.cloud.polling_interval = kwargs.pop(
            'polling_interval', config.DEFAULT_CLOUD_POLLING_INTERVAL)

        # Cloud specific kwargs preparsing.
        try:
            self._add__preparse_kwargs(kwargs)
        except MistError as exc:
            log.error("Error while adding cloud %s: %r", self.cloud, exc)
            raise
        except Exception as exc:
            log.exception("Error while preparsing kwargs on add %s",
                          self.cloud)
            raise InternalServerError(exc=exc)

        try:
            self.update(user=user, fail_on_error=fail_on_error,
                        fail_on_invalid_params=fail_on_invalid_params,
                        **kwargs)
        except (CloudUnavailableError, CloudUnauthorizedError) as exc:
            # FIXME: Move this to top of the file once Machine model is
            # migrated.  The import statement is currently here to avoid
            # circular import issues.
            from mist.api.machines.models import Machine
            # Remove any machines created from check_connection performing a
            # list_machines.
            Machine.objects(cloud=self.cloud).delete()
            # Propagate original error.
            raise

        # Add relevant polling schedules.
        self.add_polling_schedules()

    def _add__preparse_kwargs(self, kwargs):
        """Preparse keyword arguments to `self.add`

        This is called by `self.add` when adding a new cloud, in order to apply
        preprocessing to the given params. Any subclass that requires any
        special preprocessing of the params passed to `self.add`, SHOULD
        override this method.

        Params:
        kwargs: A dict of the keyword arguments that will be set as attributes
            to the `Cloud` model instance stored in `self.cloud`. This method
            is expected to modify `kwargs` in place.

        Subclasses MAY override this method.

        """
        return

    def update(self, user=None, fail_on_error=True,
               fail_on_invalid_params=True, **kwargs):
        """Edit an existing Cloud

        Params:
        fail_on_error: If True, then a connection to the cloud will be
            established and if it fails, a `CloudUnavailableError` or
            `CloudUnauthorizedError` will be raised and the cloud changes will
            not be saved.
        fail_on_invalid_params: If True, then invalid keys in `kwargs` will
            raise an Error.

        Subclasses SHOULD NOT override or extend this method.

        If a subclass has to perform special parsing of `kwargs`, it can
        override `self._update__preparse_kwargs`.

        """

        # Close previous connection.
        self.disconnect()

        # Transform params with extra underscores for compatibility.
        rename_kwargs(kwargs, 'api_key', 'apikey')
        rename_kwargs(kwargs, 'api_secret', 'apisecret')

        # Cloud specific kwargs preparsing.
        try:
            self._update__preparse_kwargs(kwargs)
        except MistError as exc:
            log.error("Error while updating cloud %s: %r", self.cloud, exc)
            raise
        except Exception as exc:
            log.exception("Error while preparsing kwargs on update %s",
                          self.cloud)
            raise InternalServerError(exc=exc)

        # Check for invalid `kwargs` keys.
        errors = {}
        for key in list(kwargs.keys()):
            if key not in self.cloud._cloud_specific_fields:
                error = "Invalid parameter %s=%r." % (key, kwargs[key])
                if fail_on_invalid_params:
                    errors[key] = error
                else:
                    log.warning(error)
                    kwargs.pop(key)
        if errors:
            log.error("Error updating %s: %s", self.cloud, errors)
            raise BadRequestError({
                'msg': "Invalid parameters %s." % list(errors.keys()),
                'errors': errors,
            })

        secret = None
        arg_from_vault = False
        # Set fields to cloud model and perform early validation.
        for key, value in kwargs.items():
            if value:  # ignore empty values
                # TODO: In an edge case, where some of the params have been
                # given plain, and some to be obtained from vault, this doesn't
                # ensure that the redundant resource (VaultSecret object) will
                # be deleted
                secret, _key, arg_from_vault = maybe_get_secret_from_arg(value,
                                                                         self.
                                                                         cloud.
                                                                         owner)

                if secret:  # value will be obtained from vault
                    data = secret.data
                    if _key not in data.keys():
                        raise BadRequestError(
                            'The key specified (%s) does not exist in \
                            secret `%s`' % (_key, secret.name))

                    if key in self.cloud._private_fields:
                        secret_value = SecretValue(secret=secret, key=_key)
                        setattr(self.cloud, key, secret_value)
                    else:
                        setattr(self.cloud, key, data[_key])

                else:

                    try:
                        secret = VaultSecret.objects.get(name='%s%s' %
                                                         (config.
                                                          VAULT_CLOUDS_PATH,
                                                          self.cloud.name),
                                                         owner=self.cloud.
                                                         owner)
                        secret.create_or_update({key: value})
                    except me.DoesNotExist:
                        secret = VaultSecret(name='%s%s' %
                                             (config.VAULT_CLOUDS_PATH,
                                              self.cloud.name),
                                             owner=self.cloud.owner)
                        # first store key in Vault
                        secret.create_or_update({key: value})
                        try:
                            secret.save()
                            if user:
                                secret.assign_to(user)
                        except me.NotUniqueError:
                            raise BadRequestError(
                                "The path `%s%s` exists on Vault. \
                                 Try changing the name of the cloud" % (
                                    config.VAULT_CLOUDS_PATH, self.cloud.name)
                            )

                    try:
                        secret.create_or_update({key: value})
                    except Exception as exc:
                        # in case secret is not successfully stored in Vault,
                        # delete it from database as well
                        if not arg_from_vault:
                            secret.delete()
                        raise exc

                    if key in self.cloud._private_fields:
                        secret_value = SecretValue(secret=secret, key=key)
                        setattr(self.cloud, key, secret_value)
                    else:
                        setattr(self.cloud, key, value)
        try:
            self.cloud.validate(clean=True)
        except me.ValidationError as exc:
            log.error("Error updating %s: %s", self.cloud, exc.to_dict())
            # delete VaultSecret object and secret
            # if it was just added to Vault
            if not arg_from_vault and secret:
                secret.delete(delete_from_engine=True)
            raise BadRequestError({'msg': str(exc),
                                   'errors': exc.to_dict()})

        # Try to connect to cloud.
        if fail_on_error:
            try:
                self.compute.check_connection()
            except (CloudUnavailableError, CloudUnauthorizedError,
                    SSLError) as exc:
                log.error("Will not update cloud %s because "
                          "we couldn't connect: %r", self.cloud, exc)
                # delete VaultSecret object and secret
                # if it was just added to Vault
                if not arg_from_vault:
                    secret.delete(delete_from_engine=True)
                raise
            except Exception as exc:
                log.exception("Will not update cloud %s because "
                              "we couldn't connect.", self.cloud)
                # delete VaultSecret object and secret
                # if it was just added to Vault
                if not arg_from_vault:
                    secret.delete(delete_from_engine=True)
                raise CloudUnavailableError(exc=exc)

        # Attempt to save.
        try:
            self.cloud.save()
        except me.ValidationError as exc:
            log.error("Error updating %s: %s", self.cloud, exc.to_dict())
            secret.delete()
            raise BadRequestError({'msg': str(exc),
                                   'errors': exc.to_dict()})
        except me.NotUniqueError as exc:
            log.error("Cloud %s not unique error: %s", self.cloud, exc)
            secret.delete()
            raise CloudExistsError()

        # Execute list_images immediately, addresses flaky edit creds test
        from mist.api.poller.tasks import list_images
        from mist.api.poller.models import ListImagesPollingSchedule
        try:
            schedule_id = str(ListImagesPollingSchedule.objects.get(
                cloud=self.cloud).id)
            list_images.send(schedule_id,)
        except ListImagesPollingSchedule.DoesNotExist:
            pass

        self.add_polling_schedules()

    def _update__preparse_kwargs(self, kwargs):
        """Preparse keyword arguments to `self.update`

        This is called by `self.update` when updating a cloud and it is also
        indirectly called during `self.add`, in order to apply preprocessing to
        the given params. Any subclass that requires any special preprocessing
        of the params passed to `self.update`, SHOULD override this method.

        Params:
        kwargs: A dict of the keyword arguments that will be set as attributes
            to the `Cloud` model instance stored in `self.cloud`. This method
            is expected to modify `kwargs` in place.

        Subclasses MAY override this method.

        """
        return

    def rename(self, name):
        try:
            self.cloud.name = name
            self.cloud.save()
        except me.NotUniqueError:
            raise CloudExistsError()

    def enable(self):
        from mist.api.tasks import delete_periodic_tasks
        delete_periodic_tasks(self.cloud.id)
        self.cloud.enabled = True
        self.cloud.save()
        self.add_polling_schedules()

    def disable(self):
        self.cloud.enabled = False
        self.cloud.save()
        # We schedule a task to set the `missing_since` of resources associated
        # with `self.cloud` with a small delay. Since the poller syncs with the
        # db every 20 sec, there is a good chance that the poller will not pick
        # up the change to `self.cloud.enabled` in time to stop scheduling
        # further polling tasks. This may result in `missing_since` being reset
        # to `None`. For that, we schedule a task in the future to ensure that
        # dramatiq has executed all respective poller tasks first.
        from mist.api.tasks import set_missing_since, delete_periodic_tasks
        set_missing_since.send_with_options(
            args=(self.cloud.id, ), delay=30_000)
        delete_periodic_tasks.send_with_options(
            args=(self.cloud.id, ), delay=30_000)

    def dns_enable(self):
        self.cloud.dns_enabled = True
        self.cloud.save()

    def dns_disable(self):
        self.cloud.dns_enabled = False
        self.cloud.save()

    def container_enable(self):
        self.cloud.container_enabled = True
        self.cloud.save()

    def container_disable(self):
        self.cloud.container_enabled = False
        self.cloud.save()

    def object_storage_enable(self):
        from mist.api.poller.models import ListBucketsPollingSchedule
        self.cloud.object_storage_enabled = True
        self.cloud.save()
        if hasattr(self.cloud.ctl, 'objectstorage'):
            schedule = ListBucketsPollingSchedule.add(
                cloud=self.cloud, run_immediately=True)
            schedule.set_default_interval(60 * 60 * 24)
            schedule.save()

    def object_storage_disable(self):
        self.cloud.object_storage_enabled = False
        self.cloud.save()

    def observation_logs_enable(self):
        self.cloud.observation_logs_enabled = True
        self.cloud.save()

    def observation_logs_disable(self):
        self.cloud.observation_logs_enabled = False
        self.cloud.save()

    def set_polling_interval(self, interval):
        if not isinstance(interval, int):
            raise BadRequestError("Invalid interval type: %r" % interval)
        if interval != 0 and not 600 <= interval <= 3600 * 12:
            raise BadRequestError("Interval must be at least 10 mins "
                                  "and at most 12 hours.")
        self.cloud.polling_interval = interval
        self.cloud.save()

    def add_polling_schedules(self):
        """Add all the relevant cloud polling schedules

        This method simply adds all relevant polling schedules and sets
        their default settings. See the `mist.api.tasks.update_poller`
        task for dynamically adding new polling schedules or updating
        existing ones.

        """

        # FIXME Imported here due to circular dependency issues.
        from mist.api.poller.models import ListMachinesPollingSchedule
        from mist.api.poller.models import ListLocationsPollingSchedule
        from mist.api.poller.models import ListSizesPollingSchedule
        from mist.api.poller.models import ListImagesPollingSchedule
        from mist.api.poller.models import ListNetworksPollingSchedule
        from mist.api.poller.models import ListZonesPollingSchedule
        from mist.api.poller.models import ListVolumesPollingSchedule
        from mist.api.poller.models import ListBucketsPollingSchedule
        from mist.api.poller.models import ListClustersPollingSchedule

        # Add machines' polling schedule.
        ListMachinesPollingSchedule.add(
            cloud=self.cloud, run_immediately=True)

        # Add networks' polling schedule, if applicable.
        if hasattr(self.cloud.ctl, 'network'):
            ListNetworksPollingSchedule.add(
                cloud=self.cloud, run_immediately=True)

        # Add zones' polling schedule, if applicable.
        if hasattr(self.cloud.ctl, 'dns') and self.cloud.dns_enabled:
            ListZonesPollingSchedule.add(
                cloud=self.cloud, run_immediately=True)

        # Add volumes' polling schedule, if applicable.
        if hasattr(self.cloud.ctl, 'storage'):
            ListVolumesPollingSchedule.add(
                cloud=self.cloud, run_immediately=True)

        # Add containers' polling schedule, if applicable.
        if hasattr(self.cloud.ctl, 'container') and \
                self.cloud.container_enabled:
            ListClustersPollingSchedule.add(
                cloud=self.cloud, run_immediately=True)

        if hasattr(self.cloud.ctl, 'objectstorage') and \
                self.cloud.object_storage_enabled:
            schedule = ListBucketsPollingSchedule.add(
                cloud=self.cloud, run_immediately=True)
            schedule.set_default_interval(60 * 60 * 24)
            schedule.save()

        # Add extra cloud-level polling schedules with lower frequency. Such
        # schedules poll resources that should hardly ever change. Thus, we
        # add the schedules, increase their interval, and forget about them.
        schedule = ListLocationsPollingSchedule.add(
            cloud=self.cloud, run_immediately=True)
        schedule.set_default_interval(60 * 60 * 24)
        schedule.add_interval(90, ttl=270)
        schedule.save()

        schedule = ListSizesPollingSchedule.add(
            cloud=self.cloud, run_immediately=True)
        schedule.set_default_interval(60 * 60 * 24)
        schedule.add_interval(90, ttl=270)
        schedule.save()

        schedule = ListImagesPollingSchedule.add(
            cloud=self.cloud, run_immediately=True)
        schedule.set_default_interval(60 * 60 * 24)
        schedule.add_interval(90, ttl=270)
        schedule.save()

    def delete(self, expire=False):
        """Delete a Cloud.

        By default the corresponding mongodb document is not actually deleted,
        but rather marked as deleted.

        :param expire: if True, the document is expired from its collection.

        """
        if expire:
            # FIXME: Set reverse_delete_rule=me.CASCADE?
            from mist.api.machines.models import Machine
            Machine.objects(cloud=self.cloud).delete()
            self.cloud.delete()
        else:
            from mist.api.tasks import set_missing_since
            self.cloud.deleted = datetime.datetime.utcnow()
            self.cloud.save()
            set_missing_since.send_with_options(
                args=(self.cloud.id, ), delay=30_000)

    def disconnect(self):
        self.compute.disconnect()

    def add_machine(self, **kwargs):
        """
        Add a machine in a bare metal cloud.
        This is only supported on Other Server clouds.
        """
        raise BadRequestError("Adding machines is only supported in Bare"
                              "Metal and KVM/Libvirt clouds.")

    def _get_provider_dict(self):
        provider_dict = None
        try:
            provider_dict = config.PROVIDERS[self.provider]
        except KeyError:
            for value in config.PROVIDERS.values():
                if self.provider == value['driver']:
                    provider_dict = value
                    break
            if not provider_dict:
                raise KeyError('Provider does not exist') from None
        return provider_dict

    def has_feature(self, feature):
        """Check whether a certain feature is supported by cloud

        List of features:
            dns
            networks
            storage
            console
            custom_size
            custom_image
            cloudinit
            location
            key
            size-image-restriction
            location-size-restriction
            location-image-restriction
            container-service
            kubernetes
        """
        provider_dict = self._get_provider_dict()
        has_feature = False
        if feature in ['dns', 'networks', 'storage', 'console']:
            has_feature = provider_dict['features'].get(feature, False)
        elif feature == 'key' and provider_dict['features']['provision']:
            has_feature = provider_dict['features']['provision'].get(feature, True)  # noqa
            # if dictionary is returned key is supported but not required
        elif feature in ['size-image-restriction', 'location-size-restriction', 'location-image-restriction']:  # noqa
            try:
                has_feature = provider_dict['features']['provision']['restrictions'].get(feature, False)  # noqa
            except (KeyError, TypeError):
                return False
        elif feature in ['container-service', 'kubernetes']:
            try:
                has_feature = provider_dict['features']['container'][feature]
            except (KeyError, TypeError):
                return False
        else:
            if provider_dict['features']['provision']:
                has_feature = provider_dict['features']['provision'].get(feature, False)  # noqa

        return has_feature

    def get_resource_cost(self, resource):
        """Get cost for the given resource.

        Supported resources:
            kubernetes-control-plane

        Returns:
            Tuple of cost per hour and cost per month
        """
        provider_dict = self._get_provider_dict()
        if resource == 'kubernetes-control-plane':
            try:
                hourly = provider_dict['cost'][resource]['cph']
            except (KeyError, TypeError):
                hourly = 0
            try:
                monthly = provider_dict['cost'][resource]['cpm']
            except (KeyError, TypeError):
                monthly = 0

            if hourly and not monthly:
                monthly = hourly * 24 * 30
            if monthly and not hourly:
                hourly = monthly / 24 / 30

        return hourly, monthly
