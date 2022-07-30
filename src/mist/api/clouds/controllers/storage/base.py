import logging
import copy
import json
import time
import datetime
from typing import List
import jsonpatch
import mongoengine.errors
import asyncio
import requests

from requests import ConnectionError

from mist.api import config

import mist.api.exceptions

from mist.api.clouds.utils import LibcloudExceptionHandler
from mist.api.clouds.controllers.base import BaseController

from mist.api.concurrency.models import PeriodicTaskInfo

from mist.api.helpers import get_datetime
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening
from mist.api.helpers import requests_retry_session
from mist.api.helpers import get_victoriametrics_write_uri
from mist.api.helpers import get_victoriametrics_uri


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

            old_volumes = {k: copy.copy(v) for k, v in cached_volumes.items()}

            # Exclude last seen from patch.
            for vd in old_volumes, new_volumes:
                for v in list(vd.values()):
                    v.pop('last_seen')

            patch = jsonpatch.JsonPatch.from_diff(old_volumes,
                                                  new_volumes).patch
            if patch:
                if not first_run and self.cloud.observation_logs_enabled:
                    from mist.api.logs.methods import log_observations
                    log_observations(self.cloud.owner.id, self.cloud.id,
                                     'volume', patch, old_volumes,
                                     new_volumes)
                if amqp_owner_listening(self.cloud.owner.id):
                    amqp_publish_user(self.cloud.owner.id,
                                      routing_key='patch_volumes',
                                      data={'cloud_id': self.cloud.id,
                                            'patch': patch})
        if config.ENABLE_METERING:
            self._update_metering_data(cached_volumes, volumes)

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
        now = datetime.datetime.utcnow()

        for libcloud_volume in libcloud_volumes:
            try:
                volume = Volume.objects.get(cloud=self.cloud,
                                            external_id=libcloud_volume.id)
            except Volume.DoesNotExist:
                volume = Volume(cloud=self.cloud,
                                external_id=libcloud_volume.id)
                volume.first_seen = datetime.datetime.utcnow()
                new_volumes.append(volume)

            volume.name = libcloud_volume.name
            try:
                volume.size = int(libcloud_volume.size)
            except (TypeError, ValueError):
                volume.size = None
            volume.extra = copy.copy(libcloud_volume.extra)
            volume.missing_since = None
            volume.last_seen = now
            try:
                created = self._list_volumes__volume_creation_date(
                    libcloud_volume)
                if created:
                    created = get_datetime(created)
                    if volume.created != created:
                        volume.created = created
            except Exception as exc:
                log.exception("Error finding creation date for %s in %s.\n%r",
                              self.cloud, volume, exc)
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
        ).update(missing_since=now)
        # Set last_seen, unset missing_since on volume models we just saw
        Volume.objects(
            cloud=self.cloud, id__in=[v.id for v in volumes]
        ).update(last_seen=now, missing_since=None)

        # Update RBAC Mappings given the list of new volumes.
        if new_volumes:
            self.cloud.owner.mapper.update(new_volumes, asynchronous=False)

        return volumes

    def list_cached_volumes(self, timedelta=datetime.timedelta(days=1)):
        """Returns volumes stored in database for a specific cloud"""
        # FIXME: Move these imports to the top of the file when circular
        # import issues are resolved
        from mist.api.volumes.models import Volume
        return Volume.objects(
            cloud=self.cloud,
            missing_since=None,
            last_seen__gt=datetime.datetime.utcnow() - timedelta,
        )

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
            raise mist.api.exceptions.VolumeCreationError(exc)

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

    def _list_volumes__volume_creation_date(self, libcloud_volume):
        return libcloud_volume.extra.get('created_at')

    def rename_volume(self, volume, name):
        """Renames a volume.

        Subclasses SHOULD NOT override or extend this method.

        If a subclass needs to override the way volumes are renamed, it
        should override the private method `_rename_volume` instead.
        """
        assert volume.cloud == self.cloud
        libcloud_volume = self.get_libcloud_volume(volume)
        self._rename_volume(libcloud_volume, name)
        self.list_volumes()

    def _rename_volume(self, libcloud_volume, name):
        pass

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
        libcloud_node = self.cloud.ctl.compute._get_libcloud_node(machine)
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
        libcloud_node = self.cloud.ctl.compute._get_libcloud_node(machine)
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

    def list_storage_classes(self) -> List[str]:
        raise NotImplementedError()

    def _update_metering_data(self, cached_volumes, volumes):
        volumes_map = {volume.id: volume for volume in volumes}
        cached_volumes_map = {
            volume["id"]: volume for _, volume in cached_volumes.items()}

        # Generate promql queries to fetch the last metering values
        # of metrics of type counter. This is required in order to calculate
        # the new values of the counter metrics since Prometheus doesn't
        # natively support the ability to increment counter metrics.
        read_queries, metering_metrics = self._generate_metering_queries(
            cached_volumes_map, volumes_map)

        # Fetch the last metering values for counter metrics.
        last_metering_data = self._fetch_metering_data(
            read_queries, volumes_map)

        # Generate Prometheus remote write compatible payload.
        fresh_metering_data = self._generate_fresh_metering_data(
            cached_volumes_map, volumes_map, last_metering_data,
            metering_metrics)

        # Send metrics payload.
        self._send_metering_data(fresh_metering_data)

    def _get_volume_metering_metrics(
            self, volume_id, volumes_map, metering_metrics):
        volume_owner = volumes_map[volume_id].owner.id
        volume_provider = volumes_map[volume_id].cloud.provider

        if metering_metrics.get(volume_owner):
            return metering_metrics[volume_owner]

        if metering_metrics.get(volume_provider):
            return metering_metrics[volume_provider]

        if metering_metrics.get("default"):
            return metering_metrics["default"]

        return {}

    def _populate_metering_metrics_map(self, volumes_map):
        """
        Populates a dict where it maps owner id, cloud provider
        or default to the appropriate metering metrics. This
        helps us later on to choose which metrics we should generate
        for each volume.
        """
        if not config.METERING_METRICS.get("volume"):
            return {}
        metering_metrics = {}
        volume_metrics_properties = config.METERING_METRICS["volume"]
        for volume_id, _ in volumes_map.items():
            volume_owner = volumes_map[volume_id].owner.id
            volume_cloud_provider = volumes_map[volume_id].cloud.provider

            owner_metrics = volume_metrics_properties.get(volume_owner, {})
            provider_metrics = volume_metrics_properties.get(
                volume_cloud_provider, {})
            default_metrics = volume_metrics_properties.get(
                "default", {})

            if owner_metrics and not metering_metrics.get(volume_owner):
                metering_metrics[volume_owner] = default_metrics
                metering_metrics[volume_owner].update(provider_metrics)
                metering_metrics[volume_owner].update(owner_metrics)

            if provider_metrics and not metering_metrics.get(volume_cloud_provider):  # noqa
                metering_metrics[volume_cloud_provider] = default_metrics
                metering_metrics[volume_cloud_provider].update(
                    provider_metrics)

            if default_metrics and not metering_metrics.get("default"):
                metering_metrics["default"] = default_metrics

        return metering_metrics

    def _group_volumes_by_timestamp(self, cached_volumes_map, volumes_map):
        """
        Group the volumes by timestamp
        """
        grouped_volumes_by_dt = {}
        for volume_id, _ in volumes_map.items():
            if not cached_volumes_map.get(volume_id):
                continue
            cached_volume = cached_volumes_map[volume_id]
            dt = None

            # Use either the last_seen or missing_since timestamp
            # to get the last value of the counter
            if cached_volume.get("last_seen"):
                dt = cached_volume["last_seen"]
            elif cached_volume.get("missing_since"):
                dt = cached_volume["missing_since"]

            if not dt:
                continue

            if not grouped_volumes_by_dt.get(dt):
                grouped_volumes_by_dt[dt] = []

            # Group the volumes by timestamp
            grouped_volumes_by_dt[dt].append(volume_id)

        return grouped_volumes_by_dt

    def _group_volumes_by_type(self, volumes_map, grouped_volumes_by_dt):
        """
        Further group down the volumes into metric categories
        (owner id, cloud provider or default). This means that
        queries are grouped by timestamp, metric_category.
        """
        volume_metrics_properties = config.METERING_METRICS["volume"]
        grouped_volumes = {}
        for dt, volume_ids in grouped_volumes_by_dt.items():
            for volume_id in volume_ids:
                volume_owner = volumes_map[volume_id].owner.id
                volume_cloud_provider = volumes_map[volume_id].cloud.provider

                if volume_metrics_properties.get(volume_owner):
                    if not grouped_volumes.get((dt, volume_owner)):
                        grouped_volumes[(dt, volume_owner)] = []

                    grouped_volumes[(dt, volume_owner)].append(volume_id)

                elif volume_metrics_properties.get(volume_cloud_provider):
                    if not grouped_volumes.get((dt, volume_cloud_provider)):
                        grouped_volumes[(dt, volume_cloud_provider)] = []

                    grouped_volumes[(dt, volume_cloud_provider)
                                    ].append(volume_id)

                elif volume_metrics_properties.get("default"):
                    if not grouped_volumes.get((dt, "default")):
                        grouped_volumes[(dt, "default")] = []

                    grouped_volumes[(dt, "default")].append(
                        volume_id)
        return grouped_volumes

    def _generate_metering_queries(self, cached_volumes_map, volumes_map):
        """
        Generate metering promql queries while grouping queries together
        to limit the number of requests to the DB
        """
        if not volumes_map or not config.METERING_METRICS.get("volume"):
            return {}, {}

        metering_metrics = self._populate_metering_metrics_map(volumes_map)

        if not metering_metrics:
            return {}, {}

        grouped_volumes_by_dt = self._group_volumes_by_timestamp(
            cached_volumes_map, volumes_map)

        grouped_volumes = self._group_volumes_by_type(
            volumes_map, grouped_volumes_by_dt)

        # Generate Prometheus queries which fetch metering data for multiple
        # volumes at once when they share the same timestamp and metrics.
        read_queries = {}
        for key, volume_ids in grouped_volumes.items():
            dt, metrics_category = key

            metering_metrics_list = "|".join(
                metric_name
                for metric_name, properties in metering_metrics[
                    metrics_category].items()
                if properties['type'] == "counter")

            volumes_ids_list = "|".join(volume_ids)
            read_queries[(dt, metrics_category)] = (
                f"{{__name__=~\"{metering_metrics_list}\""
                f",org=\"{self.cloud.owner.id}\","
                f"volume_id=~\"{volumes_ids_list}\",metering=\"true\"}}")

        return read_queries, metering_metrics

    def _fetch_query(self, dt, query):
        read_uri = get_victoriametrics_uri(self.cloud.owner)
        dt = int(datetime.datetime.timestamp(
            datetime.datetime.strptime(dt, '%Y-%m-%d %H:%M:%S.%f')))
        error_msg = f"Could not fetch metering data with query: {query}"

        try:
            data = requests_retry_session(retries=1).post(
                f"{read_uri}/api/v1/query",
                data={"query": query, "time": dt},
                timeout=10
            )
        except requests.exceptions.RequestException as e:
            error_details = str(e)
            self._report_metering_error(error_msg, error_details)
            return {}
        if data and not data.ok:
            error_details = (f"code: {data.status_code}"
                             f" response: {data.text}")
            self._report_metering_error(error_msg, error_details)
            return {}

        data = data.json()

        metering_data = {}

        # Parse payload and group metrics data by volume id
        for result in data.get("data", {}).get("result", []):
            metric_name = result["metric"]["__name__"]
            volume_id = result["metric"]["volume_id"]
            value = result["value"][1]

            if not metering_data.get(volume_id):
                metering_data[volume_id] = {}

            metering_data[volume_id].update({metric_name: value})

        return metering_data

    async def _async_fetch_metering_data(self, read_queries, loop):
        metering_data_list = [loop.run_in_executor(
            None, self._fetch_query, key[0], query)
            for key, query in read_queries.items()]

        return await asyncio.gather(*metering_data_list)

    def _fetch_metering_data(self, read_queries, volumes_map):
        if not read_queries or not volumes_map:
            return {}
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError('loop is closed')
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        asyncio.set_event_loop(loop)

        # Fetch queries
        queries_result = loop.run_until_complete(
            self._async_fetch_metering_data(read_queries, loop))
        loop.close()

        # Combine metering data from multiple queries and group it
        # by volume id
        metering_data = {}
        for volume_id, _ in volumes_map.items():
            metering_data[volume_id] = {}

            for query_result in queries_result:
                if not query_result.get(volume_id):
                    continue

                metering_data[volume_id].update(
                    query_result[volume_id])

        return metering_data

    def _find_old_counter_value(self, metric_name, volume_id, properties):
        read_uri = get_victoriametrics_uri(self.cloud.owner)
        query = (
            f"last_over_time("
            f"{metric_name}{{org=\"{self.cloud.owner.id}\""
            f",volume_id=\"{volume_id}\",metering=\"true\""
            f",value_type=\"{properties['type']}\"}}"
            f"[{config.METERING_PROMQL_LOOKBACK}])"
        )
        error_msg = f"Could not fetch old counter value with query: {query}"
        try:
            data = requests_retry_session(retries=1).post(
                f"{read_uri}/api/v1/query", data={"query": query}, timeout=10)
        except requests.exceptions.RequestException as e:
            error_details = str(e)
            self._report_metering_error(error_msg, error_details)
            return None
        if data and not data.ok:
            error_details = f"code: {data.status_code} response: {data.text}"
            self._report_metering_error(error_msg, error_details)
            return None

        data = data.json()
        results = data.get("data", {}).get("result", [])
        if len(results) > 1:
            log.warning("Returned more series than expected")
        if len(results) == 0:
            return 0
        return results[0]["value"][1]

    def _calculate_metering_data(self, volume_id, volume,
                                 new_dt, old_dt, metric_name,
                                 properties, last_metering_data):
        current_value = None
        if properties["type"] == "counter":
            old_value = last_metering_data.get(
                volume_id, {}).get(metric_name)
            if old_value:
                current_value = float(old_value)
                # Calculate the new counter by
                # taking into account the time range
                # between now and the last time the counter
                # was saved. Ignore it in case the volume
                # was missing.
                if old_dt:
                    delta_in_hours = (
                        new_dt - old_dt).total_seconds() / (60 * 60)
                    current_value += properties["value"](
                        volume, delta_in_hours)
            else:
                # When we can't find the last counter value,
                # in order to avoid counter resets, we check
                # again for the last counter up to
                # METERING_PROMQL_LOOKBACK time in the past
                current_value = self._find_old_counter_value(
                    metric_name, volume_id, properties)
        elif properties["type"] == "gauge":
            current_value = properties["value"](volume)
        else:
            log.warning(
                f"Unknown metric type: {properties['type']}"
                f" on metric: {metric_name}"
                f" with volume_id: {volume_id}")
        if current_value is not None:
            return (
                f"{metric_name}{{org=\"{self.cloud.owner.id}\""
                f",volume_id=\"{volume_id}\",metering=\"true\""
                f",value_type=\"{properties['type']}\"}}"
                f" {current_value} "
                f"{int(datetime.datetime.timestamp(new_dt))}\n")
        else:
            log.warning(
                f"None value on metric: "
                f"{metric_name} with volume_id: {volume_id}")
        return ""

    async def _async_generate_fresh_metering_data(self, volumes_map,
                                                  cached_volumes_map,
                                                  metering_metrics,
                                                  last_metering_data, loop):
        metering_data_list = []
        for volume_id, volume in volumes_map.items():
            if not volume.last_seen:
                continue
            new_dt = volume.last_seen
            old_dt = None
            cached_volume = cached_volumes_map.get(volume_id)
            if cached_volume and cached_volume.get("last_seen"):
                old_dt = datetime.datetime.strptime(
                    cached_volume["last_seen"], '%Y-%m-%d %H:%M:%S.%f')
            for metric_name, properties in self._get_volume_metering_metrics(
                    volume_id, volumes_map, metering_metrics).items():
                metering_data_list.append(
                    loop.run_in_executor(None,
                                         self._calculate_metering_data,
                                         volume_id, volume,
                                         new_dt, old_dt, metric_name,
                                         properties, last_metering_data))
        return await asyncio.gather(*metering_data_list)

    def _generate_fresh_metering_data(
            self, cached_volumes_map, volumes_map,
            last_metering_data, metering_metrics):
        if not volumes_map or not metering_metrics:
            return ""

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError('loop is closed')
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        asyncio.set_event_loop(loop)

        # Generate fresh metering data with asyncio
        # to avoid slowdowns. This is required since
        # queries to the timeseries DB may be required.
        metering_data_list = loop.run_until_complete(
            self._async_generate_fresh_metering_data(volumes_map,
                                                     cached_volumes_map,
                                                     metering_metrics,
                                                     last_metering_data,
                                                     loop))
        loop.close()
        return "".join(metering_data_list)

    def _send_metering_data(self, fresh_metering_data):
        if not fresh_metering_data:
            return
        uri = get_victoriametrics_write_uri(self.cloud.owner)
        error_msg = "Could not send metering data"
        result = None
        try:
            result = requests_retry_session(retries=1).post(
                f"{uri}/api/v1/import/prometheus",
                data=fresh_metering_data, timeout=10)
        except requests.exceptions.RequestException as e:
            error_details = str(e)
            self._report_metering_error(error_msg, error_details)
        if result and not result.ok:
            error_details = (f"code: {result.status_code}"
                             f" response: {result.text}")
            self._report_metering_error(error_msg, error_details)

    def _report_metering_error(self, error_msg, error_details):
        from mist.api.methods import notify_admin
        log_entry = error_msg + ", " + error_details
        log.warning(log_entry)
        if not config.METERING_NOTIFICATIONS_WEBHOOK:
            notify_admin(error_msg, message=error_details)
            return
        try:
            response = requests_retry_session(retries=2).post(
                config.METERING_NOTIFICATIONS_WEBHOOK,
                data=json.dumps(
                    {'text': config.PORTAL_URI + ': ' + log_entry}),
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
        except requests.exceptions.RequestException as e:
            log.error(
                'Request to slack returned an error %s'
                % (str(e))
            )
            notify_admin(error_msg, message=error_details)
            return
        if response and response.status_code not in (200, 429):
            log.error(
                'Request to slack returned an error %s, the response is:'
                '\n%s' % (response.status_code, response.text)
            )
            notify_admin(error_msg, message=error_details)
