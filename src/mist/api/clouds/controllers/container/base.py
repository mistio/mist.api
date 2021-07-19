"""Definition of base container controllers.

It contains functionality concerning the management of containers and related
objects, e.g. clusters, that are common among different cloud providers.
"""
import copy
import json
import ssl
import logging
import datetime
import requests

from bson import json_util

import jsonpatch

import mongoengine as me

from libcloud.common.types import InvalidCredsError

from mist.api import config

from mist.api.exceptions import ConflictError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import CloudUnavailableError
from mist.api.exceptions import CloudUnauthorizedError
from mist.api.exceptions import SSLError

from mist.api.helpers import get_datetime
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening

from mist.api.concurrency.models import PeriodicTaskInfo
from mist.api.concurrency.models import PeriodicTaskThresholdExceeded

from mist.api.clouds.controllers.base import BaseController

log = logging.getLogger(__name__)

__all__ = ["BaseContainerController"]


def _update_cluster_from_dict_in_process_pool(params):
    from mist.api.clouds.models import Cloud

    cloud_id = params["cloud_id"]
    now = params["now"]
    locations_map = params["locations_map"]
    cluster_dict = params["cluster_dict"]
    cloud = Cloud.objects.get(id=cloud_id)
    return cloud.ctl.container._update_cluster_from_dict(
        cluster_dict, locations_map, now
    )


class BaseContainerController(BaseController):
    """Abstract base class for clouds that provide container features."""

    def list_cached_clusters(self, timedelta=datetime.timedelta(days=1)):
        """Return list of clusters from database

        Only returns clusters that existed last time we checked and we've seen
        during the last `timedelta`.
        """
        from mist.api.containers.models import Cluster

        return Cluster.objects(
            cloud=self.cloud,
            missing_since=None,
            last_seen__gt=datetime.datetime.utcnow() - timedelta,
        )

    def list_clusters(self, persist=True):
        """Return list of clusters for the cloud

        A list of clusters is fetched from libcloud, the data is processed,
        stored on cluster models, and a list of cluster models is returned.

        Subclasses SHOULD NOT override or extend this method.

        This method wraps `_list_clusters` which contains the core
        implementation.

        """
        task_key = "cloud:list_clusters:%s" % self.cloud.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        first_run = False if task.last_success else True
        try:
            with task.task_runner(persist=persist):
                cached_clusters = [
                    m.as_dict() for m in self.list_cached_clusters()]
                clusters = self._list_clusters()
        except PeriodicTaskThresholdExceeded:
            self.cloud.ctl.disable()
            raise
        # self.produce_and_publish_patch(cached_clusters, clusters, first_run)
        return clusters

    def produce_and_publish_patch(
        self, cached_clusters, fresh_clusters, first_run=False
    ):
        old_clusters = {
            "%s-%s" % (c["id"], c["external_id"]): c for c in cached_clusters
        }
        new_clusters = {
            "%s-%s" % (c.id, c.external_id): c.as_dict()
            for c in fresh_clusters
        }
        # Exclude last seen and probe fields from patch.
        for cd in old_clusters, new_clusters:
            for c in list(cd.values()):
                c.pop("last_seen")
        patch = jsonpatch.JsonPatch.from_diff(old_clusters, new_clusters).patch
        if patch:  # Publish patches to rabbitmq.
            if not first_run and self.cloud.observation_logs_enabled:
                from mist.api.logs.methods import log_observations

                log_observations(
                    self.cloud.owner.id,
                    self.cloud.id,
                    "cluster",
                    patch,
                    old_clusters,
                    new_clusters,
                )
            if amqp_owner_listening(self.cloud.owner.id):
                amqp_publish_user(
                    self.cloud.owner.id,
                    routing_key="patch_clusters",
                    data={"cloud_id": self.cloud.id, "patch": patch},
                )

    def _list_clusters__fetch_clusters(self):
        """Perform the actual libcloud call to get list of clusters"""
        return self.connection.list_clusters()

    def _list_clusters__get_location(self, cluster_dict):
        """Find location code name/identifier from libcloud data

        This is to be called exclusively by `self._list_clusters`.

        Subclasses MAY override this method.
        """
        return cluster_dict['location']

    def _list_clusters__get_cluster_extra(self, cluster, cluster_dict):
        """Return extra dict for libcloud cluster

        Subclasses can override/extend this method if they wish to filter or
        inject extra metadata.
        """
        return copy.copy(cluster_dict["extra"])

    def _list_clusters__cluster_creation_date(self, cluster, cluster_dict):
        return cluster_dict.get("created_at")

    def _list_clusters__cluster_actions(self, cluster, cluster_dict):
        """Add metadata on the cluster dict on the allowed actions

        Any subclass that wishes to specially handle its allowed actions, can
        implement this internal method.

        cluster: A cluster mongoengine model. The model may not have yet
            been saved in the database.
        cluster_dict: An instance of a libcloud container driver cluster dict

        This method is expected to edit `cluster` in place and not return
        anything.

        Subclasses MAY extend this method.
        """
        # Defaults for running state and common clouds.
        cluster.actions.create = True
        cluster.actions.destroy = True

    def _list_clusters__postparse_cluster(self, cluster, cluster_dict):
        """Post parse a cluster before returning it in list_clusters

        Any subclass that wishes to specially handle its cloud's tags and
        metadata, can implement this internal method.

        cluster: A cluster mongoengine model. The model may not have yet
            been saved in the database.
        cluster_dict: A libcloud container driver cluster dict

        This method is expected to edit its arguments in place and return
        True if any updates have been made.

        Subclasses MAY override this method.

        """
        updated = False
        return updated

    def _update_cluster_from_dict(self, cluster_dict, locations_map, now):
        is_new = False
        updated = False
        # Fetch cluster mongoengine model from db, or initialize one.
        from mist.api.containers.models import Cluster
        try:
            cluster = Cluster.objects.get(
                cloud=self.cloud, external_id=cluster_dict["id"]
            )
        except Cluster.DoesNotExist:
            cluster = Cluster(cloud=self.cloud,
                              external_id=cluster_dict["id"])
            try:
                cluster.save()
            except me.ValidationError as exc:
                log.warn("Validation error when saving new cluster: %r" % exc)
                return None, is_new
            is_new = True
        # Discover location of cluster.
        try:
            location_id = self._list_clusters__get_location(cluster_dict)
        except Exception as exc:
            log.error("Error getting location of %s: %r", cluster, exc)
        else:
            if cluster.location != locations_map.get(location_id):
                cluster.location = locations_map.get(location_id)
                updated = True
        if cluster.name != cluster_dict['name']:
            cluster.name = cluster_dict['name']
            updated = True
        cluster_state = cluster_dict.get('status')
        config_state = config.CLUSTER_STATES.get(cluster_state)
        if cluster_state and config_state and cluster.state != config_state:
            cluster.state = config_state
            updated = True
        # Set cluster extra dict.
        # Make sure we don't meet any surprises when we try to json encode
        # later on in the HTTP response.
        extra = self._list_clusters__get_cluster_extra(cluster, cluster_dict)
        for key, val in list(extra.items()):
            try:
                json.dumps(val)
            except TypeError:
                extra[key] = str(val)
        # save extra.tags as dict
        if extra.get("tags") and isinstance(extra.get("tags"), list):
            extra["tags"] = dict.fromkeys(extra["tags"], "")
        # perform tag validation to prevent ValidationError
        # on cluster.save()
        if extra.get("tags") and isinstance(extra.get("tags"), dict):
            validated_tags = {}
            for tag in extra["tags"]:
                if not (("." in tag) or ("$" in tag)):
                    validated_tags[tag] = extra["tags"][tag]
            extra["tags"] = validated_tags
        if json.dumps(cluster.extra, default=json_util.default) != json.dumps(
            extra, default=json_util.default
        ):
            cluster.extra = extra
            updated = True
        # Get cluster creation date.
        try:
            created = self._list_clusters__cluster_creation_date(
                cluster, cluster_dict)
            if created:
                created = get_datetime(created)
                if cluster.created != created:
                    cluster.created = created
                    updated = True
        except Exception as exc:
            log.exception(
                "Error finding creation date for %s in %s.\n%r",
                self.cloud,
                cluster,
                exc,
            )
        # TODO: Consider if we should fall back to using current date.
        # if not cluster_model.created and is_new:
        #     cluster_model.created = datetime.datetime.utcnow()

        # Update with available cluster actions.
        # try:
        #     from copy import deepcopy

        #     actions_backup = deepcopy(cluster.actions)
        #     self._list_clusters__cluster_actions(cluster, cluster_dict)
        #     if actions_backup != cluster.actions:
        #         updated = True
        # except Exception as exc:
        #     log.exception(
        #         "Error while finding cluster actions "
        #         "for cluster %s:%s for %s \n %r",
        #         cluster.id,
        #         cluster_dict["name"],
        #         self.cloud,
        #         exc,
        #     )
        # Apply any cloud/provider specific post processing.
        try:
            updated = (
                self._list_clusters__postparse_cluster(
                    cluster, cluster_dict) or updated
            )
        except Exception as exc:
            log.exception(
                "Error while post parsing cluster %s:%s for %s\n%r",
                cluster.id,
                cluster_dict["name"],
                self.cloud,
                exc,
            )
        # Save all changes to cluster model on the database.
        if is_new or updated:
            try:
                cluster.save()
            except me.ValidationError as exc:
                log.error("Error adding %s: %s", cluster.name, exc.to_dict())
                raise BadRequestError(
                    {"msg": str(exc), "errors": exc.to_dict()})
            except me.NotUniqueError as exc:
                log.error("cluster %s not unique error: %s", cluster.name, exc)
                raise ConflictError("cluster with this name already exists")
        else:
            log.debug(
                "Not saving cluster %s (%s) %s" % (
                    cluster.name, cluster.id, is_new)
            )
        return cluster, is_new

    def _list_clusters(self):
        """Core logic of list_clusters method
        A list of clusters is fetched from libcloud, the data is processed,
        stored on cluster models, and a list of cluster models is returned.

        Subclasses SHOULD NOT override or extend this method.
        """
        # Query to query list of clusters from provider API.
        try:
            from time import time

            start = time()
            cluster_dicts = self._list_clusters__fetch_clusters()
            log.info(
                "List clusters returned %d results for %s in %d.",
                len(cluster_dicts),
                self.cloud,
                time() - start,
            )
        except InvalidCredsError as exc:
            log.warning(
                "Invalid creds on running list_clusters on %s: %s",
                self.cloud, exc
            )
            raise CloudUnauthorizedError(msg=str(exc))
        except (requests.exceptions.SSLError, ssl.SSLError) as exc:
            log.error("SSLError on running list_clusters on %s: %s",
                      self.cloud, exc)
            raise SSLError(exc=exc)
        except Exception as exc:
            log.exception("Error while running list_clusters on %s",
                          self.cloud)
            raise CloudUnavailableError(exc=exc)
        clusters = []
        now = datetime.datetime.utcnow()
        # This is a map of locations' external IDs and names to CloudLocation
        # mongoengine objects. It is used to lookup cached locations based on
        # a cluster's metadata in order to associate VM instances to their
        # region.
        from mist.api.clouds.models import CloudLocation

        locations_map = {}
        for location in CloudLocation.objects(cloud=self.cloud):
            locations_map[location.external_id] = location
            locations_map[location.name] = location
        from mist.api.containers.models import Cluster

        # Process each cluster in returned list.
        # Store previously unseen clusters separately.
        new_clusters = []
        if config.PROCESS_POOL_WORKERS:
            from concurrent.futures import ProcessPoolExecutor

            cloud_id = self.cloud.id
            choices = map(
                lambda cluster_dict: {
                    "cluster_dict": cluster_dict,
                    "cloud_id": cloud_id,
                    "locations_map": locations_map,
                    "now": now,
                },
                cluster_dicts,
            )
            with ProcessPoolExecutor(
                max_workers=config.PROCESS_POOL_WORKERS
            ) as executor:
                res = executor.map(
                    _update_cluster_from_dict_in_process_pool, choices)
            for cluster, is_new in list(res):
                if not cluster:
                    continue
                if is_new:
                    new_clusters.append(cluster)
                clusters.append(cluster)
        else:
            for cluster_dict in cluster_dicts:
                cluster, is_new = self._update_cluster_from_dict(
                    cluster_dict, locations_map, now
                )
                if not cluster:
                    continue
                if is_new:
                    new_clusters.append(cluster)
                clusters.append(cluster)
        # Set missing_since on cluster models we didn't see for the first time.
        Cluster.objects(
            cloud=self.cloud,
            id__nin=[c.id for c in clusters],
            missing_since=None
        ).update(missing_since=now)
        # Set last_seen, unset missing_since on cluster models we just saw
        Cluster.objects(
            cloud=self.cloud,
            id__in=[c.id for c in clusters]).update(
                last_seen=now, missing_since=None
        )
        # Update RBAC Mappings given the list of clusters seen for the first
        # time.
        self.cloud.owner.mapper.update(new_clusters, asynchronous=False)
        # Update cluster counts on cloud and org.
        # FIXME: resolve circular import issues
        from mist.api.clouds.models import Cloud

        self.cloud.cluster_count = len(clusters)
        self.cloud.save()
        self.cloud.owner.total_cluster_count = sum(
            cloud.cluster_count
            for cloud in Cloud.objects(owner=self.cloud.owner, deleted=None)
        )
        self.cloud.owner.save()
        # Close libcloud connection
        try:
            self.disconnect()
        except Exception as exc:
            log.warning("Error while closing connection: %r", exc)
        return clusters
