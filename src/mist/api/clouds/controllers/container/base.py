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

from mist.api import config

from libcloud.common.types import InvalidCredsError

from mist.api.exceptions import ConflictError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import CloudUnavailableError
from mist.api.exceptions import CloudUnauthorizedError
from mist.api.exceptions import SSLError
from mist.api.exceptions import MistNotImplementedError

from mist.api.helpers import get_datetime
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening

from mist.api.concurrency.models import PeriodicTaskInfo
from mist.api.concurrency.models import PeriodicTaskThresholdExceeded

from mist.api.clouds.controllers.base import BaseController

if config.HAS_PRICING:
    from mist.pricing.methods import get_cost_from_price_catalog
else:
    from mist.api.dummy.methods import get_cost_from_price_catalog

log = logging.getLogger(__name__)

__all__ = ["BaseContainerController"]


# clusters cost is control plane cost + node costs
# the latter is obtained from each node machine cost
def _decide_cluster_control_plane_cost(cluster):

    # cp = control plane
    try:
        catalog_cp_cph, catalog_cp_cpm, percentage = \
            get_cost_from_price_catalog(cluster)
        if catalog_cp_cph and catalog_cp_cpm:
            return (catalog_cp_cph, catalog_cp_cpm)

        return cluster.cloud.ctl.get_resource_cost('kubernetes-control-plane')
    except Exception:
        log.exception(f"Error while deciding cost for cluster {cluster.id}")


class BaseContainerController(BaseController):
    """Abstract base class for clouds that provide container features."""

    def _assert_container_feature_enabled(self):
        if not hasattr(self.cloud.ctl, 'container') or \
                not self.cloud.container_enabled:
            raise BadRequestError(
                f'Container feature is disabled on cloud: {self.cloud}')

    def _add_schedule_interval(self):
        from mist.api.poller.models import ListClustersPollingSchedule
        try:
            schedule = ListClustersPollingSchedule.objects.get(
                cloud=self.cloud)
        except ListClustersPollingSchedule.DoesNotExist:
            log.error('Schedule does not exist for cloud: %s', self.cloud)
        else:
            schedule.add_interval(30, ttl=1200)
            schedule.save()

    def _create_cluster(self, auth_context, *args, **kwargs):
        return self.connection.create_cluster(*args, **kwargs)

    def create_cluster(self, auth_context, *args, **kwargs):
        self._assert_container_feature_enabled()
        result = self._create_cluster(auth_context, *args, **kwargs)
        self._add_schedule_interval()
        return result

    def validate_create_cluster_request(self, auth_context,
                                        create_cluster_request):
        """Make sure request parameters are valid for this cloud and return
        the kwargs that will be passed as is to create cluster.
        """
        self._assert_container_feature_enabled()
        return self._validate_create_cluster_request(auth_context,
                                                     create_cluster_request)

    def _validate_create_cluster_request(self, auth_context,
                                         create_cluster_request):
        raise NotImplementedError()

    def validate_scale_nodepool_request(self,
                                        auth_context,
                                        cluster,
                                        nodepool,
                                        desired_nodes,
                                        min_nodes,
                                        max_nodes,
                                        autoscaling) -> None:
        """Make sure the request parameters are valid to scale this nodepool.

        Raises:
            BadRequestError if the parameters given are invalid

        Returns:
            None
        """
        self._assert_container_feature_enabled()
        return self._validate_scale_nodepool_request(auth_context,
                                                     cluster,
                                                     nodepool,
                                                     desired_nodes,
                                                     min_nodes,
                                                     max_nodes,
                                                     autoscaling)

    def _validate_scale_nodepool_request(self,
                                         auth_context,
                                         cluster,
                                         nodepool,
                                         desired_nodes,
                                         min_nodes,
                                         max_nodes,
                                         autoscaling) -> None:
        """
        Raises:
            BadRequestError if the parameters given are invalid

        Returns:
            None
        """

        if (min_nodes is not None and
            desired_nodes is not None and
                (min_nodes > desired_nodes)):
            raise BadRequestError(
                "Min nodes should be less or equal to desired nodes")

        if (max_nodes is not None and
            desired_nodes is not None and
                (desired_nodes > max_nodes)):
            raise BadRequestError(
                "Desired nodes should be less or equal to max nodes")

        if (min_nodes is not None and
            max_nodes is not None and
                (min_nodes > max_nodes)):
            raise BadRequestError(
                "Min nodes should be less or equal to max nodes")

    def scale_nodepool(self,
                       auth_context,
                       cluster,
                       nodepool,
                       desired_nodes,
                       min_nodes,
                       max_nodes,
                       autoscaling):
        """Scale the specified nodepool's nodes
        """
        return self._scale_nodepool(auth_context,
                                    cluster,
                                    nodepool,
                                    desired_nodes,
                                    min_nodes,
                                    max_nodes,
                                    autoscaling)

    def _scale_nodepool(self,
                        auth_context,
                        cluster,
                        nodepool,
                        desired_nodes,
                        min_nodes,
                        max_nodes,
                        autoscaling):

        raise NotImplementedError()

    def _destroy_cluster(self, *args, **kwargs):
        return self.connection.destroy_cluster(*args, **kwargs)

    def destroy_cluster(self, *args, **kwargs):
        self._assert_container_feature_enabled()
        result = self._destroy_cluster(*args, **kwargs)
        self._add_schedule_interval()
        return result

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
        self.produce_and_publish_patch(cached_clusters, clusters, first_run)
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
        # Exclude last seen and created fields from patch.
        for cd in old_clusters, new_clusters:
            for c in list(cd.values()):
                c.pop("last_seen")
                c.pop("created")
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

    def _list_clusters__get_location(self, libcloud_cluster):
        """Find location code name/identifier from libcloud data

        This is to be called exclusively by `self._list_clusters`.

        Subclasses MAY override this method.
        """
        try:
            return libcloud_cluster.location
        except AttributeError:
            return None

    def _list_clusters__cost_nodes(self, cluster, libcloud_cluster):
        """Calculate cost for a cluster

        Any subclass that wishes to handle its cloud's pricing, can implement
        this internal method.

        cluster: A cluster mongoengine model. The model may not have yet
            been saved in the database.
        libcloud_cluster: A libcloud cluster

       This method is expected to return a tuple of two values:
            (cost_per_hour, cost_per_month)

        Subclasses MAY override this method.

        """
        return 0, 0

    def _list_clusters__get_cluster_extra(self, cluster, libcloud_cluster):
        """Return extra dict for libcloud cluster

        Subclasses can override/extend this method if they wish to filter or
        inject extra metadata.
        """
        return copy.copy(libcloud_cluster.extra)

    def _list_clusters__cluster_creation_date(self, cluster, libcloud_cluster):
        try:
            return libcloud_cluster.created_at
        except AttributeError:
            return None

    def _list_clusters__cluster_actions(self, cluster, libcloud_cluster):
        """Add metadata on the cluster dict on the allowed actions

        Any subclass that wishes to specially handle its allowed actions, can
        implement this internal method.

        cluster: A cluster mongoengine model. The model may not have yet
            been saved in the database.
        libcloud_cluster: An instance of a libcloud container driver cluster

        This method is expected to edit `cluster` in place and not return
        anything.

        Subclasses MAY extend this method.
        """
        # Defaults for running state and common clouds.
        cluster.actions.create = True
        cluster.actions.destroy = True

    def _list_clusters__postparse_cluster(self, cluster, libcloud_cluster):
        """Post parse a cluster before returning it in list_clusters

        Any subclass that wishes to specially handle its cloud's tags and
        metadata, can implement this internal method.

        cluster: A cluster mongoengine model. The model may not have yet
            been saved in the database.
        libcloud_cluster: A libcloud container driver cluster

        This method is expected to edit its arguments in place and return
        True if any updates have been made.

        Subclasses MAY override this method.

        """
        updated = False
        return updated

    def _update_from_libcloud_cluster(self,
                                      libcloud_cluster,
                                      locations_map,
                                      now):
        is_new = False
        updated = False
        # Fetch cluster mongoengine model from db, or initialize one.
        from mist.api.containers.models import Cluster
        from mist.api.containers.models import CLUSTERS
        try:
            cluster = Cluster.objects.get(
                cloud=self.cloud, external_id=libcloud_cluster.id
            )
        except Cluster.DoesNotExist:
            cluster = CLUSTERS[self.cloud.provider](
                cloud=self.cloud, external_id=libcloud_cluster.id)
            cluster.first_seen = now
            try:
                cluster.save()
            except me.ValidationError as exc:
                log.warn("Validation error when saving new cluster: %r" % exc)
                return None, is_new
            is_new = True
        # Discover location of cluster.
        try:
            location_id = self._list_clusters__get_location(libcloud_cluster)
        except Exception as exc:
            log.error("Error getting location of %s: %r", cluster, exc)
        else:
            location = locations_map.get(location_id)
            # Add locations such as: 'us-east-2', if locations_map contains
            # locations such as 'us-east-2a', 'us-east-2b', etc.
            if location is None and any(
                    loc.startswith(location_id) for loc in locations_map):
                from mist.api.clouds.models import CloudLocation
                new_id = max(
                    int(k) for k in locations_map if k.isdigit()) + 1
                location = CloudLocation(
                    name=location_id,
                    cloud=self.cloud.id,
                    external_id=str(new_id))
                location.save()
            if cluster.location != location:
                cluster.location = location
                updated = True
        if cluster.name != libcloud_cluster.name:
            cluster.name = libcloud_cluster.name
            updated = True

        if libcloud_cluster.status != cluster.state:
            cluster.state = str(libcloud_cluster.status)
            updated = True

        try:
            libcloud_nodepools = self._list_clusters__fetch_nodepools(
                libcloud_cluster)
        except Exception as exc:
            log.error(
                'Failed to get nodepools for cluster %s with exception %r',
                cluster.id, exc)
        else:
            updated = self._list_clusters__update_nodepools(
                cluster, libcloud_nodepools) or updated

        # Set cluster extra dict.
        # Make sure we don't meet any surprises when we try to json encode
        # later on in the HTTP response.
        extra = self._list_clusters__get_cluster_extra(
            cluster, libcloud_cluster)
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
                cluster, libcloud_cluster)
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

        try:
            updated = (
                self._list_clusters__postparse_cluster(
                    cluster, libcloud_cluster) or updated
            )
        except Exception as exc:
            log.exception(
                "Error while post parsing cluster %s:%s for %s\n%r",
                cluster.id,
                libcloud_cluster.name,
                self.cloud,
                exc,
            )
        try:
            control_plane_cph, control_plane_cpm = \
                _decide_cluster_control_plane_cost(cluster)
            nodes_cph, nodes_cpm = \
                self._list_clusters__cost_nodes(cluster, libcloud_cluster)
            cph = nodes_cph + control_plane_cph
            cpm = nodes_cpm + control_plane_cpm
            if cluster.total_cost.hourly != round(cph, 2) or \
               cluster.total_cost.monthly != round(cpm, 2) or \
               cluster.cost.hourly != round(control_plane_cph, 2) or \
               cluster.cost.monthly != round(control_plane_cpm, 2):
                cluster.total_cost.hourly = round(cph, 2)
                cluster.total_cost.monthly = round(cpm, 2)
                cluster.cost.hourly = round(control_plane_cph, 2)
                cluster.cost.monthly = round(
                    control_plane_cpm, 2)
                updated = True
        except Exception as exc:
            log.exception("Error while calculating cost "
                          "for cluster %s:%s for %s \n%r",
                          cluster.id, libcloud_cluster.name, self.cloud, exc)
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

    def _list_clusters__fetch_nodepools(self, libcloud_cluster):
        """Fetch the cluster's nodepools from the provider API.

       This is to be called exclusively by `_list_clusters`.

        Parameters:
            libcloud_cluster: The libcloud cluster instance

        Returns:
            A list of libcloud nodepools
        """
        return []

    def _list_clusters__update_nodepools(self, cluster, libcloud_nodepools):
        """Update/Create/Delete cluster nodepools.

        Parameters:
            cluster: The Mist Cluster instance
            libcloud_nodepools: A list containing the libcloud cluster
                                nodepools

        Returns:
            bool: A boolean indicating whether the nodepools were updated
        """

        updated = self._remove_deleted_nodepools(
            cluster,
            libcloud_nodepools)

        for libcloud_nodepool in libcloud_nodepools:
            try:
                nodepool = cluster.nodepools.get(name=libcloud_nodepool.name)
            except me.DoesNotExist:
                # New Nodepool
                updated = True
                log.info("Found new nodepools %s for cluster %s",
                         libcloud_nodepool.name, cluster)
                try:
                    sizes = libcloud_nodepool.sizes
                except AttributeError:
                    sizes = [libcloud_nodepool.size]
                values = {
                    'name': libcloud_nodepool.name,
                    'node_count': libcloud_nodepool.nodes,
                    'min_nodes': libcloud_nodepool.min_nodes,
                    'max_nodes': libcloud_nodepool.max_nodes,
                    'state': libcloud_nodepool.state,
                    'locations': getattr(libcloud_nodepool, 'locations', []),
                    'sizes': sizes,
                }
                cluster.nodepools.create(**values)
            except me.MultipleObjectsReturned as exc:
                log.error(
                    "Failed to get nodepool %s for cluster %s with exc %r",
                    libcloud_nodepool.name, cluster.id, exc)
            else:
                # Update Nodepool
                updated = self._update_nodepool(
                    nodepool, libcloud_nodepool) or updated

        return updated

    def _update_nodepool(self, nodepool, libcloud_nodepool):
        """Update the Mist Nodepool from libcloud Nodepool.

        This is to be called exclusively by `_list_clusters__get_nodepools`.

        Parameters:
            cluster: The Mist Cluster instance
            libcloud_nodepools: A list containing the libcloud cluster
                                nodepools

        Returns:
            bool: A boolean indicating whether the nodepools were updated
        """
        updated = False
        if nodepool.node_count != libcloud_nodepool.nodes:
            nodepool.node_count = libcloud_nodepool.nodes
            updated = True

        if nodepool.state != libcloud_nodepool.state:
            nodepool.state = libcloud_nodepool.state
            updated = True

        if nodepool.min_nodes != libcloud_nodepool.min_nodes:
            nodepool.min_nodes = libcloud_nodepool.min_nodes
            updated = True

        if nodepool.max_nodes != libcloud_nodepool.max_nodes:
            nodepool.max_nodes = libcloud_nodepool.max_nodes
            updated = True

        try:
            locations = libcloud_nodepool.locations
        except AttributeError:
            locations = []
        if sorted(nodepool.locations) != sorted(locations):
            nodepool.locations = locations
            updated = True

        try:
            sizes = libcloud_nodepool.sizes
        except AttributeError:
            sizes = [libcloud_nodepool.size]
        if sorted(nodepool.sizes) != sorted(sizes):
            nodepool.sizes = sizes
            updated = True
        return updated

    def _remove_deleted_nodepools(self, cluster, libcloud_nodepools):
        """Remove nodepools that were not returned by libcloud.

        This is to be called exclusively by `_list_clusters__get_nodepools`.

        Parameters:
            cluster: The Mist Cluster instance
            libcloud_nodepools: A list containing the libcloud cluster
                                nodepools

        Returns:
            bool: A boolean indicating whether the nodepools were updated
        """
        updated = False
        existing_names = {nodepool.name for nodepool in cluster.nodepools}
        libcloud_names = {
            nodepool.name for nodepool in libcloud_nodepools}
        deleted = existing_names.difference(libcloud_names)
        if deleted:
            updated = True

        for nodepool_name in deleted:
            try:
                nodepool = cluster.nodepools.get(name=nodepool_name)
            except (me.DoesNotExist, me.MultipleObjectsReturned) as exc:
                log.error(
                    "Failed to delete nodepool %s for cluster %s with exc %r",
                    nodepool_name, cluster.id, exc)
            else:
                cluster.nodepools.remove(nodepool)

        return updated

    def _list_clusters__get_pod_node(self, pod, cluster, libcloud_cluster):
        """Get the node the pod is running on.

        Subclasses MAY override this method.
        """
        from mist.api.machines.models import Machine
        if pod.node_name:
            try:
                node = Machine.objects.get(name=pod.node_name,
                                           cloud=self.cloud,
                                           cluster=cluster,
                                           missing_since=None)
                return node
            except Machine.DoesNotExist:
                log.warning('Failed to get parent node: %s for pod: %s',
                            pod.node_name, pod.id)
            except me.MultipleObjectsReturned:
                log.error("Multiple Machines found for pod %s, Cloud: %s",
                          pod.node_name, self.cloud)

    def list_cached_pods(self, timedelta=datetime.timedelta(days=1)):
        """Return list of pod machines from database
        Only returns machines that existed last time we check and we've seen
        during the last `timedelta`.
        """
        from mist.api.machines.models import Machine
        return Machine.objects(
            cloud=self.cloud,
            missing_since=None,
            machine_type='pod',
            last_seen__gt=datetime.datetime.utcnow() - timedelta,
        )

    def produce_and_publish_pod_patch(self, cached_pods, fresh_pods,
                                      first_run=False):
        old_machines = {'%s-%s' % (m['id'], m['external_id']): copy.copy(m)
                        for m in cached_pods}
        new_machines = {'%s-%s' % (m.id, m.external_id): m.as_dict()
                        for m in fresh_pods}
        # Exclude last seen and probe fields from patch.
        for md in old_machines, new_machines:
            for m in list(md.values()):
                m.pop('last_seen')
                m.pop('probe')
                if m.get('extra') and m['extra'].get('ports'):
                    m['extra']['ports'] = sorted(
                        m['extra']['ports'],
                        key=lambda x: x.get('PublicPort', 0) * 100000 + x.get(
                            'PrivatePort', 0))
        patch = jsonpatch.JsonPatch.from_diff(old_machines,
                                              new_machines).patch
        if patch:  # Publish patches to rabbitmq.
            if not first_run and self.cloud.observation_logs_enabled:
                from mist.api.logs.methods import log_observations
                log_observations(self.cloud.owner.id, self.cloud.id,
                                 'machine', patch, old_machines, new_machines)
            if amqp_owner_listening(self.cloud.owner.id):
                amqp_publish_user(self.cloud.owner.id,
                                  routing_key='patch_machines',
                                  data={'cloud_id': self.cloud.id,
                                        'patch': patch})

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
            libcloud_clusters = self._list_clusters__fetch_clusters()
            log.info(
                "List clusters returned %d results for %s in %d.",
                len(libcloud_clusters),
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
            raise CloudUnavailableError(msg=str(exc))
        clusters = []
        now = datetime.datetime.utcnow()
        # This is a map of locations' external IDs and names to CloudLocation
        # mongoengine objects. It is used to lookup cached locations based on
        # a cluster's metadata in order to associate VM instances to their
        # region.
        from mist.api.clouds.models import CloudLocation

        locations_map = {}
        for location in CloudLocation.objects(
                cloud=self.cloud).only('id', 'external_id', 'name'):
            locations_map[location.external_id] = location
            locations_map[location.name] = location
        from mist.api.containers.models import Cluster
        from mist.api.machines.models import Machine
        # Process each cluster in returned list.
        # Store previously unseen clusters separately.
        new_clusters = []
        pods = []
        new_pods = []
        cached_pods = [m.as_dict()
                       for m in self.list_cached_pods()]
        for libcloud_cluster in libcloud_clusters:
            cluster, is_new = self._update_from_libcloud_cluster(
                libcloud_cluster, locations_map, now
            )
            if not cluster:
                continue
            if is_new:
                new_clusters.append(cluster)
            clusters.append(cluster)

            if cluster.include_pods:
                try:
                    libcloud_pods = libcloud_cluster.driver.ex_list_pods(
                        fetch_metrics=True)
                except Exception as exc:
                    log.error(
                        'Failed to fetch pods/metrics for cluster: %s, %r',
                        cluster, exc)
                    continue
            else:
                continue

            for libcloud_pod in libcloud_pods:
                updated = False
                new_pod = False
                try:
                    machine = Machine.objects.get(external_id=libcloud_pod.id,
                                                  cloud=self.cloud,
                                                  cluster=cluster,
                                                  machine_type='pod')
                except Machine.DoesNotExist:
                    machine = Machine(cloud=self.cloud,
                                      external_id=libcloud_pod.id,
                                      cluster=cluster,
                                      machine_type='pod'
                                      ).save()
                    new_pod = True

                if libcloud_pod.name != machine.name:
                    machine.name = libcloud_pod.name
                    updated = True

                if libcloud_pod.state != machine.state:
                    updated = True
                    machine.state = libcloud_pod.state

                if libcloud_pod.created_at:
                    try:
                        created = get_datetime(libcloud_pod.created_at)
                    except Exception as exc:
                        log.error(
                            'Failed to get creation date for pod %s: %r',
                            machine, exc)
                    else:
                        if machine.created != created:
                            machine.created = created
                            updated = True

                node = self._list_clusters__get_pod_node(
                    libcloud_pod, cluster, libcloud_cluster)

                if node and machine.parent != node:
                    machine.parent = node
                    updated = True

                ips = [ip for ip in libcloud_pod.ip_addresses if ':' not in ip]
                if ips != machine.private_ips:
                    machine.private_ips = ips
                    updated = True

                extra = {}
                extra['resources'] = libcloud_pod.extra['resources']
                extra['namespace'] = libcloud_pod.namespace
                extra['containers'] = []
                metrics = libcloud_pod.extra.get('metrics')
                for container in libcloud_pod.containers:
                    container_dict = {
                        'id': container.id,
                        'name': container.name,
                        'state': container.state,
                        'image': container.image.name,
                    }
                    if container.extra.get('resources'):
                        container_dict['resources'] = container.extra[
                            'resources']
                    if metrics:
                        usage = next((metric.get('usage')
                                      for metric in metrics
                                      if metric.get('name') == container.name),
                                     None)
                        if usage:
                            container_dict['usage'] = usage
                    extra['containers'].append(container_dict)

                if json.dumps(cluster.extra,
                              default=json_util.default) != json.dumps(
                    extra, default=json_util.default
                ):
                    machine.extra = extra
                    updated = True

                if updated or new_pod:
                    try:
                        machine.save()
                    except me.ValidationError as exc:
                        log.error("Error saving pod %s: %r", machine.name, exc)
                    except me.NotUniqueError as exc:
                        log.error("Pod %s not unique error: %r",
                                  machine.name, exc)
                if new_pod:
                    new_pods.append(machine)
                pods.append(machine)

        if new_pods:
            self.cloud.owner.mapper.update(new_pods, asynchronous=False)
        self.produce_and_publish_pod_patch(cached_pods, pods)

        Machine.objects(cloud=self.cloud,
                        id__nin=[pod.id for pod in pods],
                        missing_since=None,
                        machine_type='pod').update(missing_since=now)
        # Set last_seen, unset missing_since on pods we just saw
        Machine.objects(cloud=self.cloud,
                        id__in=[pod.id for pod in pods]
                        ).update(last_seen=now, missing_since=None)

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
        if new_clusters:
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

    def _get_libcloud_cluster(self, cluster, no_fail=False):
        """Return an instance of a libcloud cluster

        This is a private method.

        Subclasses should override or extend this method.
        """
        raise MistNotImplementedError()

    def _libcloud_ingress_to_ingress(self, libcloud_ingress):
        load_balancer_ingresses = libcloud_ingress.load_balancer_ingresses
        ips = [
            {"address": load_balancer_ingress.ip,
             "ports": [vars(ingress_port)
                       for ingress_port in load_balancer_ingress.ports
                       ]}
            for load_balancer_ingress in load_balancer_ingresses
            if load_balancer_ingress.ip
        ]
        hostnames = [
            {"address": load_balancer_ingress.hostname,
             "ports": [vars(ingress_port)
                       for ingress_port in load_balancer_ingress.ports
                       ]}
            for load_balancer_ingress in load_balancer_ingresses
            if load_balancer_ingress.hostname
        ]
        return {
            "name": libcloud_ingress.name,
            "namespace": libcloud_ingress.namespace,
            "ips": ips,
            "hostnames": hostnames,
        }

    def get_ingress(self, cluster, name, namespace):
        try:
            libcloud_cluster = self._get_libcloud_cluster(cluster)
            libcloud_ingress = libcloud_cluster.driver.ex_get_ingress(
                name, namespace)
        except Exception as exc:
            log.error(
                'Failed to fetch ingress: %s on' +
                ' namespace: %s for cluster: %s, %r',
                name, namespace, cluster, exc)
            raise CloudUnavailableError(msg=str(exc)) from exc

        return self._libcloud_ingress_to_ingress(libcloud_ingress)

    def list_ingresses(self, cluster, namespace=None):
        try:
            libcloud_cluster = self._get_libcloud_cluster(cluster)
            libcloud_ingresses = libcloud_cluster.driver.ex_list_ingresses(
                namespace)
        except Exception as exc:
            log.error('Failed to fetch ingresses for cluster: %s, %r',
                      cluster, exc)
            raise CloudUnavailableError(msg=str(exc)) from exc
        return [
            self._libcloud_ingress_to_ingress(libcloud_ingress)
            for libcloud_ingress in libcloud_ingresses
        ]

    def get_credentials(self, cluster):
        try:
            libcloud_cluster = self._get_libcloud_cluster(cluster)
            credentials = self.connection.get_cluster_credentials(
                libcloud_cluster)
        except Exception as exc:
            log.error('Failed to fetch credentials for cluster: %s, %r',
                      cluster, exc)
            raise CloudUnavailableError(msg=str(exc)) from exc
        return credentials
