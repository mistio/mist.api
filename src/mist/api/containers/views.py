import mongoengine as me
from pyramid.response import Response

from mist.api.auth.methods import auth_context_from_request
from mist.api.models import Cloud
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import InternalServerError
from mist.api.exceptions import NotFoundError
from mist.api.helpers import view_config, params_from_request
from mist.api.containers import methods
from mist.api.containers.models import Cluster
from mist.api.poller.models import ListClustersPollingSchedule


@view_config(route_name='api_v1_cloud_clusters',
             request_method='GET', renderer='json')
def list_cloud_clusters(request):
    """
    Tags: clusters
    ---
    Lists clusters on cloud along with their metadata.
    Check Permissions takes place in filter_list_clusters.
    READ permission required on cloud.
    READ permission required on cluster.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    params = params_from_request(request)
    cached = bool(params.get('cached', False))

    # SEC get filtered resources based on auth_context
    try:
        Cloud.objects.get(owner=auth_context.owner,
                          id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')
    clusters = methods.filter_list_clusters(auth_context, cloud_id,
                                            cached=cached)
    return clusters


@view_config(route_name='api_v1_cloud_cluster',
             request_method='PATCH',
             renderer='json')
def edit_cluster(request):
    """
    Tags: clusters
    ---
    For the moment only the "include_pods" parameter can be changed
    from this endpoint.
    READ permission required on cloud.
    EDIT permission required on cluster.
    ---
    include_pods:
      type: bool
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    cluster_id = request.matchdict['cluster']

    auth_context.check_perm('cloud', 'read', cloud_id)
    auth_context.check_perm('cluster', 'edit', cluster_id)

    try:
        cloud = Cloud.objects.get(id=cloud_id,
                                  owner=auth_context.owner,
                                  enabled=True,
                                  deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    if cloud.container_enabled is False:
        raise BadRequestError('Cloud Container support is disabled')

    try:
        cluster = Cluster.objects.get(id=cluster_id,
                                      cloud=cloud,
                                      owner=auth_context.owner,
                                      missing_since=None)
    except Cluster.DoesNotExist:
        raise NotFoundError('Cluster does not exist')

    params = params_from_request(request)
    try:
        include_pods = params['include_pods']
    except KeyError:
        raise BadRequestError('Required parameter "include_pods" missing')

    if not isinstance(include_pods, bool):
        raise BadRequestError('Value: "include_pods" must be boolean')

    if cluster.include_pods != include_pods:
        cluster.include_pods = include_pods
        try:
            cluster.save()
        except me.ValidationError:
            raise BadRequestError(
                'Invalid value for parameter "include_pods"')

        # Run async a list_clusters task to fetch or remove the pods
        try:
            schedule = ListClustersPollingSchedule.objects.get(cloud=cloud)
        except ListClustersPollingSchedule.DoesNotExist:
            raise InternalServerError(
                'Polling schedule for clusters does not exist')
        else:
            schedule.run_immediately = True
            schedule.save()

            return Response('OK', 200)
    else:
        raise BadRequestError(
            f'Cluster has already include_pods value set to: {include_pods}')
