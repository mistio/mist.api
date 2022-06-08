import mongoengine as me
from pyramid.response import Response

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.networks.models import Network, Subnet
from mist.api.networks.models import NETWORKS, SUBNETS
from mist.api.networks.methods import associate_ip as associate_ip_method
from mist.api.networks.methods import filter_list_networks

from mist.api.tag.methods import add_tags_to_resource
from mist.api.auth.methods import auth_context_from_request
from mist.api.clouds.methods import filter_list_clouds

from mist.api.exceptions import CloudNotFoundError
from mist.api.exceptions import SubnetNotFoundError
from mist.api.exceptions import NetworkNotFoundError
from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import MistNotImplementedError
from mist.api.exceptions import CloudUnauthorizedError, CloudUnavailableError

from mist.api.helpers import params_from_request, view_config


OK = Response("OK", 200)


@view_config(route_name='api_v1_networks',
             request_method='GET', renderer='json')
@view_config(route_name='api_v1_cloud_networks',
             request_method='GET', renderer='json')
def list_networks(request):
    """
    Tags: networks
    ---
    List the networks of a cloud

    READ permission required on cloud, networks, and subnets
    ---
    parameters:
    - name: cloud
      in: path
      required: true
      schema:
        type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict.get('cloud')
    params = params_from_request(request)

    if cloud_id:
        cached = bool(params.get('cached', False))
        try:
            Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                              deleted=None)
        except Cloud.DoesNotExist:
            raise CloudNotFoundError()
        # SEC
        auth_context.check_perm('cloud', 'read', cloud_id)
        networks = filter_list_networks(auth_context, cloud_id, cached=cached)

    else:
        cached = bool(params.get('cached', True))   # return cached by default
        auth_context.check_perm("cloud", "read", None)
        clouds = filter_list_clouds(auth_context)
        networks = []
        for cloud in clouds:
            if cloud.get('enabled'):
                try:
                    networks += filter_list_networks(auth_context,
                                                     cloud.get('id'),
                                                     cached=cached)
                except (CloudUnavailableError, CloudUnauthorizedError):
                    pass

    return networks


@view_config(route_name='api_v1_cloud_networks',
             request_method='POST', renderer='json')
def create_network(request):
    """
    Tags: networks
    ---
    Create a new network

    If subnet parameters are specified, they will be used to create a new
    subnet in the newly created network.

    ADD permission required on network
    ADD permission required on subnet
    READ permission required on cloud
    CREATE_RESOURCES permission required on cloud
    ---
    parameters:
    - name: cloud_id
      in: path
      required: true
      description: The Cloud ID
      schema:
        type: string
    requestBody:
      description: Foo
      required: true
      content:
        'application/json':
          schema:
            type: object
            properties:
              network:
                type: object
              subnet:
                type: object
            required:
            - network
    """
    cloud_id = request.matchdict['cloud']

    params = params_from_request(request)
    network_params = params.get('network')
    subnet_params = params.get('subnet')

    auth_context = auth_context_from_request(request)

    if not network_params:
        raise RequiredParameterMissingError('network')

    if subnet_params and not subnet_params.get('cidr'):
        raise RequiredParameterMissingError('cidr')

    auth_context.check_perm("cloud", "read", cloud_id)
    auth_context.check_perm("cloud", "create_resources", cloud_id)
    tags, _ = auth_context.check_perm("network", "add", None)

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except me.DoesNotExist:
        raise CloudNotFoundError()

    # Is network support available?
    if not hasattr(cloud.ctl, 'network'):
        raise NotImplementedError()

    # Create the new network
    network = NETWORKS[cloud.ctl.provider].add(cloud=cloud, **network_params)
    network.assign_to(auth_context.user)

    if tags:
        add_tags_to_resource(auth_context.owner,
                             [{'resource_type': 'network',
                               'resource_id': network.id}],
                             tags)

    # Bundling Subnet creation in this call because it is required for
    # backwards compatibility with the current UI  # FIXME
    if subnet_params:
        try:
            # Create a DB document for the new subnet and call libcloud to
            # declare it on the cloud provider
            SUBNETS[cloud.ctl.provider].add(network=network, **subnet_params)
        except Exception as exc:
            # Cleaning up the network object in case subnet creation fails
            # for any reason
            network.ctl.delete()
            network.delete()
            raise exc

    return network.as_dict()


@view_config(route_name='api_v1_network', request_method='DELETE')
def delete_network(request):
    """
    Tags: networks
    ---
    Delete a network and all corresponding subnets

    READ permission required on cloud
    READ permission required on network
    REMOVE permission required on network
    ---
    parameters:
    - name: cloud_id
      in: path
      required: true
      schema:
        type: string
    - name: network_id
      in: path
      required: true
      schema:
        type: string
    """
    cloud_id = request.matchdict['cloud']
    network_id = request.matchdict['network']

    auth_context = auth_context_from_request(request)

    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)
    auth_context.check_perm('network', 'read', network_id)
    auth_context.check_perm('network', 'remove', network_id)

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()
    try:
        network = Network.objects.get(id=network_id, cloud=cloud)
    except me.DoesNotExist:
        raise NetworkNotFoundError()

    # Delete the network
    network.ctl.delete()

    return OK


@view_config(route_name='api_v1_subnets', request_method='GET',
             renderer='json')
def list_subnets(request):
    """
    Tags: networks
    ---
    List the subnets of a network

    READ permission required on cloud
    READ permission required on network
    READ permission required on subnets
    ---
    cloud:
      in: path
      required: true
      type: string
    network_id:
      in: path
      required: true
      description: The DB ID of the network whose subnets will be returned
      type: string
    """
    cloud_id = request.matchdict['cloud']
    network_id = request.matchdict['network']

    auth_context = auth_context_from_request(request)

    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)
    auth_context.check_perm('network', 'read', network_id)

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()
    try:
        network = Network.objects.get(cloud=cloud, id=network_id)
    except Network.DoesNotExist:
        raise NetworkNotFoundError()

    return [subnet.as_dict() for subnet in network.ctl.list_subnets()]


@view_config(route_name='api_v1_subnets', request_method='POST',
             renderer='json')
def create_subnet(request):
    """
    Tags: networks
    ---
    Create subnet in a given network on a cloud

    ADD permission required on subnet
    READ permission required on cloud
    READ permission required on network
    CREATE_SUBNETS permission required on network
    CREATE_RESOURCES permission required on cloud
    ---
    cloud_id:
      in: path
      required: true
      description: The Cloud ID
      type: string
    network_id:
      in: path
      required: true
      description: The ID of the Network that will contain the new subnet
      type: string
    subnet:
      required: true
      type: object
    """
    cloud_id = request.matchdict['cloud']
    network_id = request.matchdict['network']

    params = params_from_request(request)

    auth_context = auth_context_from_request(request)

    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)
    auth_context.check_perm('cloud', 'create_resources', cloud_id)
    auth_context.check_perm('network', 'read', network_id)
    auth_context.check_perm('network', 'edit_subnets', network_id)

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()
    try:
        network = Network.objects.get(id=network_id, cloud=cloud)
    except Network.DoesNotExist:
        raise NetworkNotFoundError()

    # Create subnet.
    subnet = SUBNETS[cloud.ctl.provider].add(network=network, **params)

    return subnet.as_dict()


@view_config(route_name='api_v1_subnet', request_method='DELETE')
def delete_subnet(request):
    """
    Tags: networks
    ---
    Delete a subnet

    READ permission required on cloud
    READ permission required on network
    READ permission required on subnet
    REMOVE permission required on subnet
    ---
    cloud_id:
      in: path
      required: true
      type: string
    network_id:
      in: path
      required: true
      type: string
    subnet_id:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']
    subnet_id = request.matchdict['subnet']
    network_id = request.matchdict['network']

    auth_context = auth_context_from_request(request)

    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)
    auth_context.check_perm('network', 'read', network_id)
    auth_context.check_perm('network', 'edit_subnets', network_id)

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()
    try:
        network = Network.objects.get(id=network_id, cloud=cloud)
    except Network.DoesNotExist:
        raise NetworkNotFoundError()
    try:
        subnet = Subnet.objects.get(id=subnet_id, network=network)
        subnet.ctl.delete()
    except Subnet.DoesNotExist:
        raise SubnetNotFoundError()

    return OK


@view_config(route_name='api_v1_network', request_method='POST')
def associate_ip(request):
    """
    Tags: networks
    ---
    Associates ip with the specific network and machine.
    READ permission required on cloud.
    EDIT permission required on cloud.
    ---
    parameters:
    - name: cloud
      in: path
      required: true
      schema:
        type: string
    - name: network
      in: path
      required: true
      schema:
        type: string
    requestBody:
      description: Foo
      required: true
      content:
        'application/json':
          schema:
            type: object
            properties:
              assign:
                default: true
                type: boolean
              ip:
                type: string
              machine:
                type: string
            required:
            - ip
            - machine
    """
    cloud_id = request.matchdict['cloud']
    network_id = request.matchdict['network']
    params = params_from_request(request)
    ip = params.get('ip')
    external_id = params.get('machine')
    assign = params.get('assign', True)
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, external_id=external_id)
        machine_id = machine.id
    except me.DoesNotExist:
        machine_id = ""
    auth_context.check_perm("machine", "edit", machine_id)

    ret = associate_ip_method(auth_context.owner, cloud_id, network_id,
                              ip, machine_id, assign)
    if ret:
        return OK
    else:
        return Response("Bad Request", 400)


@view_config(route_name='api_v1_cloud_vnfs', request_method='GET',
             renderer='json')
def list_vnfs(request):
    """
    Tags: networks
    ---
    List the virtual network functions of a cloud (KVM only)

    READ permission required on cloud
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    cloud_id = request.matchdict['cloud']

    auth_context = auth_context_from_request(request)

    # SEC
    auth_context.check_perm('cloud', 'read', cloud_id)

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    try:
        return cloud.ctl.network.list_vnfs()
    except (AttributeError, NotImplementedError):
        raise MistNotImplementedError
