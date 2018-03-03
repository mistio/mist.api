import mongoengine as me
from pyramid.response import Response

import mist.api.networks.methods as methods

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.networks.models import Network, Subnet

from mist.api.auth.methods import auth_context_from_request

from mist.api.exceptions import CloudNotFoundError
from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import PolicyUnauthorizedError
from mist.api.exceptions import NetworkNotFoundError, SubnetNotFoundError

from mist.api.helpers import params_from_request, view_config

OK = Response("OK", 200)


@view_config(route_name='api_v1_networks',
             request_method='GET', renderer='json')
def list_networks(request):
    """
    Tags: networks
    ---
    Lists networks of a cloud.
    Currently supports the EC2, GCE and OpenStack providers.
    For other providers this returns an empty list.
    READ permission required on cloud.
    ---
    parameters:
    - name: cloud
      in: path
      required: true
      schema:
        type: string
    """
    cloud_id = request.matchdict['cloud']
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)

    try:
        Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except me.DoesNotExist:
        raise CloudNotFoundError

    networks = methods.list_networks(auth_context.owner, cloud_id)

    return networks


@view_config(route_name='api_v1_networks',
             request_method='POST', renderer='json')
def create_network(request):
    """
    Tags: networks
    ---
    Creates a new network. If subnet dict is specified,
    after creating the network it will use the new
    network's id to create a subnet.
    CREATE_RESOURCES permission required on cloud.
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

    # TODO
    if not auth_context.is_owner():
        raise PolicyUnauthorizedError()

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except me.DoesNotExist:
        raise CloudNotFoundError

    network = methods.create_network(auth_context.owner, cloud, network_params)
    network_dict = network.as_dict()

    # Bundling Subnet creation in this call because it is required
    #  for backwards compatibility with the current UI
    if subnet_params:
        try:
            subnet = methods.create_subnet(auth_context.owner, cloud,
                                           network, subnet_params)
        except Exception as exc:
            # Cleaning up the network object in case subnet creation
            #  fails for any reason
            network.ctl.delete()
            raise exc
        network_dict['subnet'] = subnet.as_dict()

    return network.as_dict()


@view_config(route_name='api_v1_network', request_method='DELETE')
def delete_network(request):
    """
    Tags: networks
    ---
    Deletes a network.
    CREATE_RESOURCES permission required on cloud.
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

    # TODO
    if not auth_context.is_owner():
        raise PolicyUnauthorizedError()

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError
    try:
        network = Network.objects.get(id=network_id, cloud=cloud)
    except me.DoesNotExist:
        raise NetworkNotFoundError

    methods.delete_network(auth_context.owner, network)

    return OK


@view_config(route_name='api_v1_subnets', request_method='GET',
             renderer='json')
def list_subnets(request):
    """
    List subnets of a cloud
    Currently supports the EC2, GCE and OpenStack clouds.
    For other providers this returns an empty list.
    READ permission required on cloud.
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
    auth_context.check_perm("cloud", "read", cloud_id)

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError

    if not hasattr(cloud.ctl, 'network'):
        return []

    try:
        network = Network.objects.get(cloud=cloud, id=network_id)
    except Network.DoesNotExist:
        raise NetworkNotFoundError

    subnets = cloud.ctl.network.list_subnets(network=network)

    return subnets


@view_config(route_name='api_v1_subnets', request_method='POST',
             renderer='json')
def create_subnet(request):
    """
    Tags: networks
    ---
    Create subnet on a given network on a cloud.
    CREATE_RESOURCES permission required on cloud.
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
    cidr:
      required: true
      type: string
    availability_zone:
      description: Required for Amazon VPCs
      type: string
    """
    cloud_id = request.matchdict['cloud']
    network_id = request.matchdict['network']

    params = params_from_request(request)

    auth_context = auth_context_from_request(request)

    # TODO
    if not auth_context.is_owner():
        raise PolicyUnauthorizedError()

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError
    try:
        network = Network.objects.get(id=network_id, cloud=cloud)
    except Network.DoesNotExist:
        raise NetworkNotFoundError

    subnet = methods.create_subnet(auth_context.owner, cloud, network, params)

    return subnet.as_dict()


@view_config(route_name='api_v1_subnet', request_method='DELETE')
def delete_subnet(request):
    """
    Tags: networks
    ---
    Deletes a subnet.
    CREATE_RESOURCES permission required on cloud.
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

    # TODO
    if not auth_context.is_owner():
        raise PolicyUnauthorizedError()

    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError

    try:
        network = Network.objects.get(id=network_id, cloud=cloud)
    except Network.DoesNotExist:
        raise NetworkNotFoundError

    try:
        subnet = Subnet.objects.get(id=subnet_id, network=network)
    except Subnet.DoesNotExist:
        raise SubnetNotFoundError

    methods.delete_subnet(auth_context.owner, subnet)

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
    machine_id = params.get('machine')
    assign = params.get('assign', True)
    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, machine_id=machine_id)
        machine_uuid = machine.id
    except me.DoesNotExist:
        machine_uuid = ""
    auth_context.check_perm("machine", "edit", machine_uuid)

    ret = methods.associate_ip(auth_context.owner, cloud_id, network_id,
                               ip, machine_id, assign)
    if ret:
        return OK
    else:
        return Response("Bad Request", 400)
