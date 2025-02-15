import jsonpatch
import mongoengine as me
from pyramid.response import Response
from html import escape

from mist.api import config

from mist.api.keys.models import Key
from mist.api.clouds.models import Cloud
from mist.api.scripts.models import Script
from mist.api.machines.models import Machine
from mist.api.networks.models import Network
from mist.api.schedules.models import Schedule

from mist.api.tag.methods import can_modify_resources_tags
from mist.api.tag.methods import add_tags_to_resource
from mist.api.tag.methods import resolve_id_and_get_tags
from mist.api.tag.methods import remove_tags_from_resource
from mist.api.tag.methods import get_tags_for_resource

from mist.api.auth.methods import auth_context_from_request

from mist.api.helpers import get_resource_model
from mist.api.helpers import view_config, params_from_request
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import amqp_owner_listening

from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import NotFoundError, BadRequestError

OK = Response("OK", 200)


@view_config(route_name='api_v1_tags', request_method='POST', renderer='json')
def tag_resources(request):
    """
    Tags: tags
    ---
    Batch operation for adding/removing tags from a list of resources.
    This api call provides the ability to modify the tags of a large number
    of resources. For each resource a list of dicts is passed with a key, a
    value and optionally an op field. The op field should be either '+' or '-'
    and defines whether or not the tag should be added or removed from the
    resource. If no op value is defined in the dict then '+' is assumed.
    ---
    tags:
      required: true
      type: array
    resource:
      required: true
      type: object
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)

    # FIXME: This implementation is far from OK. We need to re-code the way
    # tags are handled and make sure that RBAC is properly enforced on tags
    for resource in params:
        # list of dicts of key-value pairs
        resource_tags = resource.get('tags', '')
        # dict of resource info
        resource_data = resource.get('resource', '')

        if not resource_data:
            raise RequiredParameterMissingError("resources")
        if not resource_tags:
            raise RequiredParameterMissingError("tags")
        if not resource_data.get('type') or not resource_data.get('item_id'):
            raise BadRequestError('No type or rid provided for some of the '
                                  'resources')

        # ui send this var only for machine. image, network, location
        cloud_id = resource_data.get('cloud_id')

        if cloud_id:
            auth_context.check_perm('cloud', 'read', cloud_id)
        elif resource_data['type'] in ['machine', 'image',
                                       'network', 'volume']:
            raise RequiredParameterMissingError("cloud_id")

        query = {}
        rtype = resource_data['type']
        rid = resource_data['item_id']
        query['id'] = rid

        if cloud_id:
            query['cloud'] = cloud_id

        try:
            resource_obj = get_resource_model(rtype).objects.get(**query)
        except me.DoesNotExist:
            # if the resource can not be found just go on and process the next
            continue

        # normalized_resources.append(resource_data)
        query['rtype'] = rtype

        # split the tags into two lists: those that will be added and those
        # that will be removed
        # (XSS) Security Fix: added html.escape to sanitize user-controlled input in tags  
        # Prevents injection of malicious scripts by escaping key-value pairs
        tags_to_add = [(escape(tag['key']), escape(tag['value'])) for tag in [
            tag for tag in resource_tags if tag.get('op', '+') == '+']]
        # also extract the keys from all the tags to be deleted
        tags_to_remove = [(tag['key'], tag['value']) for tag in [
            tag for tag in resource_tags if tag.get('op', '+') == '-']]

        old_tags = get_tags_for_resource(auth_context.owner, resource_obj)
        resources = [{'resource_type': rtype,
                      'resource_id': rid}]
        if tags_to_add:
            if not can_modify_resources_tags(auth_context, resources,
                                             tags_to_add, 'add'):
                auth_context._raise(rtype, 'edit_tags', rtags=tags_to_add)

            add_tags_to_resource(auth_context.owner,
                                 resources,
                                 tags_to_add)

        if tags_to_remove:
            if not can_modify_resources_tags(auth_context, resources,
                                             tags_to_remove, 'remove'):
                auth_context._raise(rtype, 'edit_tags', rtags=tags_to_remove)

            remove_tags_from_resource(auth_context.owner,
                                      resources,
                                      tags_to_remove)

        if rtype in ['machine', 'network', 'volume', 'zone', 'record']:
            new_tags = get_tags_for_resource(auth_context.owner, resource_obj)
            try:
                external_id = getattr(resource_obj, 'external_id')
            except AttributeError:
                external_id = getattr(resource_obj, rtype + '_id')
            patch = jsonpatch.JsonPatch.from_diff(old_tags, new_tags).patch
            for item in patch:
                item['path'] = '/%s-%s/tags%s' % (resource_obj.id,
                                                  external_id,
                                                  item['path'])
            if amqp_owner_listening(resource_obj.cloud.owner.id):
                amqp_publish_user(auth_context.owner.id,
                                  routing_key='patch_%ss' % rtype,
                                  data={'cloud_id': resource_obj.cloud.id,
                                        'patch': patch})
    return OK


@view_config(route_name='cloud_tags', request_method='GET', renderer='json')
def get_cloud_tags(request):
    """
    Tags: tags
    ---
    Lists tags of a cloud.
    READ permission required on CLOUD
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict["cloud"]

    # SEC require READ permission on cloud
    auth_context.check_perm("cloud", "read", cloud_id)

    return resolve_id_and_get_tags(auth_context.owner, 'cloud', cloud_id)


@view_config(route_name='api_v1_machine_tags', request_method='GET',
             renderer='json')
def get_machine_tags(request):
    """
    Tags: tags
    ---
    Lists tags of a machine.
    READ permission required on CLOUD.
    READ permission required on MACHINE
    ---
    cloud_id:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    machine_id = request.matchdict["machine"]
    cloud_id = request.matchdict["cloud"]
    auth_context.check_perm("cloud", "read", cloud_id)

    auth_context.check_perm('cloud', 'read', cloud_id)
    # SEC
    auth_context.check_perm("machine", "read", machine_id)

    return resolve_id_and_get_tags(auth_context.owner, 'machine', machine_id,
                                   cloud_id=cloud_id)


@view_config(route_name='script_tags', request_method='GET', renderer='json')
def get_script_tags(request):
    """
    Tags: tags
    ---
    Lists tags of a script.
    READ permission required on SCRIPT
    ---
    script_id:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    script_id = request.matchdict["script"]

    # SEC require READ permission on script
    auth_context.check_perm("script", "read", script_id)

    return resolve_id_and_get_tags(auth_context.owner, 'script', script_id)


@view_config(route_name='schedule_tags', request_method='GET', renderer='json')
def get_schedule_tags(request):
    """
    Tags: tags
    ---
    Lists tags of a schedule.
    READ permission required on SCHEDULE
    ---
    schedule:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    schedule_id = request.matchdict["schedule"]

    # SEC require READ permission on script
    auth_context.check_perm("schedule", "read", schedule_id)

    return resolve_id_and_get_tags(auth_context.owner, 'schedule', schedule_id)


@view_config(route_name='key_tags', request_method='GET', renderer='json')
def get_key_tags(request):
    """
    Tags: tags
    ---
    Lists tags of an ssh key pair.
    READ permission required on KEY
    ---
    key:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    key_id = request.matchdict["key"]

    # SEC require READ permission on key
    auth_context.check_perm("key", "read", key_id)

    return resolve_id_and_get_tags(auth_context.owner, 'key', key_id)


@view_config(route_name='network_tags', request_method='GET', renderer='json')
def get_network_tags(request):
    """
    Tags: tags
    ---
    Lists tags of a network.
    READ permission required on CLOUD.
    READ permission required on NETWORK
    ---
    cloud:
      in: path
      required: true
      type: string
    network:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    network_id = request.matchdict["network"]
    cloud_id = request.params.get("cloud")

    auth_context.check_perm('cloud', 'read', cloud_id)
    # SEC require READ permission on network
    auth_context.check_perm('network', 'read', network_id)

    return resolve_id_and_get_tags(auth_context.owner, 'network', network_id,
                                   cloud_id=cloud_id)


@view_config(route_name='cloud_tags', request_method='POST', renderer='json')
def set_cloud_tags(request):
    """
    Tags: tags
    ---
    Set tags to owner's cloud.
    EDIT_TAGS permission required on SCRIPT
    ---
    tags:
      type: dict
      required: true
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    cloud_id = request.matchdict["cloud"]

    # SEC require EDIT_TAGS permission on cloud
    auth_context.check_perm("cloud", "edit_tags", cloud_id)
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner,
                                  id=cloud_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Resource with that id does not exist')

    tags = params.get("tags")
    if type(tags) != dict:
        raise BadRequestError('tags should be dictionary of tags')

    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'cloud',
                                       'resource_id': cloud.id}],
                                     tags, 'add'):
        auth_context._raise('cloud', 'edit_tags', rtags=tags)

    return add_tags_to_resource(auth_context.owner,
                                [{'resource_type': 'cloud',
                                  'resource_id': cloud_id}],
                                list(tags.items()))


@view_config(route_name='api_v1_machine_tags', request_method='POST',
             renderer='json')
def set_machine_tags(request):
    """
    Tags: tags
    ---
    Sets tags for a machine, given the cloud and machine id.
    READ permission required on cloud.
    EDIT_TAGS permission required on machine.
    ---
    cloud_id:
      in: path
      required: true
      type: string
    machine_id:
      in: path
      required: true
      type: string
    tags:
      items:
        type: object
      type: array
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    cloud_id = request.matchdict["cloud"]
    machine_id = request.matchdict["machine"]
    auth_context.check_perm("cloud", "read", cloud_id)
    try:
        machine = Machine.objects.get(cloud=cloud_id, external_id=machine_id)
    except me.DoesNotExist:
        raise NotFoundError('Resource with that id does not exist')

    # SEC require EDIT_TAGS permission on machine
    auth_context.check_perm("machine", "edit_tags", machine.id)

    tags = params.get("tags")
    if type(tags) != dict:
        raise BadRequestError('tags should be dictionary of tags')

    can_modify_resources_tags(auth_context,
                              [{'resource_type': 'machine',
                                'resource_id': machine.id}],
                              tags)

    # FIXME: This is f***** up! This method is utilized by the Ember UI in
    # order to update a machine's tags by providing the entire list of tags
    # to be re-set. However, `add_tags_to_resource` simply appends the new
    # tags without deleting any.

    old_tags = get_tags_for_resource(auth_context.owner, machine)
    add_tags_to_resource(auth_context.owner,
                         [{'resource_type': 'machine',
                           'resource_id': machine.id}],
                         list(tags.items()))

    if config.MACHINE_PATCHES:
        new_tags = get_tags_for_resource(auth_context.owner, machine)

        patch = jsonpatch.JsonPatch.from_diff(old_tags, new_tags).patch
        for item in patch:
            item['path'] = '/%s-%s/tags%s' % (machine.id, machine.external_id,
                                              item['path'])
        amqp_publish_user(auth_context.owner.id,
                          routing_key='patch_machines',
                          data={'cloud_id': cloud_id,
                                'patch': patch})
    return {}


@view_config(route_name='schedule_tags', request_method='POST',
             renderer='json')
def set_schedule_tags(request):
    """
    Tags: tags
    ---
    Set tags to owner's schedule.
    EDIT_TAGS permission required on schedule
    ---
    schedule:
      in: path
      required: true
      type: string
    tags:
      type: dict
      required: true
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    schedule_id = request.matchdict["schedule"]

    # SEC require EDIT_TAGS permission on schedule
    auth_context.check_perm("schedule", "edit_tags", schedule_id)

    schedule = Schedule.objects.get(owner=auth_context.owner,
                                    id=schedule_id, deleted=None)

    tags = params.get("tags")
    if type(tags) != dict:
        raise BadRequestError('tags should be dictionary of tags')

    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'schedule',
                                       'resource_id': schedule.id}],
                                     tags, 'add'):
        auth_context._raise('schedule', 'edit_tags', rtags=tags)

    return add_tags_to_resource(
        auth_context.owner,
        [{'resource_type': 'schedule',
          'resource_id': schedule.id}],
        list(tags.items()))


@view_config(route_name='script_tags', request_method='POST', renderer='json')
def set_script_tags(request):
    """
    Tags: tags
    ---
    Set tags to owner's script.
    EDIT_TAGS permission required on SCRIPT
    ---
    script:
      in: path
      required: true
      type: string
    tags:
      type: dict
      required: true
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    script_id = request.matchdict["script"]

    # SEC require EDIT_TAGS permission on script
    auth_context.check_perm("script", "edit_tags", script_id)

    script = Script.objects.get(owner=auth_context.owner, id=script_id,
                                deleted=None)

    tags = params.get("tags")
    if type(tags) != dict:
        raise BadRequestError('tags should be dictionary of tags')
    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'script',
                                       'resource_id': script.id}],
                                     tags, 'add'):
        auth_context._raise('script', 'edit_tags', rtags=tags)

    return add_tags_to_resource(auth_context.owner,
                                [{'resource_type': 'script',
                                  'resource_id': script.id}],
                                list(tags.items()))


@view_config(route_name='key_tags', request_method='POST', renderer='json')
def set_key_tags(request):
    """
    Tags: tags
    ---
    Set tags to owner's key.
    EDIT_TAGS permission required on KEY
    ---
    key_id:
      in: path
      required: true
      type: string
    tags:
      type: dict
      required: true
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    key_id = request.matchdict["key_id"]

    # SEC require EDIT_TAGS permission on key
    auth_context.check_perm("key", "edit_tags", key_id)

    try:
        key = Key.objects.get(owner=auth_context.owner,
                              id=key_id, deleted=None)
    except Key.DoesNotExist:
        raise NotFoundError('Resource with that id does not exist')

    tags = params.get("tags")
    if type(tags) != dict:
        raise BadRequestError('tags should be dictionary of tags')

    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'key',
                                       'resource_id': key.id}],
                                     tags, 'add'):
        auth_context._raise('key', 'edit_tags', rtags=tags)

    return add_tags_to_resource(auth_context.owner,
                                [{'resource_type': 'key',
                                  'resource_id': key.id}],
                                list(tags.items()))


@view_config(route_name='network_tags', request_method='POST', renderer='json')
def set_network_tags(request):
    """
    Tags: tags
    ---
    Sets tags for a network, given the cloud and network id.
    READ permission required on cloud.
    EDIT_TAGS permission required on network.
    ---
    cloud:
      in: path
      required: true
      type: string
    network:
      in: path
      required: true
      type: string
    tags:
      items:
        type: object
      type: array
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    cloud_id = request.matchdict["cloud"]
    network_id = request.matchdict["network"]
    auth_context.check_perm('cloud', 'read', cloud_id)
    try:
        network = Network.objects.get(cloud=cloud_id, id=network_id)
    except Network.DoesNotExist:
        raise NotFoundError('Resource with that id does not exist')

    # SEC require EDIT_TAGS permission on network
    auth_context.check_perm("network", "edit_tags", network_id)

    tags = params.get("tags")
    if type(tags) != dict:
        raise BadRequestError('tags should be dictionary of tags')
    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'network',
                                       'resource_id': network.id}],
                                     tags, 'add'):
        auth_context._raise('network', 'edit_tags', rtags=tags)

    return add_tags_to_resource(
        auth_context.owner,
        [{'resource_type': 'network',
          'resource_id': network.id}],
        list(tags.items()))


@view_config(route_name='schedule_tag', request_method='DELETE',
             renderer='json')
def delete_schedule_tag(request):
    """
    Tags: tags
    ---
    Deletes tag in the db for specified resource_type.
    ---
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    schedule_id = request.matchdict["schedule"]
    tag_key = params.get("tag_key")
    tags = {tag_key: ''}
    # SEC require EDIT_TAGS permission on schedule
    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'schedule',
                                       'resource_id': schedule_id}],
                                     tags, 'remove'):
        auth_context._raise('schedule', 'edit_tags', rtags=tags)

    return remove_tags_from_resource(auth_context.owner,
                                     [{'resource_type': 'schedule',
                                       'resource_id': schedule_id}],
                                     tags)


@view_config(route_name='cloud_tag', request_method='DELETE', renderer='json')
def delete_cloud_tag(request):
    """
    Tags: tags
    ---
    Deletes tag in the db for specified resource_type.
    EDIT_TAGS permission required on cloud.
    ---
    tag_key:
      required: true
      type: string
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    cloud_id = request.matchdict["cloud"]
    tag_key = params.get("tag_key")
    tags = {tag_key: ''}

    # SEC require EDIT_TAGS permission on cloud
    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'cloud',
                                       'resource_id': cloud_id}],
                                     tags, 'remove'):
        auth_context._raise('cloud', 'edit_tags', rtags=tags)

    return remove_tags_from_resource(auth_context.owner,
                                     [{'resource_type': 'cloud',
                                       'resource_id': cloud_id}],
                                     tags)


@view_config(route_name='api_v1_machine_tag', request_method='DELETE',
             renderer='json')
def delete_machine_tag(request):
    """
    Tags: tags
    ---
    Deletes tag in the db for specified resource_type.
    READ permission required on cloud.
    EDIT_TAGS permission required on machine.
    ---
    tag_key:
      required: true
      type: string
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    cloud_id = request.matchdict["cloud"]
    machine_id = request.matchdict["machine"]
    tag_key = params.get("tag_key")
    tags = {tag_key: ''}

    # SEC require EDIT_TAGS permission on machine
    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'machine',
                                       'resource_id': machine_id}],
                                     tags, 'remove'):
        auth_context._raise('machine', 'edit_tags', rtags=tags)

    return remove_tags_from_resource(auth_context.owner,
                                     [{'resource_type': 'machine',
                                       'resource_id': machine_id}],
                                     tags)


@view_config(route_name='script_tag', request_method='DELETE', renderer='json')
def delete_script_tag(request):
    """
    Tags: tags
    ---
    Deletes a tag in the db for specified resource_type.
    EDIT_TAGS permission required on script.
    ---
    tag_key:
      required: true
      type: string
    script_id:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    script_id = request.matchdict["script"]
    tag_key = params.get("tag_key")
    tags = {tag_key: ''}

    # SEC require EDIT_TAGS permission on script
    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'script',
                                       'resource_id': script_id}],
                                     tags, 'remove'):
        auth_context._raise('script', 'edit_tags', rtags=tags)

    return remove_tags_from_resource(auth_context.owner,
                                     [{'resource_type': 'script',
                                       'resource_id': script_id}],
                                     tags)


@view_config(route_name='key_tag', request_method='DELETE', renderer='json')
def delete_key_tag(request):
    """
    Tags: tags
    ---
    Deletes a tag in the db for specified resource_type.
    EDIT_TAGS permission required on key.
    ---
    tag_key:
      required: true
      type: string
    key:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    key_id = request.matchdict["key"]
    tag_key = params.get("tag_key")
    tags = {tag_key: ''}

    # SEC require EDIT_TAGS permission on key
    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'key',
                                       'resource_id': key_id}],
                                     tags, 'remove'):
        auth_context._raise('key', 'edit_tags', rtags=tags)

    return remove_tags_from_resource(auth_context.owner,
                                     [{'resource_type': 'key',
                                       'resource_id': key_id}],
                                     tags, 'remove')


@view_config(route_name='network_tag', request_method='DELETE',
             renderer='json')
def delete_network_tag(request):
    """
    Tags: tags
    ---
    Delete tag in the db for specified resource_type.
    READ permission required on cloud.
    EDIT_TAGS permission required on network.
    ---
    tag_key:
      in: path
      required: true
      type: string
    cloud_id:
      in: path
      required: true
      type: string
    network_id:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict["cloud_id"]
    network_id = request.matchdict["network_id"]
    tag_key = request.matchdict["tag_key"]

    auth_context.check_perm('cloud', 'read', cloud_id)
    # SEC require EDIT_TAGS permission on network
    auth_context.check_perm('network', 'edit_tags', network_id)
    tags = {tag_key: ''}

    # SEC require EDIT_TAGS permission on network
    if not can_modify_resources_tags(auth_context,
                                     [{'resource_type': 'network',
                                       'resource_id': network_id}],
                                     tags, 'remove'):
        auth_context._raise('network', 'edit_tags', rtags=tags)

    return remove_tags_from_resource(auth_context.owner,
                                     [{'resource_type': 'network',
                                       'resource_id': network_id}],
                                     tags)
