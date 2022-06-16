import logging
import re
from mist.api.exceptions import NotFoundError, PolicyUnauthorizedError

from mongoengine import Q
import mongoengine as me
from mist.api.tag.models import Tag
from mist.api.helpers import trigger_session_update
from mist.api.helpers import get_object_with_id, search_parser
from functools import reduce
from mist.api.config import TAGS_RESOURCE_TYPES
from mist.api import config
from mist.api.helpers import get_resource_model


log = logging.getLogger(__name__)


def get_tags(auth_context, types=[], search='', sort='key',
             start=None, limit=None, only=None, deref=None):
    """
    List unique tags and the corresponding resources.

    Supports filtering, sorting, pagination. Enforces RBAC.

    Parameters:
        auth_context(AuthContext): The AuthContext of the user
            to list tags for.
        verbose(bool):  Flag to determine whether the tagged resources are
                        going to be displayed (default False)
        resource(str): Display tags on a single resource
                       One of taggable resources:
            'bucket', 'cloud', 'cluster', 'image', 'key',
            'machine', 'network', 'record', 'schedule',
            'script', 'secret', 'stack', 'subnet', 'template',
            'tunnel', 'volume', 'zone'
        search(str): The pattern to search for, that contains:
            key(field)-value pairs separated by one of the operators:
                :, =, !=
            Example:
            >>>  key:key1 or key:key1 value:value1
        cloud(str): List resources from these clouds only,
            with the same pattern as `search`.
        tags(str or dict): List resources which satisfy these tags:
            Examples:
            >>> '{"dev": "", "server": "east"}'
            >>> 'dev,server=east'
        only(str): The fields to load from the resource_type's document,
            comma-seperated.
        sort(str): The field to order the query results by; field may be
            prefixed with “+” or a “-” to determine the ordering direction.
        start(int): The index of the first item to return.
        limit(int): Return up to this many items.
        deref(str): Name or id. Display either the id or the name of the tagged
                    resources (default id).
    Returns:
        tuple(A mongoengine QuerySet containing the objects found,
             the total number of items found)
    """

    query = Q(owner=auth_context.owner)

    if config.HAS_RBAC and not auth_context.is_owner():
        rbac_filter = Q()
        for rtype, rids in auth_context.get_allowed_resources().items():
            if rids:
                rbac_filter |= Q(resource_type=rtype.rstrip('s'),
                                 resource_id__in=rids)
        query &= rbac_filter

    missing_resources = get_missing_resources()
    if missing_resources:
        missing_query = Q()
        for rtype, rids in missing_resources.items():
            missing_query |= Q(resource_type=rtype, resource_id__nin=rids)

        query &= missing_query

    if types == 'all':
        types = TAGS_RESOURCE_TYPES
    elif types:
        types = types.split(',')

    type_query = Q()
    for rtype in types:
        type_query |= Q(resource_type=rtype.rstrip('s'))
    query &= type_query
    # search filter contains space separated terms
    # if the term contains :,=,<,>,!=, <=, >= then assume key/value query
    # otherwise search for objects with id or name matching the term
    terms = search_parser(search)
    for term in terms:
        if "!=" in term:
            k, v = term.split("!=")
            mongo_operator = '__ne'
        elif ':' in term or '=' in term:
            k, v = re.split(r'[:,=]', term)
            mongo_operator = ''
        query &= Q(**{f'{k}{mongo_operator}': v})

    if sort[0] in ['+', '-'] and sort[1:] in ['key', 'resource_count']:
        reverse = True if sort[0] == '-' else False
        sort = sort[1:]
    elif sort in ['key', 'resource_count']:
        reverse = False
    else:
        sort = 'key'
        reverse = False

    tags = Tag.objects(query)

    tags_unique = [{'key': k, 'value': v} for k, v in
                   set((t.key, t.value) for t in tags)]
    data = []

    for tag_unique in tags_unique:

        item = {'tag': {tag_unique['key']: tag_unique['value']}}
        item['resource_count'] = tags.filter(**tag_unique).count()
        if types:

            for resource_type in types:
                resource_type = resource_type.rstrip('s')
                resource_atrrs = []
                if deref == 'name' and resource_type == 'zone':
                    attr = 'domain'
                else:
                    attr = deref

                for tag in tags.filter(**tag_unique,
                                       resource_type=resource_type):

                    if deref == 'id':
                        resource_atrrs.append(tag.resource_id)
                    else:
                        resource = tag.resource
                        if resource:
                            resource_atrrs.append(getattr(resource, attr))

                if resource_atrrs:
                    item[resource_type + 's'] = resource_atrrs
        data.append(item)

    if sort == "resource_count" and types:
        data.sort(key=lambda x: x['resource_count'],
                  reverse=reverse)
    elif sort == 'key':
        data.sort(key=lambda x: list(x['tag'])[0],
                  reverse=reverse)

    try:
        start = int(start)
        limit = int(limit)
    except (ValueError, TypeError):
        start = 0
        limit = 100

    if only and data:
        only_list = [field for field in data[0]
                     if field in only.split(',')]
        data = [{k: v for k, v in d.items() if k in only_list} for d in data]

    meta = {
        'total': len(data),
        'returned': len(data[start:start + limit]),
        'sort': sort,
        'start': start
    }

    return data[start:start + limit], meta


def get_tags_for_resource(owner, resource_obj, *args, **kwargs):
    return {tag.key: tag.value
            for tag in get_tag_objects_for_resource(
                owner, resource_obj, args, kwargs)}


def get_tag_objects_for_resource(owner, resource_obj, *args, **kwargs):
    return Tag.objects(
        owner=owner,
        resource_type=resource_obj.to_dbref().collection.rstrip('s'),
        resource_id=resource_obj.id)


def add_tags_to_resource(owner, resources, tags, *args, **kwargs):
    """
    This function gets a dict of tags in the form
    {'key1': 'value1',..,'key_i','value_i'}, or a list of key,value tuples
    (api-v1-implementation) and a list of dict-like resource objects
    with keys 'resource_type', 'resource_id'. For every resource, already
    existing tags in the request will be filtered out, existing tags with
    common keys will by updated, and non-existing will be added.
    :param owner: the resource owner
    :param resources: the resource objects where the tags will be added
    :param tags: list of tags to be added
    """

    tag_objects = []
    missing_resources = get_missing_resources()
    rtypes_to_update = set()
    for resource in resources:
        resource_type = resource.get('resource_type').rstrip('s')
        resource_id = resource.get('resource_id')

        if resource_id in missing_resources[resource_type]:
            raise NotFoundError(msg=f'{resource_type} {resource_id}')
        try:
            resource_obj = get_resource_model(
                resource_type).objects(id=resource_id).get()
        except me.DoesNotExist:
            raise NotFoundError(msg=f'{resource_type} {resource_id}')

        existing_tags = get_tags_for_resource(owner, resource_obj)

        tag_dict = {
            k: v for k, v
            in dict(tags).items() - existing_tags.items()
        }
        if tag_dict:
            # Remove existing tags with common keys with the tags to be added,
            # in order to update them.
            remove_tags_from_resource(owner, [resource], tag_dict)

            rtypes_to_update.add(resource_type + 's')
            tag_objects.extend([Tag(owner=owner, resource_id=resource_id,
                                    resource_type=resource_type, key=key,
                                    value=value)
                                for key, value in tag_dict.items()])

            # SEC
            owner.mapper.update(resource_obj)
    Tag.objects.insert(tag_objects)
    trigger_session_update(owner, list(rtypes_to_update))


def remove_tags_from_resource(owner, resources, tags, *args, **kwargs):
    """
    This function get a list of tags in the form {'key1': 'value1',
    'key2': 'value2'} and a list of dict-like resource objects
    with keys 'resource_type', 'resource_id'.
    :param owner: the resource owner
    :param resources: the resource objects from which the tags will be removed
    :param rtype: resource type
    :param tags: list of tags to be deleted
    """
    # ensure there are no duplicate tag keys because mongoengine will
    # raise exception for duplicates in query
    key_list = list(dict(tags))
    # create a query that will return all the tags with the specified keys
    query = reduce(lambda q1, q2: q1.__or__(q2),
                   [Q(key=key) for key in key_list])

    resource_query = Q()
    missing_resources = get_missing_resources()
    rtypes_to_update = set()

    for resource in resources:
        resource_type = resource.get('resource_type').rstrip('s')
        resource_id = resource.get('resource_id')

        if resource_id in missing_resources[resource_type]:
            raise NotFoundError(msg=f'{resource_type} {resource_id}')

        resource_query |= Q(owner=owner,
                            resource_id=resource_id,
                            resource_type=resource_type)
        rtypes_to_update.add(resource_type + 's')
        # SEC
        owner.mapper.update(
            get_resource_model(resource_type).
            objects(id=resource_id).get())

    query &= resource_query
    Tag.objects.filter(query).delete()
    trigger_session_update(owner, list(rtypes_to_update))


def resolve_id_and_get_tags(owner, rtype, rid, *args, **kwargs):
    """
    This call will try to fetch the object of type rtype from the db with id
    rid. If the object is of type machine, image, network or location the
    cloud_id must also be provided in the kwargs. If the resource type is
    machine then the machine_id must be provided and not the object id. Whether
    or not the owner has the necessary credentials to get the tags of the
    resource is left to the caller of this function to validate.
    :param owner: the owner of the resource
    :param rtype: resource type
    :param rid: resource id
    :return: the tags of this resource
    """
    resource_obj = get_object_with_id(owner, rid, rtype, *args, **kwargs)
    return get_tags_for_resource(owner, resource_obj)


def can_modify_resources_tags(auth_context, resources, tags, op: str) -> bool:
    """
    This method checks edit_tags permission, and whether security
    tags are modified. In either case, if the user belongs to the owner
    team, the result is true.
    Security tags are part of team policies. The only occasion where a
    non-owner can have security tags in his tag request in his tag request
    is if the security tags allready exist in the resource.
    :param auth_context: the auth_context of the request
    :param resources: the resources on which the tags are going to be applied.
    A list of dict-like objects with keys 'resource_type', 'resource_id'
    :param tags: the new tags dict
    :return: False, if the user  is not owner, and doesn't have edit_tags
    permission, or security_tags are going to be modified. True otherwise
    """

    if auth_context.org and not auth_context.is_owner():
        tags = dict(tags)
        need_sec_tags_check = False

        security_tags = [(k, v) for tag in auth_context.get_security_tags()
                         for k, v in tag.items()]
        common_keys = set(dict(security_tags)).intersection(set((tags)))
        common_tags = set(security_tags).intersection(set(tags.items()))
        if common_keys:
            if op == 'remove':
                return False

            for key in common_keys:
                if key not in (ctag[0] for ctag in common_tags):
                    return False
            need_sec_tags_check = True

        for resource in resources:
            resource_type = resource.get('resource_type').rstrip('s')
            resource_id = resource.get('resource_id')

            try:
                auth_context.check_perm(resource_type, 'edit_tags',
                                        resource_id)
            except PolicyUnauthorizedError:
                return False

            if need_sec_tags_check:
                existing_tags = {(tag.key, tag.value)
                                 for tag in Tag.objects(
                                     owner=auth_context.owner,
                                     resource_type=resource_type,
                                     resource_id=resource_id)}
                if not common_tags.issubset(existing_tags):
                    return False
    return True


def get_missing_resources() -> dict:
    """
    This method runs a query and returns the taggable resources
    that are missing, deleted, or disabled.
    """

    dikt = {rtype: [] for rtype in TAGS_RESOURCE_TYPES}
    states_rtypes = {
        'deleted': ['cloud', 'key', 'script', 'template'],
        'missing_since': ['machine', 'cluster', 'network',
                          'volume', 'image', 'subnet']
    }
    for state, rtypes in states_rtypes.items():
        condition = None if state == 'missing_since' else False
        for resource_type in rtypes:
            query = Q(**{f'{state}__ne': condition})
            if resource_type == 'cloud':
                query |= Q(**{'enabled': False})
            try:
                resource_objs = get_resource_model(
                    resource_type).objects(query)
            except KeyError:
                continue
            if resource_objs:
                dikt[resource_type] += [obj.id for obj in resource_objs]

    return dikt
