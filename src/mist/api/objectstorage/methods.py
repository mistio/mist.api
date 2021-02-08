import logging

from mist.api.objectstorage.models import ObjectStorage


log = logging.getLogger(__name__)


def list_storage(owner, cloud_id, cached=True):
    if cached:
        storage = ObjectStorage.objects(
            owner=owner,
            cloud=cloud_id,
            missing_since=None
        )

    else:
        log.error('Not cached request')
        # TODO: is there a better way?
        store = ObjectStorage(owner=owner)
        storage = store.ctl.objectstorage.list_storage()

        # Update RBAC Mappings given the list of new secrets.
        owner.mapper.update(storage, asynchronous=False)

    return [_store.as_dict() for _store in storage]


def list_storage_content(owner, storage_id, path='', cached=True):
    if cached:
        storage = ObjectStorage.objects.get(
            owner=owner,
            id=storage_id,
            missing_since=None
        )

    else:
        # TODO: is there a better way?
        store = ObjectStorage(owner=owner)
        storage = store.ctl.objectstorage.list_storage()

        # Update RBAC Mappings given the list of new secrets.
        owner.mapper.update(storage, asynchronous=False)

    return storage.get_content(path)


def filter_list_object_storage(auth_context, cloud_id, cached=True, perm='read'):
    storage = list_storage(auth_context.owner, cloud_id, cached)
    if not auth_context.is_owner():
        allowed_resources = auth_context.get_allowed_resources(perm)
        for i in range(len(storage) - 1, -1, -1):
            if storage[i]['id'] not in allowed_resources['objectstorage']:
                storage.pop(i)
    return storage


def filter_list_storage_content(auth_context, storage_id, path='', cached=True):
    return list_storage_content(auth_context.owner, storage_id, path, cached)
