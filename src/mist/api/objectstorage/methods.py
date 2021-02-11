import logging

from mist.api.objectstorage.models import Bucket


log = logging.getLogger(__name__)


def list_buckets(owner, cloud_id, cached=True):
    if cached:
        buckets = Bucket.objects(
            owner=owner,
            cloud=cloud_id,
            missing_since=None
        )

    else:
        log.error('Not cached request')
        bucket = Bucket(owner=owner)
        buckets = bucket.ctl.objectstorage.list_buckets()

        # Update RBAC Mappings given the list of new secrets.
        owner.mapper.update(buckets, asynchronous=False)

    return [_bucket.as_dict() for _bucket in buckets]


def list_bucket_content(owner, storage_id, path='', cached=True):
    if cached:
        buckets = Bucket.objects.get(
            owner=owner,
            id=storage_id,
            missing_since=None
        )

    else:
        bucket = Bucket(owner=owner)
        buckets = bucket.ctl.objectstorage.list_buckets()

        # Update RBAC Mappings given the list of new secrets.
        owner.mapper.update(buckets, asynchronous=False)

    return buckets.get_content(path)


def filter_list_buckets(auth_context,
                        cloud_id,
                        cached=True,
                        perm='read'):
    buckets = list_buckets(auth_context.owner, cloud_id, cached)
    if not auth_context.is_owner():
        allowed_resources = auth_context.get_allowed_resources(perm)
        for i in range(len(buckets) - 1, -1, -1):
            if buckets[i]['id'] not in allowed_resources['buckets']:
                buckets.pop(i)
    return buckets


def filter_list_bucket_content(auth_context,
                                bucket_id,
                                path='',
                                cached=True):
    return list_bucket_content(auth_context.owner, bucket_id, path, cached)
