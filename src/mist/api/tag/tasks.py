from mist.api.dramatiq_app import dramatiq
from mist.api.helpers import get_resource_model
from mongoengine import ValidationError, DoesNotExist


@dramatiq.actor(queue_name='dramatiq_tags', max_retries=0)
def update_tags(tag_objects):
    resources = set(
        [(x['resource_type'], x['resource_id'])
         for x in tag_objects])

    for resource in resources:
        resource_type, resource_id = resource
        tags = {
            x['key']: x['value'] for x in tag_objects
            if (x['resource_type'], x['resource_id']) == resource}

        try:
            get_resource_model(resource_type).objects.get(
                id=resource_id).update_tags(tags)
        except (DoesNotExist, ValidationError) as exc:
            update_tags.logger.error(
                'Saving tag  on %s (id%s)failed with %r',
                tags, resource_type, resource_id, exc)


@dramatiq.actor(queue_name='dramatiq_tags', max_retries=0)
def delete_tags(tag_objects):
    resources = set(
        [(x['resource_type'], x['resource_id'])
         for x in tag_objects])

    for resource in resources:
        resource_type, resource_id = resource
        key_list = [
            x['key'] for x in tag_objects
            if (x['resource_type'], x['resource_id']) == resource]
        try:
            get_resource_model(resource_type).objects.get(
                id=resource_id).delete_tags(key_list)
        except (DoesNotExist, ValidationError) as exc:
            delete_tags.logger.error(
                'Deleting tag %s on %s (id%s)failed with %r',
                key_list, resource_type, resource_id, exc)
