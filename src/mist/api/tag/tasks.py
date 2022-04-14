from mist.api.dramatiq_app import dramatiq
from mist.api.helpers import get_resource_model
from mongoengine import ValidationError, DoesNotExist


@dramatiq.actor(queue_name='dramatiq_tags',  max_retries=0)
def update_tags(resource_type, resource_id, tag_dict):
    try:
        get_resource_model(resource_type).objects.get(
            id=resource_id).update_tags(tag_dict)
    except (DoesNotExist, ValidationError) as exc:
        update_tags.logger.error(
            'Saving tag  on %s (id%s)failed with %r',
            tag_dict, resource_type, resource_id, exc)


@dramatiq.actor(queue_name='dramatiq_tags', max_retries=0)
def delete_tags(resource_type, resource_id, key_list):
    try:
        get_resource_model(resource_type).objects.get(
            id=resource_id).delete_tags(key_list)
    except (DoesNotExist, ValidationError) as exc:
        update_tags.logger.error(
            'Deleting tag %s on %s (id%s)failed with %r',
            key_list, resource_type, resource_id, exc)
