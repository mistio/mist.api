import logging
from mist.api.dramatiq_app import dramatiq

log = logging.getLogger(__name__)


@dramatiq.actor(queue_name='dramatiq_tags', store_results=True)
def update_tags(resource, tag_dict):
    try:
        resource.update_tags(tag_dict)
    except Exception as e:
        log.error('%r' % e)
        raise e


@dramatiq.actor(queue_name='dramatiq_tags', store_results=True)
def delete_tags(resource, key_list):
    try:
        resource.delete_tags(key_list)
    except Exception as e:
        log.error('%r' % e)
        raise e
