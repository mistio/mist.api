from mist.api.clouds.models import Cloud
from mist.api.tag.methods import get_tags_for_resource

from mist.api.exceptions import PolicyUnauthorizedError

from mist.api import config

from mist.api.dns.models import Zone

import logging

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)



def list_zones(owner, cloud_id, cached=False):
    """List the zones of the specified cloud"""
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()

    if not hasattr(cloud.ctl, 'dns') or not cloud.dns_enabled:
        return []

    if cached:
        zones = cloud.ctl.dns.list_cached_zones()
    else:
        zones = cloud.ctl.dns.list_zones()

    return [z.as_dict() for z in zones]


def filter_list_zones(auth_context, cloud_id, zones=None, perm='read'):
    """List zone entries based on the permissions granted to the user."""

    if zones is None:
        zones = list_zones(auth_context.owner, cloud_id)
    if not zones:  # Exit early in case the cloud provider returned 0 zones.
        return {'cloud_id': cloud_id, 'zones': []}
    if not auth_context.is_owner():
        return_zones = []
        try:
            auth_context.check_perm('cloud', 'read', cloud_id)
        except PolicyUnauthorizedError:
            return {'cloud_id': cloud_id, 'zones': []}
        allowed_zones = set(auth_context.get_allowed_resources(rtype='zones'))
        allowed_records = set(
            auth_context.get_allowed_resources(rtype='records'))
        for zone in zones:
            if zone['id'] in allowed_zones:
                for idx in reversed(range(len(zone['records']))):
                    if zone['records'][idx]['id'] not in allowed_records:
                        zone['records'].pop(idx)
                return_zones.append(zone)
        zones = return_zones
    return {'cloud_id': cloud_id, 'zones': zones}


def list_records(owner, zone, cached=False):
    """List records returning all records for an owner"""
    records = zone.ctl.list_records(cached=cached)
    return [r.as_dict() for r in records]


def filter_list_records(auth_context, zone, records=None, perm='read'):
    """List record entries based on the permissions granted to the user."""
    recs = []
    if records is None:
        records = list_records(auth_context.owner, zone)
    if not records:  # Exit early in case the cloud provider returned 0 records
        return recs
    if not auth_context.is_owner():
        try:
            auth_context.check_perm('zone', 'read', zone.id)
        except PolicyUnauthorizedError:
            return recs
        allowed_records = set(
            auth_context.get_allowed_resources(rtype='records'))
        for record in records:
            if record['id'] in allowed_records:
                recs.append(record)
        records = recs
    return records
