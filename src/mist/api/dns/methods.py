from mist.api.clouds.models import Cloud
from mist.api.tag.methods import get_tags_for_resource

from mist.api.exceptions import PolicyUnauthorizedError

from mist.api import config

import logging

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)


def list_zones(owner, cloud_id):
    """List zones returning all zones for an owner"""
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id)
    except Cloud.DoesNotExist:
        return []
    log.warn('Running list zones for user %s, cloud %s', owner.id, cloud.id)
    if not hasattr(cloud.ctl, 'dns'):
        return []
    else:
        zones_ret = []
        zones = cloud.ctl.dns.list_zones()
        for zone in zones:
            zone_dict = zone.as_dict()
            zone_dict['records'] = list_records(owner, zone)
            zone_dict['tags'] = get_tags_for_resource(owner, zone)
            zones_ret.append(zone_dict)
    log.warn('Returning list zones for user %s, cloud %s', owner.id, cloud.id)
    return zones_ret


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


def list_records(owner, zone):
    """List records returning all records for an owner"""
    log.warn('Running list records for user %s, zone %s', owner.id, zone.id)
    recs = []
    records = zone.ctl.list_records()
    for record in records:
        record_dict = record.as_dict()
        record_dict['tags'] = get_tags_for_resource(owner, record)
        recs.append(record_dict)
    log.warn('Returning list records for user %s, zone %s', owner.id, zone.id)
    return recs


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
