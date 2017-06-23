from mist.api.dns.models import Zone
from mist.api.users.models import User, Owner, Organization
from mist.api.clouds.models import Cloud
from mist.api.tag.methods import get_tags_for_resource
from mist.api.auth.methods import auth_context_from_request

from mist.api.exceptions import PolicyUnauthorizedError

from mist.api import config

import logging

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)


def list_zones(owner, cloud):
    """List zones returning all zones for an owner"""
    log.warn('Running list zones for user %s, cloud %s', owner.id, cloud.id)
    if not hasattr(cloud.ctl, 'dns'):
        return []
    else:
        zones_ret = []
        zones = cloud.ctl.dns.list_zones()
        for zone in zones:
            zone_dict = zone.as_dict()
            zone_dict['records'] = list_records(owner, zone)
            zone_dict["tags"] = get_tags_for_resource(owner, zone)
            zones_ret.append(zone_dict)
    log.warn('Returning list zones for user %s, cloud %s', owner.id, cloud.id)
    return zones_ret

def filter_list_zones(auth_context, cloud, zones=None, perm='read'):
    """List zone entries based on the permissions granted to the user."""

    if zones is None:
        zones = list_zones(auth_context.owner, cloud)
    if not zones:  # Exit early in case the cloud provider returned 0 zones.
        return {'cloud_id': cloud.id, 'zones': []}
    if not auth_context.is_owner():
        return_zones = []
        try:
            auth_context.check_perm('cloud', 'read', cloud.id)
        except PolicyUnauthorizedError:
            return {'cloud_id': cloud.id, 'zones': []}
        allowed_zones = set(auth_context.get_allowed_resources(rtype='zones'))
        for zone in zones:
            if zone['id'] in allowed_zones:
                zone_obj = Zone.objects.get(owner=auth_context.owner, cloud=cloud,
                                            id=zone['id'])
                zone['records'] = filter_list_records(auth_context, zone_obj)
                return_zones.append(zone)
        zones = return_zones
    return {'cloud_id': cloud.id, 'zones': zones}

def list_records(owner, zone):
    """List records returning all records for an owner"""

    if not isinstance(zone, Zone):
        zone = Zone.objects.get(zone)
    log.warn('Running list records for user %s, zone %s', owner.id, zone.id)
    recs = []
    records = zone.ctl.list_records()
    for record in records:
        record_dict = record.as_dict()
        record_dict["tags"] = get_tags_for_resource(owner, record)
        recs.append(record_dict)
    log.warn('Returning list records for user %s, zone %s', owner.id, zone.id)
    return recs

def filter_list_records(auth_context, zone, perm='read'):
    """List record entries based on the permissions granted to the user."""

    recs = []
    records = list_records(auth_context.owner, zone)
    if not records:  # Exit early in case the cloud provider returned 0 records.
        return recs
    if not auth_context.is_owner():
        try:
            auth_context.check_perm('zone', 'read', zone.id)
        except PolicyUnauthorizedError:
            return recs
        allowed_records = set(auth_context.get_allowed_resources(rtype='records'))
        for record in records:
            if record['id'] in allowed_records:
                recs.append(record)
    return recs
