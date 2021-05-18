from mist.api.clouds.models import Cloud

from mist.api.exceptions import PolicyUnauthorizedError, CloudNotFoundError

from mist.api import config

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


def filter_list_zones(auth_context, cloud_id, zones=None, perm='read',
                      cached=False):
    """Filter the zones of the specific cloud based on the RBAC policy"""
    if zones is None:
        zones = list_zones(auth_context.owner, cloud_id, cached=cached)
    if auth_context.is_owner():
        return zones
    else:
        allowed_resources = auth_context.get_allowed_resources(perm)
        if cloud_id not in allowed_resources['clouds']:
            return []
        filtered = []
        for zone in zones:
            if zone['id'] in allowed_resources['zones']:
                for rec in list(zone['records']):
                    if rec not in allowed_resources['records']:
                        zone['records'].pop(rec)
                filtered.append(zone)
        return filtered


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
