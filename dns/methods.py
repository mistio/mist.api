from mist.io.dns.models import Zone
from mist.io.users.models import User, Owner, Organization
from mist.io.clouds.models import Cloud

from mist.io import config

import logging

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)


def list_zones(owner, cloud):
    """List zones returning all zones for an owner"""
    log.warn('Running list zones for user %s, cloud %s', owner.id, cloud.id)
    ret = {}
    if not hasattr(cloud.ctl, 'dns'):
        ret = {'cloud_id': cloud.id, 'zones': []}
    else:
        zones_ret = []
        zones = cloud.ctl.dns.list_zones()

        for zone in zones:
            zone_dict = zone.as_dict()
            zone_dict['records'] = [record.as_dict() for
                                    record in zone.ctl.list_records()]
            zones_ret.append(zone_dict)
        ret = {'cloud_id': cloud.id, 'zones': zones_ret}
    log.warn('Returning list zones for user %s, cloud %s', owner.id, cloud.id)
    return ret


def filter_list_zones(auth_context, cloud, perm='read'):
    """List zone entries based on the permissions granted to the user."""
    zones = list_zones(auth_context.owner, cloud)
    if not auth_context.is_owner():
        zones = [zone for zone in zones if zone['id']
                 in auth_context.get_allowed_resources(rtype='zones')]
    return zones
