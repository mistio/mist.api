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
    ret = {}
    if not hasattr(cloud.ctl, 'dns'):
        ret = []
    else:
        zones_ret = []
        zones = cloud.ctl.dns.list_zones()

        for zone in zones:
            recs = []
            zone_dict = zone.as_dict()
            for record in zone.ctl.list_records():
                rec = record.as_dict()
                rec["tags"] = get_tags_for_resource(owner, record)
                recs.append(rec)
            zone_dict['records'] = recs
            zone_dict["tags"] = get_tags_for_resource(owner, zone)
            zones_ret.append(zone_dict)
        ret = zones_ret
    log.warn('Returning list zones for user %s, cloud %s', owner.id, cloud.id)
    return ret

def filter_list_zones(auth_context, cloud, perm='read'):
    """List zone entries based on the permissions granted to the user."""
    zones = list_zones(auth_context.owner, cloud)
    if not auth_context.is_owner():
        try:
            auth_context.check_perm('cloud', 'read', cloud.id)
        except PolicyUnauthorizedError:
            return []
        allowed_zones = set(auth_context.get_allowed_resources(rtype='zones'))
        zones = [zone for zone in zones if zone['id'] in allowed_zones]
        print "zones: %s " % zones
    return {'cloud_id': cloud.id, 'zones': zones}
