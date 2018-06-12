import logging

import requests

from mist.api.celery_app import app

from mist.api import config
from mist.api.portal.models import Portal, AvailableUpgrade
from mist.api.metering.methods import get_current_portal_usage


log = logging.getLogger(__name__)


def get_version_params(portal=None):
    if portal is None:
        portal = Portal.get_singleton()
    params = {
        'portal_id': portal.id,
        'created_at': str(portal.created_at),
        'license_key': config.LICENSE_KEY,
    }
    for key, value in config.VERSION.iteritems():
        params['version_%s' % key] = value
    for key, value in get_current_portal_usage().items():
        params['usage_%s' % key] = value
    return params


@app.task
def check_new_versions(url="https://mist.io/api/v1/version-check"):
    portal = Portal.get_singleton()
    params = get_version_params(portal)

    log.info("Will check for new versions. Url %s - Params %s", url, params)
    resp = requests.get(url, params)
    if not resp.ok:
        log.error("Bad response while checking for new versions: %s: %s",
                  resp.status_code, resp.text)
        raise Exception("%s: %s" % (resp.status_code, resp.text))
    portal.available_upgrades = []
    for version in resp.json():
        available_upgrade = AvailableUpgrade()
        for key in ('name', 'sha'):
            if key not in version:
                log.warning("Missing required field '%s' from version.", key)
                break
            available_upgrade[key] = version[key]
        else:
            portal.available_upgrades.append(available_upgrade)
    portal.save()


def get_usage_params(portal=None):
    if portal is None:
        portal = Portal.get_singleton()
    params = get_version_params(portal=portal)
    # Inject more info into params
    return params


@app.task
def usage_survey(url="https://mist.io/api/v1/usage-survey"):
    portal = Portal.get_singleton()
    params = get_usage_params(portal)

    log.info("Will send usage info. Url %s - Params %s", url, params)
    resp = requests.get(url, params)
    if not resp.ok:
        log.error("Bad response while sending usage info: %s: %s",
                  resp.status_code, resp.text)
        raise Exception("%s: %s" % (resp.status_code, resp.text))
