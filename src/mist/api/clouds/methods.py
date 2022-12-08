import re

import mist.api.clouds.models as cloud_models

from mist.api.clouds.models import Cloud

from mist.api.helpers import trigger_session_update

from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import BadRequestError, NotFoundError

from mist.api.monitoring.methods import disable_monitoring_cloud

from mist.api import config

import logging

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)

log = logging.getLogger(__name__)


def validate_cloud_name(name):
    if not re.search(r'^[0-9a-zA-Z]+[0-9a-zA-Z-_ .]{0,}[0-9a-zA-Z]+$', name):
        raise BadRequestError(
            "Cloud name may only contain ASCII letters, "
            "numbers, dashes and dots")
    return name


def add_cloud(owner, name, provider, user, params):
    """Add cloud to owner"""
    # FIXME: Some of these should be explicit arguments, others shouldn't exist
    fail_on_error = params.pop('fail_on_error',
                               params.pop('remove_on_error', True))
    params.pop('name', None)
    params.pop('provider', None)
    # Find proper Cloud subclass.
    if not provider:
        raise RequiredParameterMissingError("provider")

    name = validate_cloud_name(name)
    log.info("Adding new cloud in provider '%s'", provider)
    if provider not in cloud_models.CLOUDS:
        raise BadRequestError("Invalid provider '%s'." % provider)
    cloud_cls = cloud_models.CLOUDS[provider]  # Class of Cloud model.

    # Add the cloud.
    cloud = cloud_cls.add(owner, name, user, fail_on_error=fail_on_error,
                          fail_on_invalid_params=False, **params)
    ret = {
        'cloud_id': cloud.id,
        'errors': getattr(cloud,
                          'errors', []),  # just an attribute, not a field
    }

    log.info("Cloud with id '%s' added successfully.", cloud.id)

    return ret


def rename_cloud(owner, cloud_id, new_name):
    """Renames cloud with given cloud_id."""
    log.info("Renaming cloud: %s", cloud_id)
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    new_name = validate_cloud_name(new_name)
    cloud.ctl.rename(new_name)
    log.info("Successfully renamed cloud '%s'", cloud_id)
    trigger_session_update(owner, ['clouds'])


def remove_cloud(owner, cloud_id, delete_from_vault=False):
    """Deletes cloud with given cloud_id."""

    log.info("Deleting cloud: %s", cloud_id)

    try:
        disable_monitoring_cloud(owner, cloud_id)
    except Exception as exc:
        log.warning("Couldn't disable monitoring before deleting cloud. "
                    "Error: %r", exc)

    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        cloud.ctl.delete()
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    log.info("Successfully deleted cloud '%s'", cloud_id)

    if delete_from_vault and cloud._private_fields:
        private_field = getattr(cloud, cloud._private_fields[0])
        private_field.secret.delete(delete_from_engine=True)

    trigger_session_update(owner, ['clouds'])


def purge_cloud(cloud_id):
    from mist.api.machines.models import Machine
    from mist.api.networks.models import Network
    from mist.api.volumes.models import Volume
    from mist.api.containers.models import Cluster
    from mist.api.dns.models import Zone, Record  # noqa
    from mist.api.poller.models import CloudPollingSchedule
    from mist.api.clouds.models import CloudLocation, CloudSize
    from mist.api.images.models import CloudImage

    referencing_types = [
        Cluster, Machine, Volume, Zone, Network, CloudPollingSchedule,
        CloudImage, CloudSize, CloudLocation,
    ]
    for rtype in referencing_types:
        rtype.objects(cloud=cloud_id).delete()
    Cloud.objects(id=cloud_id).delete()


# SEC
def filter_list_clouds(auth_context, query_filter=None, sort=None,
                       perm='read', as_dict=True):
    """Returns a list of clouds, which is filtered based on RBAC Mappings for
    non-Owners.
    """
    clouds = list_clouds(auth_context.owner, query_filter=query_filter,
                         sort=sort, as_dict=as_dict)
    if not auth_context.is_owner():
        clouds = [cloud for cloud in clouds if cloud['id'] in
                  auth_context.get_allowed_resources(rtype='clouds')]
    return clouds


def list_clouds(owner, query_filter=None, sort=None, as_dict=True):
    # TODO: apply query_filter & sorting
    clouds = Cloud.objects(owner=owner, deleted=None)
    if as_dict:
        if as_dict == 'v2':
            return [cloud.as_dict_v2() for cloud in clouds]
        else:
            return [cloud.as_dict() for cloud in clouds]
    else:
        return clouds
