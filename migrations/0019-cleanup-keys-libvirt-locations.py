from datetime import datetime


def cleanup_keys():
    """
    Removes trailing chars from private keys
    It has been reported by users but shouldn't normally happen
    """
    from mist.api.keys.models import SSHKey
    for key in SSHKey.objects(deleted=None):
        if key.private.endswith('-'):
            continue
        while len(key.private) and not key.private.endswith('-'):
            key.private = key.private[:-1]
        key.save()


def cleanup_libvirt_cloud_locations():
    """
    Marks CloudLocation objects missing if the respective host is missing
    """
    from mist.api.models import Machine
    from mist.api.clouds.models import CloudLocation, LibvirtCloud
    libvirt_cloud_ids = [loc.id for loc in LibvirtCloud.objects(
        deleted=None).only('id')]

    for loc in CloudLocation.objects(cloud__in=libvirt_cloud_ids):
        try:
            Machine.objects.get(
                cloud=loc.cloud, missing_since=None,
                machine_id=loc.external_id)
        except Machine.DoesNotExist:
            loc.missing_since = datetime.now()
            loc.save()


if __name__ == '__main__':
    cleanup_keys()
    cleanup_libvirt_cloud_locations()
