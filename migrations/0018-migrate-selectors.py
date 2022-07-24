import traceback
from datetime import datetime

from pymongo import MongoClient

from mist.api.config import MONGO_URI

COLLECTIONS = ('schedules', 'rules')
SELECTOR_CLS_NEW_NAME = {
    'GenericResourceSelector': 'ResourceSelector',
    'MachinesAgeSelector': 'AgeSelector',
    'MachinesSelector': 'ResourceSelector'
}


def migrate_selectors():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    for collection in COLLECTIONS:
        db_collection = db[collection]
        for cls, newcls in SELECTOR_CLS_NEW_NAME.items():
            query = {'selectors._cls': cls}
            value = {'$set': {'selectors.$._cls': newcls}}
            if cls == 'MachinesSelector':
                value['$set']['resource_model_name'] = 'machine'
            try:
                db_collection.update_many(query, value)
            except Exception:
                traceback.print_exc()
            else:
                print(f'{db_collection.name}: selectors._cls rename '
                      f'{cls} -> {newcls} - OK!')


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
    libvirt_cloud_ids = [l.id for l in LibvirtCloud.objects(
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
    migrate_selectors()
    cleanup_keys()
    cleanup_libvirt_cloud_locations()
