import traceback

from pymongo import MongoClient
from pymongo.errors import OperationFailure

from mist.api.config import MONGO_URI


def migrate_zone_id():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_zones = db['zones']

    # drop index containing zone_id
    try:
        db_zones.drop_index('cloud_1_zone_id_1_deleted_1')
    except OperationFailure:
        print("Index already dropped")

    failed = migrated = skipped = 0

    for zone in db_zones.find():
        if not zone.get('zone_id', None):
            skipped += 1
            continue

        print('Updating zone ' + zone['_id'])
        try:
            external_id = zone['zone_id']
            db_zones.update_one(
                {'_id': zone['_id']},
                {'$unset': {'zone_id': ''}}
            )
            db_zones.update_one(
                {'_id': zone['_id']},
                {'$set': {'external_id': external_id}}
            )
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1

    print('Zones migrated: %d' % migrated)

    if skipped:
        print('Zones skipped: %d' % skipped)

    if failed:
        print('********* WARNING ************')
        print('Failed to migrate %d zones' % failed)

    c.close()


if __name__ == '__main__':
    migrate_zone_id()
