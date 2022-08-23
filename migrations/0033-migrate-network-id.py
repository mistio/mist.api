import traceback

from pymongo import MongoClient
from pymongo.errors import OperationFailure
from mist.api.config import MONGO_URI


def migrate_network_id():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_networks = db['networks']

    # drop index containing network_id
    try:
        db_networks.drop_index('cloud_1_network_id_1')
    except OperationFailure:
        print("Index already dropped")

    failed = migrated = skipped = 0

    for network in db_networks.find():
        if not network.get('network_id', None):
            skipped += 1
            continue

        print('Updating network ' + network['_id'])
        try:
            external_id = network['network_id']
            db_networks.update_one(
                {'_id': network['_id']},
                {'$unset': {'network_id': ''}}
            )
            db_networks.update_one(
                {'_id': network['_id']},
                {'$set': {'external_id': external_id}}
            )
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1

    print('Networks migrated: %d' % migrated)

    if skipped:
        print('Networks skipped: %d' % skipped)

    if failed:
        print('********* WARNING ************')
        print('Failed to migrate %d networks' % failed)

    c.close()


if __name__ == '__main__':
    migrate_network_id()
