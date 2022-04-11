import traceback

from pymongo import MongoClient
from pymongo.errors import OperationFailure

from mist.api.config import MONGO_URI


def migrate_subnet_id():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_subnets = db['subnets']

    # drop index containing subnet_id
    try:
        db_subnets.drop_index('network_1_subnet_id_1')
    except OperationFailure:
        print("Index already dropped")

    failed = migrated = skipped = 0

    for subnet in db_subnets.find():
        if not subnet.get('subnet_id', None):
            skipped += 1
            continue

        print('Updating subnet ' + subnet['_id'])
        try:
            external_id = subnet['subnet_id']
            db_subnets.update_one(
                {'_id': subnet['_id']},
                {'$unset': {'subnet_id': ''}}
            )
            db_subnets.update_one(
                {'_id': subnet['_id']},
                {'$set': {'external_id': external_id}}
            )
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1

    print('Subnets migrated: %d' % migrated)

    if skipped:
        print('Subnets skipped: %d' % skipped)

    if failed:
        print('********* WARNING ************')
        print('Failed to migrate %d subnets' % failed)

    c.close()


if __name__ == '__main__':
    migrate_subnet_id()
