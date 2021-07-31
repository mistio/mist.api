import traceback

from pymongo import MongoClient, errors
from mist.api.config import MONGO_URI


def migrate_machine_id():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_machines = db['machines']

    # drop index containing machine_id
    try:
        db_machines.drop_index('cloud_1_machine_id_1')
    except errors.OperationFailure:
        pass

    failed = migrated = 0

    for machine in db_machines.find():
        print('Updating machine ' + machine['_id'])
        try:
            external_id = machine['machine_id']
            db_machines.update_one(
                {'_id': machine['_id']},
                {'$unset': {'machine_id': ''}}
            )
            db_machines.update_one(
                {'_id': machine['_id']},
                {'$set': {'external_id': external_id}}
            )
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1

    print('Machines migrated: %d' % migrated)

    if failed:
        print('********* WARNING ************')
        print('Failed to migrate %d machines' % failed)

    c.close()


if __name__ == '__main__':
    migrate_machine_id()
