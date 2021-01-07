import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI


def migrate_record_id():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_records = db['records']

    # drop index containing zone_id
    db_records.drop_index('zone_1_record_id_1_deleted_1')

    failed = migrated = 0

    for record in db_records.find():
        print('Updating record ' + record['_id'])
        try:
            external_id = record['record_id']
            db_records.update_one(
                {'_id': record['_id']},
                {'$unset': {'record_id': ''}}
            )
            db_records.update_one(
                {'_id': record['_id']},
                {'$set': {'external_id': external_id}}
            )
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1

    print('Records migrated: %d' % migrated)

    if failed:
        print('********* WARNING ************')
        print('Failed to migrate %d records' % failed)

    c.close()


if __name__ == '__main__':
    migrate_record_id()
