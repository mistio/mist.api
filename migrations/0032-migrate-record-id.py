import traceback

from pymongo import MongoClient
from pymongo.errors import OperationFailure

from mist.api.config import MONGO_URI


def migrate_record_id():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_records = db['records']

    # drop index containing record_id
    try:
        db_records.drop_index('zone_1_record_id_1_deleted_1')
    except OperationFailure:
        print("Index already dropped")

    failed = migrated = skipped = 0

    for record in db_records.find():
        if not record.get('record_id', None):
            skipped += 1
            continue
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

    if skipped:
        print('Records skipped: %d' % skipped)

    if failed:
        print('********* WARNING ************')
        print('Failed to migrate %d records' % failed)

    c.close()


if __name__ == '__main__':
    migrate_record_id()
