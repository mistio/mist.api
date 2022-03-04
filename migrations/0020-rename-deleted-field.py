from pymongo import MongoClient
from mist.api.config import MONGO_URI

DB_COLLECTIONS = ['zones', 'records']


def rename_deleted_field():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    for collection in DB_COLLECTIONS:
        db_collection = db[collection]
        update_result = db_collection.update_many(
            {}, {'$rename': {'deleted': 'missing_since'}})
        if update_result.modified_count > 0:
            print(f'Successfully renamed {collection} field: '
                  '`deleted` -> `missing_since`')


if __name__ == '__main__':
    rename_deleted_field()
