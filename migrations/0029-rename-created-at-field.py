from pymongo import MongoClient
from mist.api.config import MONGO_URI


def rename_created_at_field():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    for collection in db.list_collection_names():
        db_collection = db[collection]
        update_result = db_collection.update_many(
            {}, {'$rename': {'created_at': 'created'}})
        if update_result.modified_count > 0:
            print(f'Successfully renamed {collection} field: '
                  '`created_at` -> `created`')


if __name__ == '__main__':
    rename_created_at_field()
