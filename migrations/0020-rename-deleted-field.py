from pymongo import MongoClient
from mist.api.config import MONGO_URI

RENAME_MAPS = {
    'zones': {'deleted': 'missing_since'},
    'records': {'deleted': 'missing_since'},
    'stack': {'deleted_at': 'deleted'},
    'template': {'deleted_at': 'deleted'},
}


def rename_deleted_field():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    for collection, rename_map in RENAME_MAPS.items():
        db_collection = db[collection]
        update_result = db_collection.update_many(
            {}, {'$rename': rename_map})
        if update_result.modified_count > 0:
            print(f'Successfully renamed {collection} field: '
                  f'{rename_map}'.replace(':', ' ->'))


if __name__ == '__main__':
    rename_deleted_field()
