import traceback

from pymongo import MongoClient

from mist.api.config import MONGO_URI

COLLECTIONS = ('schedules', 'rules')
SELECTOR_CLS_NEW_NAME = {
    'GenericResourceSelector': 'ResourceSelector',
    'MachinesAgeSelector': 'AgeSelector'
}


def migrate_selectors():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    for collection in COLLECTIONS:
        db_collection = db[collection]
        for cls, newcls in SELECTOR_CLS_NEW_NAME.items():
            query = {'selectors._cls': cls}
            value = {'$set': {'selectors.$._cls': newcls}}
            try:
                db_collection.update_many(query, value)
            except Exception:
                traceback.print_exc()
            else:
                print(f'{db_collection.name}: selectors._cls rename '
                      f'{cls} -> {newcls} - OK!')


if __name__ == '__main__':
    migrate_selectors()
