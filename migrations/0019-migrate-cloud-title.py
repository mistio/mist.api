import traceback

from pymongo import MongoClient
from pymongo import errors
from mist.api.config import MONGO_URI


def migrate_clouds():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_clouds = db['clouds']

    # drop index containing title
    try:
        db_clouds.drop_index('owner_1_title_1_deleted_1')
    except errors.OperationFailure:
        pass

    failed = migrated = 0

    for cloud in db_clouds.find():
        print('Updating cloud ' + cloud['_id'])
        try:
            cloud_name = cloud['title']
            db_clouds.update_one(
                {'_id': cloud['_id']},
                {'$unset': {'title': ''}}
            )
            db_clouds.update_one(
                {'_id': cloud['_id']},
                {'$set': {'name': cloud_name}}
            )
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1

    print('Clouds migrated: %d' % migrated)

    if failed:
        print('********* WARNING ************')
        print('Failed to migrate %d clouds' % failed)

    c.close()


if __name__ == '__main__':
    migrate_clouds()
