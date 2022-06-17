import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI


def migrate_schedule_actions():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_schedules = db['schedules']
    failed = migrated = skipped = 0
    for schedule in db_schedules.find():
        print('Updating schedule action ' + schedule['_id'])
        try:
            try:
                action = schedule['task_type']
            except Exception:
                print('Field task_type has been already migrated')
                skipped += 1
                continue
            update_unset_result = db_schedules.update_one(
                {'_id': schedule['_id']},
                {'$unset': {'task_type': ''}}
            )
            update_set_result = db_schedules.update_one(
                {'_id': schedule['_id']},
                {'$set': {'actions': [action]}}
            )
            print(update_unset_result.modified_count)
            if update_unset_result.modified_count > 0 and update_set_result.modified_count > 0:
                print(f'Successfully migrated schedule action: '
                      f'with id: {schedule["_id"]} ')
                migrated += 1
            else:
                skipped += 1
        except Exception:
            print(f'*** WARNING ** Could not migrate schedule action '
                    f'with id: {schedule["_id"]} ')
            traceback.print_exc()
            failed += 1
            continue

    print(f'Schedules migrated: {str(migrated)}')
    print(f'Schedules skipped: {str(skipped)}')
    print(f'Failed to migrate: {str(failed)}')


if __name__ == '__main__':
    migrate_schedule_actions()