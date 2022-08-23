import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI


def migrate_schedule_types():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_schedules = db['schedules']
    failed = migrated = skipped = 0
    for schedule in db_schedules.find():
        print('Updating schedule type ' + schedule['_id'])
        try:
            try:
                schedule_type = schedule['schedule_type']
            except Exception:
                print('Field schedule_type has been already migrated')
                skipped += 1
                continue
            update_unset_result = db_schedules.update_one(
                {'_id': schedule['_id']},
                {'$unset': {'schedule_type': ''}}
            )
            update_set_result = db_schedules.update_one(
                {'_id': schedule['_id']},
                {'$set': {'when': schedule_type}}
            )
            print(update_unset_result.modified_count)
            update_count_1 = update_unset_result.modified_count
            update_count_2 = update_set_result.modified_count
            if update_count_1 > 0 and update_count_2 > 0:
                print(f'Successfully migrated schedule type: '
                      f'with id: {schedule["_id"]} ')
                migrated += 1
            else:
                skipped += 1
        except Exception:
            print(f'*** WARNING ** Could not migrate schedule type '
                  f'with id: {schedule["_id"]} ')
            traceback.print_exc()
            failed += 1
            continue

    print(f'Schedules migrated: {str(migrated)}')
    print(f'Schedules skipped: {str(skipped)}')
    print(f'Failed to migrate: {str(failed)}')


if __name__ == '__main__':
    migrate_schedule_types()
