import traceback
from pymongo import MongoClient
from mist.api.config import MONGO_URI


def rename_schedule_task_enabled_field():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_schedules = db['schedules']
    failed = renamed = skipped = 0
    for schedule in db_schedules.find():
        skipped_all = True
        try:
            update_result = db_schedules.update_many(
                {}, {'$rename': {'task_enabled': 'enabled'}})
            if update_result.modified_count > 0:
                print('Successfully renamed schedule field: '
                      '`task_enabled` -> `enabled`')
                skipped_all = False
        except Exception:
            print('*** WARNING ** Could not rename schedule task_enabled '
                  'field for %s' % schedule['_id'])
            traceback.print_exc()
            failed += 1
            continue
        else:
            if skipped_all:
                skipped += 1
                print('Skipped')
            else:
                renamed += 1

    print('Schedules renamed: ' + str(renamed))
    print('Schedules skipped: ' + str(skipped))
    print('Failed to rename: ' + str(failed))


if __name__ == '__main__':
    rename_schedule_task_enabled_field()
