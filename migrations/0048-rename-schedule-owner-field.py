import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from pymongo.errors import OperationFailure

RENAME_MAPS = {
    'owner': {'owner': 'org'}
}


def rename_schedule_owner_field():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_schedules = db['schedules']
    print(db_schedules.find())
    failed = renamed = skipped = 0
    # drop index containing owner
    try:
        db_schedules.drop_indexes()
    except OperationFailure:
        print("Indexes already dropped")
    for schedule in db_schedules.find():
        for _, rename_map in RENAME_MAPS.items():
            try:
                print("SCHEDULE", schedule['_id'])
                print("RENAME MAP", rename_map)
                update_result = db_schedules.update_one(
                    {'_id': schedule['_id']},
                    {'$rename': rename_map}
                )
                print(update_result.modified_count)
                if update_result.modified_count > 0:
                    print(f'Successfully renamed schedule field: '
                          f'with id: {schedule["_id"]} '
                          f'{rename_map}'.replace(':', ' ->'))
                    renamed += 1
                else:
                    skipped += 1
            except Exception:
                print(f'*** WARNING ** Could not rename schedule field '
                      f'with id: {schedule["_id"]} '
                      f'{rename_map}'.replace(':', ' ->'))
                traceback.print_exc()
                failed += 1
                continue

    print(f'Schedules renamed: {str(renamed)}')
    print(f'Schedules skipped: {str(skipped)}')
    print(f'Failed to rename: {str(failed)}')


if __name__ == '__main__':
    rename_schedule_owner_field()
