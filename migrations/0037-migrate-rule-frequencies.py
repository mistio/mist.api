import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI


def migrate_rule_frequencies():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_rules = db['rules']
    failed = migrated = skipped = 0
    for rule in db_rules.find():
        print('Updating rule frequency ' + rule['_id'])
        try:
            try:
                frequency = rule['frequency']
            except Exception:
                print('Field frequency has been already migrated')
                skipped += 1
                continue
            update_unset_result = db_rules.update_one(
                {'_id': rule['_id']},
                {'$unset': {'frequency': ''}}
            )
            frequency['_cls'] = 'Interval'
            update_set_result = db_rules.update_one(
                {'_id': rule['_id']},
                {'$set': {'when': frequency}}
            )
            update_count_1 = update_unset_result.modified_count
            update_count_2 = update_set_result.modified_count
            if update_count_1 > 0 and update_count_2 > 0:
                print(f'Successfully migrated rule frequency: '
                      f'with id: {rule["_id"]} ')
                migrated += 1
            else:
                skipped += 1
        except Exception:
            print(f'*** WARNING ** Could not migrate rule frequency '
                  f'with id: {rule["_id"]} ')
            traceback.print_exc()
            failed += 1
            continue

    print(f'Rules migrated: {str(migrated)}')
    print(f'Rules skipped: {str(skipped)}')
    print(f'Failed to migrate: {str(failed)}')


if __name__ == '__main__':
    migrate_rule_frequencies()
