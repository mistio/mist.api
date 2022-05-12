import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI


def rename_title_field():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_rules = db['rules']
    print(db_rules.find())
    failed = renamed = skipped = 0
    for rule in db_rules.find():
        try:
            print("RULE", rule['_id'])
            update_result = db_rules.update_one(
                {'_id': rule['_id']}, 
                {'$rename': {'title': 'name'}}
            )
            if update_result.modified_count > 0:
                print('Successfully renamed rule field: `title` -> `name`')
                renamed += 1
            else:
                skipped += 1
        except Exception:
            print(f"*** WARNING ** Could not rename key {rule['_id']}")
            traceback.print_exc()
            failed += 1
            continue

    print(f'Rules renamed: {str(renamed)}')
    print(f'Rules skipped: {str(skipped)}')
    print(f'Failed to rename: {str(failed)}')

if __name__ == '__main__':
    rename_title_field()
