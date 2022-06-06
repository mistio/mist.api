import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from pymongo.errors import OperationFailure

RENAME_MAPS = {
    'owner': {'owner_id': 'org_id'},
    'name': {'title': 'name'}
}


def rename_title_and_owner_id_fields():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_rules = db['rules']
    print(db_rules.find())
    failed = renamed = skipped = 0
    # drop index containing owner_id
    try:
        db_rules.drop_indexes()
    except OperationFailure:
        print("Indexes already dropped")
    for rule in db_rules.find():
        for _, rename_map in RENAME_MAPS.items():
            try:
                print("RULE", rule['_id'])
                print("RENAME MAP", rename_map)
                update_result = db_rules.update_one(
                    {'_id': rule['_id']},
                    {'$rename': rename_map}
                )
                print(update_result.modified_count)
                if update_result.modified_count > 0:
                    print(f'Successfully renamed rule field: '
                          f'with id: {rule["_id"]} '
                          f'{rename_map}'.replace(':', ' ->'))
                    renamed += 1
                else:
                    skipped += 1
            except Exception:
                print(f'*** WARNING ** Could not rename rule field '
                      f'with id: {rule["_id"]} '
                      f'{rename_map}'.replace(':', ' ->'))
                traceback.print_exc()
                failed += 1
                continue

    print(f'Rules renamed: {str(renamed)}')
    print(f'Rules skipped: {str(skipped)}')
    print(f'Failed to rename: {str(failed)}')


if __name__ == '__main__':
    rename_title_and_owner_id_fields()
