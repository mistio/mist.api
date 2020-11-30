#!/usr/bin/env python

# Rename conditions to selectors


def migrate_selectors(dry=True):
    from pymongo import MongoClient
    from mist.api.config import MONGO_URI, MONGO_DB
    db = MongoClient(MONGO_URI)[MONGO_DB]
    migrated = {
        'schedules': 0,
        'rules': 0
    }

    for collection in ['schedules', 'rules']:
        for document in getattr(db, collection).find({}):
            if document.get('conditions'):
                selectors = document.pop('conditions')
                for selector in selectors:
                    # Rename selector class
                    selector['_cls'] = selector['_cls'].replace(
                        'Condition', 'Selector')
                    # Rename property `tags` to `include`
                    if 'tags' in selector:
                        selector['include'] = selector.pop('tags')
                document['selectors'] = selectors
                if not dry:
                    print("Migrating %s" % collection[:-1])
                    result = getattr(db, collection).replace_one(
                        {'_id': document['_id']}, document)
                    assert result.modified_count == 1
            migrated[collection] += 1

    print("Migrated %d schedules & %d rules" % (
        migrated['schedules'], migrated['rules']))

    if dry:
        print("Dry run, no changes written")


if __name__ == '__main__':
    migrate_selectors(dry=False)
