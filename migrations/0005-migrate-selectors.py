#!/usr/bin/env python

# Rename conditions to selectors


def migrate_selectors(dry = True):
    from pymongo import MongoClient
    from mist.api.config import MONGO_URI, MONGO_DB
    db = MongoClient(MONGO_URI)[MONGO_DB]
    migrated = {
        'schedules': 0,
        'rules': 0
    }

    for schedule in db.schedules.find({}):
        if schedule.get('conditions'):
            selectors = schedule.pop('conditions')
            for selector in selectors:
                selector['_cls'] = selector['_cls'].replace('Condition', 'Selector')
            schedule['selectors'] = selectors
            if not dry:
                print("Migrating schedule")
                result = db.schedules.replace_one({'_id': schedule['_id']}, schedule)
                assert result.modified_count == 1
            migrated['schedules'] += 1

    for rule in db.rules.find({}):
        if rule.get('conditions'):
            selectors = rule.pop('conditions')
            for selector in selectors:
                selector['_cls'] = selector['_cls'].replace('Condition', 'Selector')
            rule['selectors'] = selectors
            if not dry:
                print("Migrating rule")
                result = db.rules.replace_one({'_id': rule['_id']}, rule)
                assert result.modified_count == 1
            migrated['rules'] += 1

    print("Migrated %d schedules & %d rules" % (migrated['schedules'], migrated['rules']))
    if dry:
        print("Dry run, no changes written")


if __name__ == '__main__':
    migrate_selectors(dry=False)
