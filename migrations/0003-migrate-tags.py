import mongoengine as me

from mist.api.users.models import Owner
from mist.api.models import *  # noqa


def migrate_tags():
    class Tag(me.Document):
        owner = me.ReferenceField(Owner, required=True)
        key = me.StringField(required=True)
        resource_type = me.StringField()
        value = me.StringField()
        resource = me.GenericReferenceField()
        resource_id = me.StringField()

        meta = {
            'indexes': [
                'owner',
                {
                    'fields': ['resource', 'key'],
                    'sparse': False,
                    'unique': False,
                    'cls': False,
                },
            ],
        }

    from pymongo import MongoClient
    from mist.api.config import MONGO_URI, MONGO_DB
    db = MongoClient(MONGO_URI)[MONGO_DB]
    db.tag.drop_indexes()
    print('Dropped tag indexes')
    total = Tag.objects.count()
    print('Migrating %d tags' % total)
    migrated = deleted = skipped = 0
    for tag in Tag.objects:
        try:
            if tag.resource:
                tag.resource_id = tag.resource.id
                tag.resource_type = tag.resource.to_dbref().collection.strip(
                    's')
                tag.resource = None
                tag.save()
                migrated += 1
                if not migrated % 10:
                    print('Migrated %d/%d tags' % (migrated, total))
            elif tag.resource_id:
                skipped += 1
                continue
            else:
                print('Deleting tag %s:%s pointing to no %s' % (
                    tag.key, tag.value, tag.resource_type))
                tag.delete()
                deleted += 1
        except me.DoesNotExist:
            print('Deleting tag %s:%s pointing to missing %s' % (
                tag.key, tag.value, tag.resource_type))
            tag.delete()
            deleted += 1

    print('Migrated %d, deleted %s, skipped %d, out of %d tags' % (
        migrated, deleted, skipped, total))


if __name__ == '__main__':
    migrate_tags()
