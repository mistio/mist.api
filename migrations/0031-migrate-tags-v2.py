import mongoengine as me
from mist.api.models import *  # noqa
from mist.api.tag.models import Tag
from pymongo import MongoClient
from mist.api.config import MONGO_URI, MONGO_DB


def migrate_tags_v2():
    total = Tag.objects.count()
    migrated = skipped = deleted = 0

    for tag in Tag.objects:
        try:
            if f',{tag.key}:{tag.value},' not in tag.resource.tags:
                tag.resource.update_tags({tag.key: tag.value})
                migrated += 1
            else:
                skipped += 1

        except me.DoesNotExist:
            print('Deleting tag %s:%s pointing to missing %s' % (
                tag.key, tag.value, tag.resource_type))
            tag.delete()
            deleted += 1

    print('Migrated %d, deleted %s, skipped %d, out of %d tags' % (
        migrated, deleted, skipped, total))


if __name__ == '__main__':
    migrate_tags_v2()
