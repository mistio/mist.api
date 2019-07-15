import mongoengine as me

from mist.api.users.models import Owner


def migrate_tags():
    class Tag(me.Document):
        owner = me.ReferenceField(Owner, required=True)
        key = me.StringField(required=True)
        resource_type = me.StringField()
        value = me.StringField()
        resource = me.GenericReferenceField()
        resource_id = me.StringField()

    for tag in Tag.objects:
        if tag.resource:
            tag.resource_id = tag.resource.id
            tag.resource_type = tag.__class__.__name__.lower()
            tag.resource = None
            tag.save()


if __name__ == '__main__':
    migrate_tags()
