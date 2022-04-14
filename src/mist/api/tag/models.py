import re


import mongoengine as me
from mist.api.config import TAGS_RESOURCE_TYPES
from mist.api.users.models import Owner
from mist.api.tag.tasks import update_tags, delete_tags


class Tag(me.Document):

    owner = me.ReferenceField(Owner, required=True,
                              reverse_delete_rule=me.CASCADE)
    key = me.StringField(required=True)

    resource_type = me.StringField(choices=TAGS_RESOURCE_TYPES)

    value = me.StringField()
    resource_id = me.StringField()

    meta = {
        'indexes': ['owner', 'resource_type', 'resource_id', 'key']
    }

    @property
    def resource(self):
        try:
            resource_type = self.resource_type.rstrip('s')
            from mist.api.helpers import get_resource_model
            return get_resource_model(resource_type).objects.get(id=self.resource_id)   # noqa: E501
        except AttributeError:
            return None

    def validate(self, clean=False):
        if not re.search(r'^[a-zA-Z0-9_]+(?:[ :.-][a-zA-Z0-9_]+)*$',
                         self.key):
            raise me.ValidationError('Invalid key name')

    def __str__(self):
        return 'Tag %s:%s for %s' % (self.key, self.value, self.resource)

    def as_dict(self):
        return {
            'key': self.key,
            'value': self.value,
            'owner': self.owner.id,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
        }

    def save(self):
        super(Tag, self).save()
        update_tags.send(self.resource_type,
                         self.resource_id,
                         {self.key: self.value})

    def delete(self):
        super(Tag, self).delete()
        delete_tags.send(self.resource_type,
                         self.resource_id,
                         [self.key])
