import uuid

import mongoengine as me

from mist.api.mongoengine_extras import MistDictField


class CloudImage(me.Document):
    """A base Cloud Image Model."""
    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    cloud = me.ReferenceField('Cloud', required=True,
                              reverse_delete_rule=me.CASCADE)
    external_id = me.StringField(required=True)
    name = me.StringField()
    starred = me.BooleanField(default=True)
    stored_after_search = me.BooleanField(default=False)
    missing_since = me.DateTimeField()
    extra = MistDictField()
    os_type = me.StringField(default='linux')
    meta = {
        'collection': 'images',
        'indexes': [
            {
                'fields': ['cloud', 'external_id'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ]
    }

    def __str__(self):
        name = "%s, %s (%s)" % (self.name, self.cloud.id, self.external_id)
        return name

    def as_dict(self):
        return {
            'id': self.id,
            'cloud': self.cloud.id,
            'external_id': self.external_id,
            'name': self.name,
            'starred': self.starred,
            'extra': self.extra,
            'os_type': self.os_type,
            'missing_since': str(self.missing_since.replace(tzinfo=None)
                                 if self.missing_since else '')
        }
