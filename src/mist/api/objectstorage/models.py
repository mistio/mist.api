""" Bucket entity model."""

import uuid
import logging
import mongoengine as me

from mist.api.ownership.mixins import OwnershipMixin
from mist.api.mongoengine_extras import MistDictField


log = logging.getLogger(__name__)


class BucketItem(me.EmbeddedDocument):
    name = me.StringField(required=True)
    size = me.IntField()
    hash = me.StringField(required=True)
    container = MistDictField()
    extra = MistDictField()
    meta_data = MistDictField()


class Bucket(OwnershipMixin, me.Document):
    """The basic bucket model"""

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)

    cloud = me.ReferenceField('Cloud', required=True,
                              reverse_delete_rule=me.CASCADE)
    owner = me.ReferenceField('Organization', required=True,
                              reverse_delete_rule=me.CASCADE)
    location = me.ReferenceField('CloudLocation', required=False,
                                 reverse_delete_rule=me.DENY)
    name = me.StringField(required=True)

    content = me.EmbeddedDocumentListField(BucketItem)

    extra = MistDictField()
    created = me.DateTimeField()
    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    first_seen = me.DateTimeField()

    def __init__(self, *args, **kwargs):
        super(Bucket, self).__init__(*args, **kwargs)

    def clean(self):
        self.owner = self.owner or self.cloud.owner

    def as_dict(self):
        return {
            'id': self.id,
            'cloud': self.cloud.id,
            'cloud_title': self.cloud.name,
            'name': self.name,
            'provider': self.cloud.provider,
            'region': self.cloud.region,
            'extra': self.extra,
            'created': str(self.created),
            'last_seen': str(self.last_seen),
        }

    def get_content(self):
        return {
            **self.as_dict(),
            'content': {c.name: c.to_mongo() for c in self.content}
        }
