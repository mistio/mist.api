"""Object Storage entity model."""

import uuid
import logging
import mongoengine as me

from mist.api.ownership.mixins import OwnershipMixin
from mist.api.mongoengine_extras import MistDictField


log = logging.getLogger(__name__)


class ObjectStorageItem(me.EmbeddedDocument):
    name = me.StringField(required=True)
    size = me.IntField()
    hash = me.StringField(required=True)
    type = me.StringField()
    container = MistDictField()
    extra = MistDictField()
    meta_data = MistDictField()

    def clean(self):
        self.type = 'folder' if self.name.endswith('/') else 'file'


class ObjectStorage(OwnershipMixin, me.Document):
    """The basic object storage model"""

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)

    cloud = me.ReferenceField('Cloud', required=True,
                              reverse_delete_rule=me.CASCADE)
    owner = me.ReferenceField('Organization', required=True,
                              reverse_delete_rule=me.CASCADE)
    location = me.ReferenceField('CloudLocation', required=False,
                                 reverse_delete_rule=me.DENY)
    name = me.StringField(required=True)

    content = me.EmbeddedDocumentListField(ObjectStorageItem)

    extra = MistDictField()
    missing_since = me.DateTimeField()

    def __init__(self, *args, **kwargs):
        super(ObjectStorage, self).__init__(*args, **kwargs)

    def clean(self):
        self.owner = self.owner or self.cloud.owner

    def as_dict(self):
        return {
            'id': self.id,
            'cloud': self.cloud.id,
            'cloud_title': self.cloud.title,
            'name': self.name,
            'provider': self.cloud.provider,
            'region': self.cloud.region,
            'extra': self.extra
        }

    def get_content(self, path):
        return {
            **self.as_dict(),
            'content': {c.name: c.to_mongo() for c in self.content}
        }
