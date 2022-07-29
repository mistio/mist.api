import uuid

import mongoengine as me

from mist.api.mongoengine_extras import MistDictField

from mist.api.ownership.mixins import OwnershipMixin
from mist.api.tag.models import Tag
from mist.api.tag.mixins import TagMixin


class CloudImage(OwnershipMixin, me.Document, TagMixin):
    """A base Cloud Image Model."""
    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    cloud = me.ReferenceField('Cloud', required=True,
                              reverse_delete_rule=me.CASCADE)
    external_id = me.StringField(required=True)
    name = me.StringField()
    starred = me.BooleanField(default=False)
    stored_after_search = me.BooleanField(default=False)
    created = me.DateTimeField()
    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    first_seen = me.DateTimeField()
    extra = MistDictField()
    os_type = me.StringField(default='linux')
    os_distro = me.StringField(default='other', null=False)
    architecture = me.ListField(me.StringField(choices=('x86', 'arm')),
                                null=False, default=lambda: ['x86'])
    min_disk_size = me.FloatField()  # min disk size in GBs
    min_memory_size = me.IntField()  # min ram size in MBs
    # needed by KVM
    locations = me.ListField(me.StringField(), required=False)
    origin = me.StringField(default='system', null=False,
                            choices=('system',
                                     'marketplace',
                                     'custom',
                                     'snapshot'))

    meta = {
        'collection': 'images',
        'indexes': [
            'cloud',
            'external_id',
            'last_seen',
            'missing_since',
            'stored_after_search',
            {
                'fields': ['cloud', 'external_id'],
                'sparse': False,
                'unique': True,
                'cls': False,
            }, {
                'fields': ['$tags'],
                'default_language': 'english',
                'sparse': True,
                'unique': False
            }
        ]
    }

    def __str__(self):
        # this is for mongo medthod objects.only('id') to work..
        if self.cloud:
            name = "%s, %s (%s)" % (self.name, self.cloud.id, self.external_id)
        else:
            name = f"{self.name}, None, {self.external_id}"
        return name

    def as_dict(self, extra=True):
        ret = {
            'id': self.id,
            'cloud': self.cloud.id if self.cloud else None,  # same as above
            'external_id': self.external_id,
            'name': self.name,
            'starred': self.starred,
            'extra': self.extra if extra else {},
            'os_type': self.os_type,
            'os_distro': self.os_distro,
            'architecture': self.architecture,
            'min_disk_size': self.min_disk_size,
            'min_memory_size': self.min_memory_size,
            'tags': {
                tag.key: tag.value
                for tag in Tag.objects(
                    resource_id=self.id,
                    resource_type='image').only('key', 'value')
            },
            'origin': self.origin,
            'created': str(self.created),
            'last_seen': str(self.last_seen),
            'missing_since': str(self.missing_since.replace(tzinfo=None)
                                 if self.missing_since else '')
        }
        if self.locations:
            ret['locations'] = self.locations
        return ret

    def as_dict_v2(self, deref='auto', only=''):
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = [
            'id', 'name', 'external_id', 'starred', 'os_type', 'os_distro',
            'architecture', 'min_disk_size', 'min_memory_size', 'extra',
            'locations']
        deref_map = {
            'cloud': 'name',
            'owned_by': 'email',
            'created_by': 'email'
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)

        if 'tags' in only or not only:
            ret['tags'] = {
                tag.key: tag.value for tag in Tag.objects(
                    resource_id=self.id, resource_type='image').only(
                        'key', 'value')}
        if 'last_seen' in ret:
            ret['last_seen'] = str(ret['last_seen'])
        if 'created' in ret:
            ret['created'] = str(ret['created'])

        return ret
