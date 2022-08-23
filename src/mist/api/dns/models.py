"""Definition of DNS Zone and Record mongoengine models"""

import uuid
import ipaddress as ip

import mongoengine as me

from mist.api.tag.models import Tag
from mist.api.clouds.models import Cloud
from mist.api.users.models import Organization
from mist.api.dns.controllers import ZoneController, RecordController
from mist.api.clouds.controllers.dns.base import BaseDNSController
from mist.api.ownership.mixins import OwnershipMixin
from mist.api.mongoengine_extras import MistDictField
from mist.api.tag.mixins import TagMixin
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import RequiredParameterMissingError

# This is a map from type to record class, eg:
# 'A': ARecord
# It is autofilled by _populate_records which is run on the end of this file.
RECORDS = {}


def _populate_records():
    """Populates RECORDS variable with mappings from types to records"""
    for key, value in list(globals().items()):
        if key.endswith('Record') and key != 'Record':
            value = globals()[key]
            if issubclass(value, Record) and value is not Record:
                RECORDS[value._record_type] = value


class Zone(OwnershipMixin, me.Document, TagMixin):
    """This is the class definition for the Mongo Engine Document related to a
    DNS zone.
    """

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    owner = me.ReferenceField('Organization', required=True,
                              reverse_delete_rule=me.CASCADE)

    external_id = me.StringField(required=True)
    domain = me.StringField(required=True)
    type = me.StringField(required=True)  # TODO: Rename
    ttl = me.IntField(required=True, default=0)
    extra = MistDictField()
    cloud = me.ReferenceField(Cloud, required=True,
                              reverse_delete_rule=me.CASCADE)
    last_seen = me.DateTimeField()
    created = me.DateTimeField()
    missing_since = me.DateTimeField()
    first_seen = me.DateTimeField()

    meta = {
        'collection': 'zones',
        'indexes': [
            'owner', 'last_seen', 'missing_since',
            {
                'fields': ['cloud', 'external_id', 'last_seen',
                           'missing_since'],
                'sparse': False,
                'unique': True,
                'cls': False,
            }, {
                'fields': ['$tags'],
                'default_language': 'english',
                'sparse': True,
                'unique': False
            }
        ],
    }

    def __init__(self, *args, **kwargs):
        super(Zone, self).__init__(*args, **kwargs)
        self.ctl = ZoneController(self)

    @classmethod
    def add(cls, owner, cloud, id='', **kwargs):
        """Add Zone

        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.

        You're not meant to be calling this directly, but on a cloud subclass
        instead like this:

            zone = Zone.add(owner=org, domain='domain.com.')

        Params:
        - owner and domain are common and required params
        - only provide a custom zone id if you're migrating something
        - kwargs will be passed to appropriate controller, in most cases these
          should match the extra fields of the particular zone type.

        """
        if not kwargs['domain']:
            raise RequiredParameterMissingError('domain')
        if not cloud or not isinstance(cloud, Cloud):
            raise BadRequestError('cloud')
        if not owner or not isinstance(owner, Organization):
            raise BadRequestError('owner')
        zone = cls(owner=owner, cloud=cloud, domain=kwargs['domain'])
        if id:
            zone.id = id
        return zone.ctl.create_zone(**kwargs)

    def delete(self):
        super(Zone, self).delete()
        Tag.objects(resource_id=self.id, resource_type='zone').delete()
        self.owner.mapper.remove(self)
        if self.owned_by:
            self.owned_by.get_ownership_mapper(self.owner).remove(self)

    def as_dict_v2(self, deref='auto', only=''):
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = [
            'id', 'domain', 'type', 'ttl', 'extra', 'last_seen', ]
        deref_map = {
            'cloud': 'name',
            'owned_by': 'email',
            'created_by': 'email'
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)

        if 'name' in only or not only:
            ret['name'] = self.domain

        if 'external_id' in only or not only:
            ret['external_id'] = None
            if self.external_id:
                ret['external_id'] = self.external_id

        if 'records' in only or not only:
            ret['records'] = {r.id: r.as_dict() for r
                              in Record.objects(zone=self, missing_since=None)}
        if 'tags' in only or not only:
            ret['tags'] = {
                tag.key: tag.value for tag in Tag.objects(
                    resource_id=self.id, resource_type='zone').only(
                        'key', 'value')}
        if 'last_seen' in ret:
            ret['last_seen'] = str(ret['last_seen'])

        return ret

    def as_dict(self):
        """Return a dict with the model values."""
        return {
            'id': self.id,
            'external_id': self.external_id,
            'domain': self.domain,
            'type': self.type,
            'ttl': self.ttl,
            'extra': self.extra,
            'cloud': self.cloud.id,
            'created': str(self.created),
            'last_seen': str(self.last_seen),
            'missing_since': str(self.missing_since),
            'owned_by': self.owned_by.id if self.owned_by else '',
            'created_by': self.created_by.id if self.created_by else '',
            'records': {r.id: r.as_dict() for r
                        in Record.objects(zone=self, missing_since=None)},
            'tags': {
                tag.key: tag.value
                for tag in Tag.objects(
                    resource_id=self.id,
                    resource_type='zone').only('key', 'value')
            }
        }

    def clean(self):
        """Overriding the default clean method to implement param checking"""
        if not self.domain.endswith('.'):
            self.domain += "."

    def __str__(self):
        return 'Zone %s (%s/%s) of %s' % (self.id, self.external_id,
                                          self.domain, self.owner)


class Record(OwnershipMixin, me.Document, TagMixin):
    """This is the class definition for the Mongo Engine Document related to a
    DNS record.
    """

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)

    external_id = me.StringField(required=True)
    name = me.StringField(required=True)
    type = me.StringField(required=True)
    rdata = me.ListField(required=True)
    extra = MistDictField()
    ttl = me.IntField(default=0)
    # This ensures that any records that are under a zone are also deleted when
    # we delete the zone.
    zone = me.ReferenceField(Zone, required=True,
                             reverse_delete_rule=me.CASCADE)
    owner = me.ReferenceField('Organization', required=True,
                              reverse_delete_rule=me.CASCADE)
    created = me.DateTimeField()
    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    first_seen = me.DateTimeField()

    meta = {
        'collection': 'records',
        'allow_inheritance': True,
        'indexes': [
            'owner', 'zone', 'external_id', 'last_seen', 'missing_since',
            {
                'fields': ['$tags'],
                'default_language': 'english',
                'sparse': True,
                'unique': False
            },
        ],
    }
    _record_type = None

    def __init__(self, *args, **kwargs):
        super(Record, self).__init__(*args, **kwargs)
        self.ctl = RecordController(self)

    @classmethod
    def add(cls, owner=None, zone=None, id='', **kwargs):
        """Add Record

        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.

        You're not meant to be calling this directly, but on a cloud subclass
        instead like this:

            record = Record.add(zone=zone, **kwargs)

        Params:
        - zone is a required param
        - only provide a custom record id if you're migrating something
        - kwargs will be passed to appropriate controller, in most cases these
          should match the extra fields of the particular record type.

        """
        if not kwargs['name']:
            raise RequiredParameterMissingError('name')
        if not kwargs['data']:
            raise RequiredParameterMissingError('data')
        if not kwargs['type']:
            raise RequiredParameterMissingError('type')
        # If we were not given a zone then we need the owner to try and find
        # the best matching domain.
        if not zone and kwargs['type'] in ['A', 'AAAA', 'CNAME']:
            assert isinstance(owner, Organization)
            zone = BaseDNSController.find_best_matching_zone(owner,
                                                             kwargs['name'])
        assert isinstance(zone, Zone)

        record = cls(zone=zone)
        if id:
            record.id = id
        return record.ctl.create_record(**kwargs)

    def delete(self):
        super(Record, self).delete()
        Tag.objects(resource_id=self.id, resource_type='record').delete()
        self.zone.owner.mapper.remove(self)
        if self.owned_by:
            self.owned_by.get_ownership_mapper(self.owner).remove(self)

    def clean(self):
        """Overriding the default clean method to implement param checking"""
        self.type = self._record_type
        if not self.owner:
            self.owner = self.zone.owner

    def __str__(self):
        return 'Record %s (name:%s, type:%s) of %s' % (
            self.id, self.name, self.type, self.zone.domain)

    def as_dict(self):
        """ Return a dict with the model values."""
        return {
            'id': self.id,
            'external_id': self.external_id,
            'name': self.name,
            'type': self.type,
            'rdata': self.rdata,
            'ttl': self.ttl,
            'extra': self.extra,
            'zone': self.zone.id,
            'created': str(self.created),
            'last_seen': str(self.last_seen),
            'missing_since': str(self.missing_since),
            'owned_by': self.owned_by.id if self.owned_by else '',
            'created_by': self.created_by.id if self.created_by else '',
            'tags': {
                tag.key: tag.value
                for tag in Tag.objects(
                    resource_id=self.id,
                    resource_type='record').only('key', 'value')
            }
        }

    def as_dict_v2(self, deref='auto', only=''):
        """ Return a dict with the model values."""
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = [
            'id',
            'external_id',
            'name',
            'type',
            'rdata',
            'ttl',
            'extra',
            'zone',
            'created',
            'last_seen',
            'missing_since',
            'owned_by',
            'created_by',
        ]
        deref_map = {
            'zone': 'name',
            'owned_by': 'email',
            'created_by': 'email',
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)
        if 'last_seen' in ret:
            ret['last_seen'] = str(ret['last_seen'])
        if 'missing_since' in ret:
            ret['missing_since'] = str(ret['missing_since'])
        if 'created' in ret:
            ret['created'] = str(ret['created'])
        if 'tags' in only or not only:
            ret['tags'] = {
                tag.key: tag.value
                for tag in Tag.objects(
                    resource_id=self.id,
                    resource_type='record').only('key', 'value')
            }
        return ret


class ARecord(Record):

    _record_type = "A"

    def clean(self):
        """Overriding the default clean method to implement param checking"""
        super(ARecord, self).clean()
        for ip_addr in self.rdata:
            try:
                ip.ip_address(ip_addr)
            except ValueError:
                raise me.ValidationError(
                    'IPv4 address provided is not valid %s' % ip_addr)

        if len(self.rdata) < 1:
            raise me.ValidationError(
                'At least onne IP address is required for ARecord')


class AAAARecord(Record):

    _record_type = "AAAA"

    def clean(self):
        """Overriding the default clean method to implement param checking"""
        super(AAAARecord, self).clean()
        try:
            ip_addr = self.rdata[0]
            ip.ip_address(ip_addr)
        except ValueError:
            raise me.ValidationError('IPv6 address provided is not valid')
        if not len(self.rdata) == 1:
            raise me.ValidationError('We cannot have more than one rdata'
                                     'values for this type of record.')


class CNAMERecord(Record):

    _record_type = "CNAME"

    def clean(self):
        """Overriding the default clean method to implement param checking"""
        super(CNAMERecord, self).clean()
        if not self.rdata[0].endswith('.'):
            self.rdata[0] += '.'
        if not len(self.rdata) == 1:
            raise me.ValidationError('We cannot have more than one rdata'
                                     'values for this type of record.')


class MXRecord(Record):

    _record_type = "MX"


class NSRecord(Record):

    _record_type = "NS"


class SOARecord(Record):

    _record_type = "SOA"


class TXTRecord(Record):

    _record_type = "TXT"

    def clean(self):
        """Overriding the default clean method to implement param checking"""
        super(TXTRecord, self).clean()
        if not self.rdata[0].endswith('"'):
            self.rdata[0] += '"'
        if not self.rdata[0].startswith('"'):
            self.rdata[0] = '"' + self.rdata[0]


_populate_records()
