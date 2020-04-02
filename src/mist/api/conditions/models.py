import re
import datetime

import mongoengine as me

from mist.api.helpers import get_resource_model
from mist.api.helpers import rtype_to_classpath

from mist.api.tag.models import Tag


class BaseCondition(me.EmbeddedDocument):
    """Abstract base class used as a common interface for condition types.

    There are five different types for now:

        FieldCondition, TaggingCondition, GenericResourceCondition,
        MachinesCondition (deprecated), and MachinesAgeCondition

    """

    meta = {
        'allow_inheritance': True,
    }

    ctype = 'base'

    def update(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def q(self):
        return me.Q()

    def as_dict(self):
        return {'type': self.ctype}


class ConditionalClassMixin(object):
    """Generic condition mixin class used as a handler for different
    query sets for a specific collection. It constructs a query from
    a list of query sets which chains together with logical & operator."""

    conditions = me.EmbeddedDocumentListField(BaseCondition)

    resource_model_name = me.StringField(
        required=True, default='machine',
        choices=list(rtype_to_classpath.keys()))

    @property
    def condition_resource_cls(self):
        return get_resource_model(self.resource_model_name)

    def owner_query(self):
        return me.Q(owner=self.owner_id)

    def get_resources(self):
        query = self.owner_query()
        for condition in self.conditions:
            query &= condition.q
        if 'deleted' in self.condition_resource_cls._fields:
            query &= me.Q(deleted=None)
        if 'missing_since' in self.condition_resource_cls._fields:
            query &= me.Q(missing_since=None)
        return self.condition_resource_cls.objects(query)

    def get_ids(self):
        return [resource.id for resource in self.get_resources()]


class FieldCondition(BaseCondition):
    """Generic condition for any field which is supported by specific
    collection."""

    ctype = 'field'

    field = me.StringField(required=True)
    value = me.DynamicField(required=True)
    operator = me.StringField(required=True, default='eq',
                              choices=('eq', 'ne', 'gt', 'lt'))

    @property
    def q(self):
        if self.operator == 'eq':
            return me.Q(**{self.field: self.value})
        return me.Q(**{'%s__%s' % (self.field, self.operator): self.value})

    def as_dict(self):
        return {'type': self.ctype, 'field': self.field,
                'value': self.value, 'operator': self.operator}


class TaggingCondition(BaseCondition):

    ctype = 'tags'

    tags = me.DictField(required=True, default=lambda: {})

    @property
    def q(self):
        rtype = self._instance.condition_resource_cls._meta[
            "collection"].rstrip('s')
        ids = set()
        for key, value in self.tags.items():
            query = {
                'owner': self._instance.owner,
                'resource_type': rtype,
                'key': key,
            }
            if value:
                query['value'] = value
            ids |= set(tag.resource_id for tag in Tag.objects(**query))
        return me.Q(id__in=ids)

    def validate(self, clean=True):
        if self.tags:
            regex = re.compile(r'^[a-z0-9_-]+$')
            for key, value in self.tags.items():
                if not key:
                    raise me.ValidationError('You cannot add a tag '
                                             'without a key')
                elif not regex.match(key) or (value and
                                              not regex.match(value)):
                    raise me.ValidationError('Tags must be in key=value '
                                             'format and only contain the '
                                             'characters a-z, 0-9, _, -')
        super(TaggingCondition, self).validate(clean=True)

    def clean(self):
        if not self.tags:
            self.tags = {}
        elif not isinstance(self.tags, dict):
            raise me.ValidationError('Tags must be a dictionary')

    def __str__(self):
        return 'Tags: %s' % self.tags

    def as_dict(self):
        return {'type': self.ctype, 'tags': self.tags}


class GenericResourceCondition(BaseCondition):
    """Condition used to query any resource which is a me.Document subclass.

    The condition's type `ctype` is not hard-coded but rather computed based
    on the `resource_model_name` field of the `ConditionalClassMixin`.

    """

    ids = me.ListField(me.StringField(required=True), required=True)

    @property
    def q(self):
        return me.Q(id__in=self.ids)

    @property
    def ctype(self):
        return self._instance and \
            self._instance.resource_model_name.rstrip('s') + 's'

    def as_dict(self):
        return {'type': self.ctype, 'ids': self.ids}


class MachinesCondition(GenericResourceCondition):
    """Predecessor of the newest GenericResourceCondition.

    This condition was used to declare a list of machines ids.

    This condition is now **DEPRECATED** in favor of GenericResourceCondition.
    It is still kept for backwards compatibility, since the Schedule and Rule
    models have been using it up until now and mongoDB stores a reference to
    this class in the form of: `{"_cls": "MachinesCondition"}`. New/updated
    documents will use the new `GenericResourceCondition`. When this class is
    no longer required by mongoDB/mongoengine, it can just be deleted (no db
    schema migration is required).

    """

    ctype = 'machines'


class MachinesAgeCondition(BaseCondition):
    """Condition which computes machine's age and queries
    for machines which are older than this age. """

    ctype = 'age'

    minutes = me.IntField(required=True)

    @property
    def q(self):
        d = datetime.datetime.now() - datetime.timedelta(minutes=self.minutes)
        return me.Q(created__lt=d)

    def as_dict(self):
        return {'type': self.ctype, 'minutes': self.minutes}
