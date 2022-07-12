import re
import datetime

import mongoengine as me

from mist.api.helpers import get_resource_model
from mist.api.helpers import rtype_to_classpath

from mist.api.tag.models import Tag
from mist.api.clouds.models import Cloud


class BaseSelector(me.EmbeddedDocument):
    """Abstract base class used as a common interface for selector types.

    There are five different types for now:

        FieldSelector, TaggingSelector, ResourceSelector
        and AgeSelector

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


class SelectorClassMixin(object):
    """Generic selector mixin class used as a handler for different
    query sets for a specific collection. It constructs a query from
    a list of query sets which chains together with logical & operator."""

    selectors = me.EmbeddedDocumentListField(BaseSelector)

    resource_model_name = me.StringField(
        required=True, default='machine',
        choices=list(rtype_to_classpath.keys()))

    @property
    def selector_resource_cls(self):
        return get_resource_model(self.resource_model_name)

    def org_query(self):
        return me.Q(owner=self.org_id)

    def get_resources(self):
        query = self.org_query()
        for selector in self.selectors:
            query &= selector.q
        if 'deleted' in self.selector_resource_cls._fields:
            query &= me.Q(deleted=None)
        if 'missing_since' in self.selector_resource_cls._fields:
            query &= me.Q(missing_since=None)
        if 'cloud' in self.selector_resource_cls._fields:
            query &= me.Q(cloud__in=Cloud.objects(enabled=True))
        return self.selector_resource_cls.objects(query)

    def get_ids(self):
        return [resource.id for resource in self.get_resources()]


class FieldSelector(BaseSelector):
    """Generic selector for any field which is supported by specific
    collection."""

    ctype = 'field'

    field = me.StringField(required=True)
    value = me.DynamicField(required=True)
    operator = me.StringField(required=True, default='eq',
                              choices=('eq', 'ne', 'gt', 'lt', 'regex'))

    @property
    def q(self):
        if self.operator == 'eq':
            return me.Q(**{self.field: self.value})
        elif self.operator == 'regex':
            return me.Q(**{self.field: re.compile(self.value)})
        return me.Q(**{'%s__%s' % (self.field, self.operator): self.value})

    def as_dict(self):
        return {'type': self.ctype, 'field': self.field,
                'value': self.value, 'operator': self.operator}


class TaggingSelector(BaseSelector):

    ctype = 'tags'

    include = me.DictField(default=lambda: {})
    exclude = me.DictField(default=lambda: {})

    @property
    def q(self):
        rtype = self._instance.selector_resource_cls._meta[
            "collection"].rstrip('s')
        ids = set()
        for key, value in self.include.items():
            query = {
                'owner': self._instance.org,
                'resource_type': rtype,
                'key': key,
            }
            if value:
                query['value'] = value
            ids |= set(tag.resource_id for tag in Tag.objects(**query))
        # TODO: exclude items
        return me.Q(id__in=ids)

    def validate(self, clean=True):
        for field in ['include', 'exclude']:
            if getattr(self, field):
                regex = re.compile(r'^[a-z0-9_-]+$')
                for key, value in getattr(self, field).items():
                    if not key:
                        raise me.ValidationError('You cannot add a tag '
                                                 'without a key')
                    elif not regex.match(key) or (value and
                                                  not regex.match(value)):
                        raise me.ValidationError('Tags must be in key=value '
                                                 'format and only contain the '
                                                 'characters a-z, 0-9, _, -')
        super(TaggingSelector, self).validate(clean=True)

    def clean(self):
        for field in ['include', 'exclude']:
            if not getattr(self, field):
                setattr(self, field, {})
            elif not isinstance(getattr(self, field), dict):
                raise me.ValidationError('%s must be a dictionary' % field)

    def __str__(self):
        ret = ''
        if self.include:
            ret += 'Include tags: %s\t' % self.include
        if self.exclude:
            ret += 'Exclude tags: %s' % self.exclude
        return ret

    def as_dict(self):
        return {'type': self.ctype, 'include': self.include}


class ResourceSelector(BaseSelector):
    """Selector used to query any resource which is a me.Document subclass.

    The selector's type `ctype` is not hard-coded but rather computed based
    on the `resource_model_name` field of the `SelectorClassMixin`.

    """

    ids = me.ListField(me.StringField(required=True), required=True)

    @property
    def q(self):
        return me.Q(id__in=self.ids)

    @property
    def ctype(self):
        if self._instance is not None:
            return self._instance.resource_model_name.rstrip('s') + 's'
        try:
            return self.type.rstrip('s') + 's'
        except AttributeError:
            return None

    def as_dict(self):
        return {'type': self.ctype, 'ids': self.ids}


class AgeSelector(BaseSelector):
    """Selector which computes a resources's age and queries
    for resources which are older than this age. """

    ctype = 'age'

    minutes = me.IntField(required=True)

    @property
    def q(self):
        d = datetime.datetime.now() - datetime.timedelta(minutes=self.minutes)
        return me.Q(created__lt=d)

    def as_dict(self):
        return {'type': self.ctype, 'minutes': self.minutes}
