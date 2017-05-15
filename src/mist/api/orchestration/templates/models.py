import uuid
import logging
import datetime
import mongoengine as me

import mist.api.tag.models
import mist.api.orchestration.templates.controllers as ctls

from mist.api.users.models import Organization

from mist.api.scripts.models import Location
from mist.api.scripts.models import UrlLocation as _UrlLocation
from mist.api.scripts.models import GithubLocation as _GithubLocation
from mist.api.scripts.models import InlineLocation as _InlineLocation


log = logging.getLogger(__name__)


class InlineLocation(_InlineLocation):

    def __unicode__(self):
        return 'Template: {0.source_code}'.format(self)


class GithubLocation(_GithubLocation):

    def __unicode__(self):
        msg = 'Template from repository {0.repo}'
        if self.entrypoint:
            msg += ' with entrypoint: {0.entrypoint}'
        return msg.format(self)


class UrlLocation(_UrlLocation):

    def __unicode__(self):
        msg = 'Template from URL {0.url}'
        if self.entrypoint:
            msg += ' with entrypoint: {0.entrypoint}'
        return msg.format(self)


class Input(me.EmbeddedDocument):
    """An input of a Template."""

    name = me.StringField(required=True)
    type = me.StringField()
    default = me.StringField()
    description = me.StringField()

    def clean(self):
        self.type = self.type or type(self.default).__name__

    def as_dict(self):
        return {
            'name': self.name,
            'type': self.type,
            'default': self.default,
            'description': self.description,
        }


class Output(me.EmbeddedDocument):
    """An output of a Template."""

    name = me.StringField(required=True)
    description = me.StringField()

    def as_dict(self):
        return {
            'name': self.name,
            'description': self.description,
        }


class Workflow(me.EmbeddedDocument):
    """A workflow of a Template."""

    name = me.StringField(required=True)
    inputs = me.EmbeddedDocumentListField(Input)

    def as_dict(self):
        return {
            'name': self.name,
            'inputs': [i.as_dict() for i in self.inputs if
                       i.name not in self._instance._private_inputs]
        }


class Relationship(me.EmbeddedDocument):
    """A relationship between instances defined in a Template."""

    name = me.StringField(required=True)
    source = me.StringField(required=True)
    target = me.StringField(required=True)

    def as_dict(self):
        return {
            'name': self.name,
            'source': self.source,
            'target': self.target,
        }


#class Sections(me.EmbeededDocument):
#    """"""
#
#    inputs = me.EmbeddedDocumentListField(Input)
#    outputs = me.EmbeddedDocumentListField(Output)
#    workflows = me.EmbeddedDocumentListField(Workflow)
#    relationships = me.EmbeddedDocumentListField(Relationship)
#
#    def as_dict(self):
#        return {
#            'inputs': [i.as_dict() for i in self.inputs if
#                       i.name not in self._instance._private_inputs]
#            'outputs': [o.as_dict() for o in self.outputs]
#            'workflows': [w.as_dict() for w in self.outputs]
#            'relationships': [r.as_dict() for r in self.relationships]
#        }


class Template(me.Document):
    """The base Template entity model.

    This class defines the basic Template entity. All Template types should
    subclass and extend the base Template in order to account for type-specific
    parsing and processings needs.

    All Template documents, regardless of type, will be stored in the same
    mongodb collection. A Template's type may also be defined by specifying
    the `exec_type` class attribute.

    In order to create a new Template instance, one is meant to call the `add`
    classmethod on a subclass of `Template`. Each `Template` subclass should
    also define its own `_controller_cls` class attribute, which must be a
    subclass of `mist.api.orchestration.templates.base.BaseTemplateController`
    and is accessible by the `ctl` instance attribute.

    """

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)

    owner = me.ReferenceField(Organization, required=True)
    name = me.StringField(required=True)
    description = me.StringField()
    version = me.StringField()

    # The sections of a parsed Template.
    inputs = me.EmbeddedDocumentListField(Input)
    outputs = me.EmbeddedDocumentListField(Output)
    workflows = me.EmbeddedDocumentListField(
        Workflow, required=True
        default=lambda: [Workflow(name='install'), Workflow(name='uninstall')])
    relationships = me.EmbeddedDocumentListField(Relationship)

    location = me.EmbeddedDocumentField(Location, required=True)

    created_at = me.DateTimeField(default=datetime.datetime.utcnow)
    deleted = me.DateTimeField()

    meta = {
        'allow_inheritance': True,
        'collection': 'templates',
        'indexes': [
            {
                'fields': ['owner', 'name', 'deleted'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ],
    }

    _controller_cls = None
    _private_inputs = None

    def __init__(self, *args, **kwargs):
        super(Template, self).__init__(*args, **kwargs)
        if self._controller_cls is None:
            raise TypeError("Cannot initialize %s, since it's an abstract base"
                            " class and SHOULD NOT be used to create Template "
                            "instances. Instead, all subclasses of `Template` "
                            "should define their owner `_controller_cls` class"
                            " attribute, which should point to a subclass of "
                            "the `BaseTemplateController`", self)

        if not issubclass(self._controller_cls, BaseTemplateController):
            raise TypeError("All subclasses of %s MUST define their own "
                            "`_controller_cls` class attribute, which must "
                            "be a subclass of `BaseTemplateController`", self)

        # Initialize controller cls.
        self.ctl = self._controller_cls(self)

    @classmethod
    def add(cls, owner, name, description='', id='', **kwargs):
        """Add a new Template.

        This is classmethod, meaning that it is meant to be called on the class
        itself and not on an instance of the class, as such:

            template = CloudifyBlueprint.add(owner=owner, name=name, **kwargs)

        This method and all Template actions are meant to be performed on a
        subclass of `Template` and not directly on the main class.

        Arguments:
            - owner: The Owner of this Template - an instance of Organization
            - name: The Template's name
            - id: A custom Template pk. Do not provide an id unless migrating
            - kwargs: Additional fields that will be passed to the controller

        """
        if not isinstance(owner, Organization):
            raise RequiredParameterMissingError('owner')
        if not name:
            raise RequiredParameterMissingError('name')
        template = cls(owner=owner, name=name)
        if id:
            template.id = id
        if description:
            template.description = description
        template.ctl.add(**kwargs)
        return template

    @property
    def template(self):
        """Return the actual Template or URL it resides."""
        if self.location.type == 'url':
            return self.location.url
        elif self.location.type == 'github':
            return self.location.repo
        elif self.location.type == 'inline':
            return self.location.source_code

    @property
    def tags(self):
        """Return the tags of this Template."""
        return {
            tag.key: tag.value for
            tag in mist.api.tag.models.Tag(owner=self.owner, resource=self)
        }

    def delete(self):
        super(Template, self).delete()
        self.owner.mapper.remove(self)
        mist.api.tag.models.Tag.objects(resource=self).delete()

    def as_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'location': self.location.as_dict(),
            'inputs': [i.as_dict() for i in self.inputs if
                       i.name not in self._private_inputs]
            'outputs': [o.as_dict() for o in self.outputs]
            'workflows': [w.as_dict() for w i n self.workflow]
            'relationships': [r.as_dict() for r in self.relationships]
            'exec_type': self.exec_type,
            'created_at': str(self.created_at),
            'tags': [{'key': key, 'value': value} for key, value in self.tags],
        }

    # TODO
    # def as_dict_old(self):
    #     return {}

    def __str__(self):
        return "%s %s of %s" % (self.__class__.__name__, self.name, self.owner)


class CloudifyBlueprint(Template):

    exec_type = 'cloudify'

    _controller_cls = ctls.CloudifyBlueprintController
    _private_inputs = [
        'mist_uri', 'mist_token', 'mist_username', 'mist_password',
    ]
