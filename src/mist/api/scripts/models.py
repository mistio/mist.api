"""Script entity model."""
import re
import datetime
from uuid import uuid4
import mongoengine as me
import mist.api.tag.models
from urllib.parse import urlparse
from mist.api.users.models import Owner
from mist.api.exceptions import BadRequestError
from mist.api.scripts.base import BaseScriptController
from mist.api.exceptions import RequiredParameterMissingError
from mist.api.ownership.mixins import OwnershipMixin
from mist.api.tag.models import Tag
from mist.api.tag.mixins import TagMixin

import mist.api.scripts.controllers as controllers


class Location(me.EmbeddedDocument):
    """Abstract Base class used as a common interface for location types.
        There are three different types: InLineLocation, GithubLocation
        and UrlLocation
    """
    meta = {'allow_inheritance': True}

    def as_dict(self):
        NotImplementedError()


class InlineLocation(Location):
    type = 'inline'
    source_code = me.StringField(required=True)

    def as_dict(self):
        return {'source_code': self.source_code,
                'type': self.type
                }

    def __unicode__(self):
        return 'Script is {0.source_code}'.format(self)


class GithubLocation(Location):
    type = 'github'
    repo = me.StringField(required=True)
    entrypoint = me.StringField()

    def clean(self):
        script_url = urlparse(self.repo)
        if len(script_url.path[1:].split('/')) != 2:
            raise BadRequestError(
                "'repo' must be in "
                "the form of either 'https://github.com/owner/repo' or "
                "simply 'owner/repo'."
            )

    def as_dict(self):
        return {'repo': self.repo,
                'entrypoint': self.entrypoint or '',
                'type': self.type}

    def __unicode__(self):
        if self.entrypoint:
            return 'Script is in repo {0.repo} ' \
                   'and entrypoint {0.entrypoint}'.format(self)
        else:
            return 'Script is in repo {0.repo}'.format(self)


class UrlLocation(Location):
    type = 'url'
    url = me.StringField(required=True)
    entrypoint = me.StringField()

    def clean(self):
        script_url = urlparse(self.url)
        if not (script_url.scheme and script_url.netloc):
            raise BadRequestError("This is not a valid url!")
        if not (self.url.startswith('http://') or
                self.url.startswith('https://')):
            raise BadRequestError("When 'location_type' is 'url', 'script' "
                                  "must be a valid url starting with "
                                  "'http://' or 'https://'.")

    def as_dict(self):
        return {'url': self.url,
                'entrypoint': self.entrypoint or '',
                'type': self.type}

    def __unicode__(self):
        if self.entrypoint:
            return 'Script is in url {0.repo} and ' \
                   'entrypoint {0.entrypoint}'.format(self)
        else:
            return 'Script is in repo {0.repo}'.format(self)


class Script(OwnershipMixin, me.Document, TagMixin):
    """Abstract base class for every script attr mongoengine model.

        This class defines the fields common to all scripts of all types.
        For each different script type, a subclass should be created adding
        any script specific fields and methods.

        Documents of all Script subclasses will be stored on the same mongo
        collection.

        One can perform a query directly on Script to fetch all script types,
        like this:
            Script.objects(owner=owner).count()

        This will return an iterable of scripts for that owner. Each key will
        be an instance of its respective Script subclass, like AnsibleScript
        and CollectdScript instances.

        Scripts of a specific type can be queried like this:
            AnsibleScript.objects(owner=owner).count()

        This will return an iterable of AnsibleScript instances.

        To create a new script, one should initialize a Script subclass like
        AnsibleScript. Initializing directly a Script instance won't have any
        fields or associated handler to work with.

        Each Script subclass should define a `_controller_cls` class attribute.
        Its value should be a subclass of
        `mist.api.scripts.controllers.BaseScriptController'. These
        subclasses are stored in `mist.api.scripts.BaseScriptController`.
        When a script is instantiated, it is given a `ctl` attribute which
        gives access to the scripts controller.
        This way it is possible to do things like:

            script = AnsibleScript.objects.get(id=script_id)
            script.ctl.get_file()
        """

    meta = {
        'allow_inheritance': True,
        'collection': 'scripts',
        'indexes': [
            {
                'fields': ['owner', 'name', 'deleted'],
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

    id = me.StringField(primary_key=True,
                        default=lambda: uuid4().hex)

    name = me.StringField(required=True)
    description = me.StringField()
    owner = me.ReferenceField(Owner, required=True,  # TODO Owner -> Org
                              reverse_delete_rule=me.CASCADE)
    location = me.EmbeddedDocumentField(Location, required=True)

    created = me.DateTimeField(default=datetime.datetime.now)

    deleted = me.DateTimeField()

    migrated = me.BooleanField()  # NOTE For collectd scripts' migration.

    _controller_cls = None

    def __init__(self, *args, **kwargs):
        super(Script, self).__init__(*args, **kwargs)
        # Set attribute `ctl` to an instance of the appropriate controller.
        if self._controller_cls is None:
            raise NotImplementedError(
                "Can't initialize %s. Script is an abstract base class and "
                "shouldn't be used to create script instances. All Script "
                "subclasses should define a `_controller_cls` class attribute "
                "pointing to a `BaseController` subclass." % self
            )
        elif not issubclass(self._controller_cls, BaseScriptController):
            raise TypeError(
                "Can't initialize %s.  All Script subclasses should define a"
                " `_controller_cls` class attribute pointing to a "
                "`BaseController` subclass." % self
            )
        self.ctl = self._controller_cls(self)
        # Calculate and store script type specific fields.
        self._script_specific_fields = [field for field in type(self)._fields
                                        if field not in Script._fields]

    @classmethod
    def add(cls, owner, name, id='', **kwargs):
        """Add script
        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.
        You 're not meant to be calling this directly, but on a script subclass
        instead like this:
            script = Script.add(owner=org, name='unicorn', **kwargs)
        """
        if not name:
            raise RequiredParameterMissingError('name')
        if not owner or not isinstance(owner, Owner):
            raise BadRequestError('owner')
        script = cls(owner=owner, name=name)
        if id:
            script.id = id
        script.ctl.add(**kwargs)
        return script

    @property
    def script(self):
        if self.location.type == 'inline':
            return self.location.source_code
        elif self.location.type == 'github':
            return self.location.repo
        elif self.location.type == 'url':
            return self.location.url

    def delete(self):
        super(Script, self).delete()
        mist.api.tag.models.Tag.objects(
            resource_id=self.id, resource_type='script').delete()
        self.owner.mapper.remove(self)
        if self.owned_by:
            self.owned_by.get_ownership_mapper(self.owner).remove(self)

    def as_dict(self):
        """Data representation for api calls."""
        return {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
            'exec_type': self.exec_type,
            'location': self.location.as_dict(),
            'owned_by': self.owned_by.id if self.owned_by else '',
            'created_by': self.created_by.id if self.created_by else '',
        }

    def as_dict_v2(self, deref='auto', only=''):
        """Returns the API representation of the `Script` object."""
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = ['id', 'name', 'description', 'exec_type']
        deref_map = {
            'owned_by': 'email',
            'created_by': 'email'
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)

        if 'location' in only or not only:
            ret['location'] = self.location.as_dict()

        if 'tags' in only or not only:
            ret['tags'] = {
                tag.key: tag.value
                for tag in Tag.objects(
                    owner=self.owner,
                    resource_id=self.id,
                    resource_type='script').only('key', 'value')
            }

        return ret

    def __str__(self):
        return 'Script %s (%s) of %s' % (self.name, self.id, self.owner)


class AnsibleScript(Script):

    exec_type = 'ansible'

    _controller_cls = controllers.AnsibleScriptController


class ExecutableScript(Script):

    exec_type = 'executable'

    _controller_cls = controllers.ExecutableScriptController


class TelegrafScript(Script):

    exec_type = 'executable'

    # ex. a dict with value_type='gauge', value_unit=''
    extra = me.DictField()

    _controller_cls = controllers.TelegrafScriptController

    def clean(self):
        # Make sure the script name does not contain any weird characters.
        if not re.match('^[\w]+$', self.name):
            raise me.ValidationError('Alphanumeric characters and underscores '
                                     'are only allowed in custom script names')

        # Custom scripts should be provided inline (for now).
        if not isinstance(self.location, InlineLocation):
            raise me.ValidationError('Only inline scripts supported for now')

        # Make sure shebang is present.
        if not self.location.source_code.startswith('#!'):
            raise me.ValidationError('Missing shebang')

        # Check metric type.
        if self.extra.get('value_type', 'gauge') not in ('gauge', 'derive'):
            raise me.ValidationError('value_type must be "gauge" or "derive"')
