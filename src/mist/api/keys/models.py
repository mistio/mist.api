"""Key entity model"""
import io
import logging
import datetime
from uuid import uuid4
import mongoengine as me
from paramiko.rsakey import RSAKey

import mist.api.tag.models
from mist.api.users.models import Owner
from mist.api.exceptions import BadRequestError
from mist.api.keys import controllers
from mist.api.keys.base import BaseKeyController
from mist.api.exceptions import RequiredParameterMissingError
from mist.api.ownership.mixins import OwnershipMixin
from mist.api.secrets.models import SecretValue
from mist.api.tag.mixins import TagMixin
from mist.api.tag.models import Tag

log = logging.getLogger(__name__)


class Key(OwnershipMixin, me.Document, TagMixin):
    """Abstract base class for every key/machine attr mongoengine model.

    This class defines the fields common to all keys of all types. For each
    different key type, a subclass should be created adding any key
    specific fields and methods.

    Documents of all Key subclasses will be stored on the same mongo
    collection.

    One can perform a query directly on Key to fetch all key types, like
    this:

        Key.objects(owner=owner).count()

    This will return an iterable of keys for that owner. Each key will be
    an instance of its respective Key subclass, like SSHKey and SignedSSHKey
    instances.

    Keys of a specific type can be queried like this:

        SSKey.objects(owner=owner).count()

    This will return an iterable of SSHKey instances.

    To create a new key, one should initialize a Key subclass like
    SSHKey. Initializing directly a Key instance won't have any fields
    or associated handler to work with.

    Each Key subclass should define a `_controller_cls` class attribute. Its
    value should be a subclass of
    `mist.api.keys.controllers.BaseKeyController'. These
    subclasses are stored in `mist.api.keys.BaseKeyController`. When a key is
    instantiated, it is given a `ctl` attribute which gives access to the
    keys controller. This way it is possible to do things like:

        key = SSKey.objects.get(id=key_id)
        key.ctl.generate()

    """
    meta = {
        'allow_inheritance': True,
        'collection': 'keys',
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
    owner = me.ReferenceField(Owner, reverse_delete_rule=me.CASCADE)
    default = me.BooleanField(default=False)
    created = me.DateTimeField(default=datetime.datetime.now)
    deleted = me.DateTimeField()

    _private_fields = ()
    _controller_cls = None

    def __init__(self, *args, **kwargs):
        super(Key, self).__init__(*args, **kwargs)

        # Set attribute `ctl` to an instance of the appropriate controller.
        if self._controller_cls is None:
            raise NotImplementedError(
                "Can't initialize %s. Key is an abstract base class and "
                "shouldn't be used to create cloud instances. All Key "
                "subclasses should define a `_controller_cls` class attribute "
                "pointing to a `BaseController` subclass." % self
            )
        elif not issubclass(self._controller_cls, BaseKeyController):
            raise TypeError(
                "Can't initialize %s.  All Key subclasses should define a"
                " `_controller_cls` class attribute pointing to a "
                "`BaseController` subclass." % self
            )
        self.ctl = self._controller_cls(self)

        # Calculate and store key type specific fields.
        self._key_specific_fields = [field for field in type(self)._fields
                                     if field not in Key._fields]

    @classmethod
    def add(cls, owner, name, id='', user=None, **kwargs):
        """Add key

        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.

        You 're not meant to be calling this directly, but on a key subclass
        instead like this:

            key = SSHKey.add(owner=org, name='unicorn', **kwargs)
        """
        if not name:
            raise RequiredParameterMissingError('name')
        if not owner or not isinstance(owner, Owner):
            raise BadRequestError('owner')
        key = cls(owner=owner, name=name)
        if id:
            key.id = id
        key.ctl.add(user=user, **kwargs)
        return key

    def delete(self):
        super(Key, self).delete()
        mist.api.tag.models.Tag.objects(
            resource_id=self.id, resource_type='key').delete()
        self.owner.mapper.remove(self)
        if self.owned_by:
            self.owned_by.get_ownership_mapper(self.owner).remove(self)

    def as_dict(self):
        # Return a dict as it will be returned to the API
        mdict = {
            'id': self.id,
            'name': self.name,
            'owner': self.owner.id,
            'default': self.default,
            'owned_by': self.owned_by.id if self.owned_by else '',
            'created_by': self.created_by.id if self.created_by else '',
        }

        mdict.update({key: getattr(self, key)
                      for key in self._key_specific_fields
                      if key not in self._private_fields})
        return mdict

    def as_dict_v2(self, deref='auto', only=''):
        """Returns the API representation of the `Volume` object."""
        from mist.api.helpers import prepare_dereferenced_dict
        from mist.api.machines.models import KeyMachineAssociation

        standard_fields = ['id', 'name', 'default']
        deref_map = {
            'owned_by': 'email',
            'created_by': 'email',
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)
        if 'associations' in only or not only:
            ret['associations'] = [
                km.as_dict_v2() for km in KeyMachineAssociation.objects(
                    key=self)
            ]
        if 'tags' in only or not only:
            ret['tags'] = {
                tag.key: tag.value
                for tag in Tag.objects(
                    owner=self.owner,
                    resource_id=self.id,
                    resource_type='key').only('key', 'value')
            }
        return ret

    def __str__(self):
        return '%s key %s (%s) of %s' % (type(self), self.name,
                                         self.id, self.owner)


class SSHKey(Key):
    """An ssh key."""

    public = me.StringField(required=True)
    private = me.EmbeddedDocumentField(SecretValue, required=True)

    _controller_cls = controllers.SSHKeyController
    _private_fields = ('private',)

    def clean(self):
        """Ensures that self is a valid RSA key pair."""

        from Crypto import Random
        Random.atfork()

        # Generate public key from private key file.
        try:
            key = RSAKey.from_private_key(io.StringIO(self.private.value))
            self.public = 'ssh-rsa ' + key.get_base64()
        except Exception:
            log.exception("Error while constructing public key "
                          "from private.")
            raise me.ValidationError("Private key is not a valid RSA key.")


class SignedSSHKey(SSHKey):
    """An signed ssh key."""

    certificate = me.StringField(required=True)

    _controller_cls = controllers.BaseKeyController

    def clean(self):
        """
        # Checks if certificate is specific ssh-rsa-cert
           and ensures that self is a valid RSA key pair."""
        super(SignedSSHKey, self).clean()
        if not self.certificate.startswith('ssh-rsa-cert-v01@openssh.com'):
            raise BadRequestError("Certificate is not a valid signed RSA key.")
