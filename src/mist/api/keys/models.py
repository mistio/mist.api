"""Key entity model"""
import io
import logging
from uuid import uuid4
import mongoengine as me
from paramiko.rsakey import RSAKey
import hvac

import mist.api.tag.models
from mist.api.users.models import Owner
from mist.api.exceptions import BadRequestError
from mist.api.keys import controllers
from mist.api.keys.base import BaseKeyController
from mist.api.exceptions import RequiredParameterMissingError
from mist.api.ownership.mixins import OwnershipMixin
from mist.api import config


log = logging.getLogger(__name__)



class SecretValue(me.EmbeddedDocument):
    secret = me.ReferenceField('Secret', required=True)
    key_name = me.StringField()

    @property
    def value(self):
        if self.key_name:
            return self.secret.value[self.key_name]
        else:
            return self.secret.value


class Key(OwnershipMixin, me.Document):
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
    instaniated, it is given a `ctl` attribute which gives access to the
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
            },
        ],
    }

    id = me.StringField(primary_key=True,
                        default=lambda: uuid4().hex)
    name = me.StringField(required=True)
    owner = me.ReferenceField(Owner, reverse_delete_rule=me.CASCADE)
    default = me.BooleanField(default=False)
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
    def add(cls, owner, name, id='', **kwargs):
        """Add key

        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.

        You 're not meant to be calling this directly, but on a key subclass
        instead like this:

            key = SSHKey.add(owner=org, name='unicorn', **kwargs)
        """
        if not name:
            raise RequiredParameterMissingError('title')
        if not owner or not isinstance(owner, Owner):
            raise BadRequestError('owner')
        key = cls(owner=owner, name=name)
        if id:
            key.id = id
        key.ctl.add(**kwargs)
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

    def __str__(self):
        return '%s key %s (%s) of %s' % (type(self), self.name,
                                         self.id, self.owner)



class SSHKey(Key):
    """An ssh key."""

    public = me.StringField(required=True)
    private = me.EmbeddedDocumentField(SecretValue)

    _controller_cls = controllers.SSHKeyController
    _private_fields = ('private',)

    def clean(self):
        """Ensures that self is a valid RSA keypair."""

        from Crypto import Random
        Random.atfork()

        # Generate public key from private key file.
        try:
            key = RSAKey.from_private_key(io.StringIO(self.private))
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
           and ensures that self is a valid RSA keypair."""
        super(SignedSSHKey, self).clean()
        if not self.certificate.startswith('ssh-rsa-cert-v01@openssh.com'):
            raise BadRequestError("Certificate is not a valid signed RSA key.")

class Secret(OwnershipMixin, me.Document):

    """ A Secret object """

    name = me.StringField(required=True)
    owner = me.ReferenceField(Owner, reverse_delete_rule=me.CASCADE)
    metadata = me.DictField(required=True)

    meta = {
        'allow_inheritance': True,
        'collection': 'secrets',
        'indexes': [
            {
                'fields': ['owner', 'name'],
                'sparse': False,
                'unique': False,
                'cls': False,
            },
        ],
    }

    _controller_cls = None

    def __init__(self, *args, **kwargs):
        super(Key, self).__init__(*args, **kwargs)

        # Set attribute `ctl` to an instance of the appropriate controller.
        if self._controller_cls is None:
            raise NotImplementedError(
                "Can't initialize %s. Secret is an abstract base class and "
                "shouldn't be used to create cloud instances. All Key "
                "subclasses should define a `_controller_cls` class attribute "
                "pointing to a `BaseController` subclass." % self
            )
        # elif not issubclass(self._controller_cls, VaultController):
        #     raise TypeError(
        #         "Can't initialize %s.  All Secret subclasses should define a"
        #         " `_controller_cls` class attribute pointing to a "
        #         "`BaseController` subclass." % self
        #     )
        # self.ctl = self._controller_cls(self)

        # # Calculate and store key type specific fields.
        # self._secret_specific_fields = [field for field in type(self)._fields
                                        # if field not in Secret._fields]

    @property
    def data(self):
        raise NotImplementedError


class VaultSecret(Secret):
    """ A Vault Secret object """

    secret_engine_name = me.StringField(required=True)

    client = hvac.Client()

    #_controller_cls = controllers.VaultController

    def __init__(self,
                 name,
                 secret_engine_name='kv1',
                 metadata={},
                 *args, **kwargs):

        """ Construct Secret object given Secret's Path """
        super(Secret, self).__init__(*args, **kwargs)
        self.secret_engine_name = secret_engine_name
        self.name = name
        self.metadata = metadata

    def list_secrets(self):
        """ List all available Secrets in Secret Engine """
        print(self.client.list(self.secret_engine_name)['data'])

    def list_sec_engines(self):
        """ List all available Secret Engines """
        print(self.client.list_secret_backends()['data'])

    @property
    def data(self):
        """ TODO """

        token = config.VAULT_TOKEN
        url = config.VAULT_ADDR

        self.client = hvac.Client(url=url, token=token)
        assert(self.client.is_authenticated())

        # Construct Vault API path
        secret_path = self.secret_engine_name + '/' + self.secret_name

        # Check KV version; kv1 or kv2
        version = self.client.\
            lists_secret_backends()[self.secret_engine_name + '/']['type']

        # TODO: Make sure the response works with all types of Secrets
        api_response = self.client.read(secret_path)

        # KV1
        if version == 'kv':
            return self.kv1_secret(api_response)
        # KV2
        elif version == 'kv2':
            return self.kv2_secret(api_response)
        # Not Supported
        else:
            exit('Wrong Secret type')

    def kv1_secret(self, returned_secret):
        """ Retrieve Secret value from "data" of JSON reply """
        try:
            key = returned_secret['data']
        except KeyError:
            print(returned_secret)
        return key

    def kv2_secret(self, returned_secret):
        # TODO: Check if this works
        """ Retrieve Secret value from "data" of JSON reply """
        try:
            key = returned_secret['data']
        except KeyError:
            print(returned_secret)
        return key
