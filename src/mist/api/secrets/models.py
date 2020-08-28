import logging
import mongoengine as me
#import hvac
from mist.api.users.models import Owner
from mist.api.ownership.mixins import OwnershipMixin
from mist.api.secrets import controllers
from mist.api import config


log = logging.getLogger(__name__)


class Secret(OwnershipMixin, me.Document):
    """ A Secret object """

    name = me.StringField(required=True)
    owner = me.ReferenceField(Owner, reverse_delete_rule=me.CASCADE)
    metadata = me.DictField(required=False) # TODO

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
        super(Secret, self).__init__(*args, **kwargs)

        # Set attribute `ctl` to an instance of the appropriate controller.
        if self._controller_cls is None:
            raise NotImplementedError(
                "Can't initialize %s. Secret is an abstract base class and "
                "shouldn't be used to create cloud instances. All Secret "
                "subclasses should define a `_controller_cls` class attribute "
                "pointing to a `BaseSecretController` subclass." % self
            )
        elif not issubclass(self._controller_cls, controllers.BaseSecretController):
            raise TypeError(
                "Can't initialize %s.  All Secret subclasses should define a"
                " `_controller_cls` class attribute pointing to a "
                "`BaseSecretController` subclass." % self
            )
        self.ctl = self._controller_cls(self)

        # Calculate and store key type specific fields.
        self._secret_specific_fields = [field for field in type(self)._fields
                                        if field not in Secret._fields]

    @property
    def data(self):
        raise NotImplementedError


class VaultSecret(Secret):
    """ A Vault Secret object """

    secret_engine_name = me.StringField(required=True)

    _controller_cls = controllers.VaultSecretController

    def __init__(self,
                 name,
                 data,
                 secret_engine_name='kv1',
                 metadata={},
                 *args, **kwargs):

        """ Construct Secret object given Secret's path """
        super(VaultSecret, self).__init__(*args, **kwargs)
        self.secret_engine_name = secret_engine_name
        self.name = name
        self.metadata = metadata

    @property
    def data(self):
        if self._data:
            self.ctl.create_secret(self._data)
        else:
            return self.ctl.read_secret()

    def retrieve_kv(self):
        """ Retrieve Secret value from "data" of JSON reply """
        try:
            # Supposes that data is read from Vault
            key = self.data['data']
        except KeyError:
            print(self.data)
        return key


class SecretValue(me.EmbeddedDocument):
    """ Retrieve the value of a Secret object """

    secret = me.ReferenceField(Secret, required=True)
    key_name = me.StringField()

    @property
    def value(self):
        if self.key_name:
            return self.secret.retrieve_kv[self.key_name]
        else:
            return self.secret.retrieve_kv
