"""Definition of Cloud mongoengine models"""

import uuid
import logging

import mongoengine as me

from mist.api.tag.models import Tag
from mist.api.keys.models import Key
from mist.api.users.models import Organization
from mist.api.ownership.mixins import OwnershipMixin
from mist.api.mongoengine_extras import MistDictField

from mist.api.clouds.controllers.main import controllers

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import CloudExistsError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api import config

__all__ = [
    "Cloud",
    "CloudLocation",
    "CloudSize",
    "AmazonCloud",
    "AlibabaCloud",
    "DigitalOceanCloud",
    "MaxihostCloud",
    "LinodeCloud",
    "RackSpaceCloud",
    "SoftLayerCloud",
    "AzureCloud",
    "AzureArmCloud",
    "GoogleCloud",
    "HostVirtualCloud",
    "PacketCloud",
    "VultrCloud",
    "VSphereCloud",
    "VCloud",
    "OpenStackCloud",
    "DockerCloud",
    "LibvirtCloud",
    "OnAppCloud",
    "OtherCloud",
    "KubeVirtCloud"
]
# This is a map from provider name to provider class, eg:
# 'linode': LinodeCloud
# It is autofilled by _populate_clouds which is run on the end of this file.
CLOUDS = {}


log = logging.getLogger(__name__)


def _populate_clouds():
    """Populates CLOUDS variable with mappings from providers to clouds"""
    for key, value in list(globals().items()):
        if key.endswith('Cloud') and key != 'Cloud':
            value = globals()[key]
            if issubclass(value, Cloud) and value is not Cloud:
                CLOUDS[value._controller_cls.provider] = value


class Cloud(OwnershipMixin, me.Document):
    """Abstract base class for every cloud/provider mongoengine model

    This class defines the fields common to all clouds of all types. For each
    different cloud type, a subclass should be created adding any cloud
    specific fields and methods.

    Documents of all Cloud subclasses will be stored on the same mongo
    collection.

    One can perform a query directly on Cloud to fetch all cloud types, like
    this:

        Cloud.objects(owner=owner).count()

    This will return an iterable of clouds for that owner. Each cloud will be
    an instance of its respective Cloud subclass, like AmazonCloud and
    LinodeCloud instances.

    Clouds of a specific type can be queried like this:

        AmazonCloud.objects(owner=owner).count()

    This will return an iterable of AmazonCloud instances.

    To create a new cloud, one should initialize a Cloud subclass like
    AmazonCloud. Intializing directly a Cloud instance won't have any
    credential fields or associated handler to work with.

    Each Cloud subclass should define a `_controller_cls` class attribute. Its
    value should be a subclass of
    `mist.api.clouds.controllers.main.base.BaseMainController`. These
    subclasses are stored in `mist.api.clouds.controllers`. When a cloud is
    instanciated, it is given a `ctl` attribute which gives access to the
    clouds controller. This way it is possible to do things like:

        cloud = Cloud.objects.get(id=cloud_id)
        print cloud.ctl.compute.list_machines()

    """

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    owner = me.ReferenceField(Organization, required=True,
                              reverse_delete_rule=me.CASCADE)

    title = me.StringField(required=True)
    enabled = me.BooleanField(default=True)

    machine_count = me.IntField(default=0)

    starred = me.ListField()
    unstarred = me.ListField()
    polling_interval = me.IntField(default=0)  # in seconds

    dns_enabled = me.BooleanField(default=False)
    observation_logs_enabled = me.BooleanField(default=False)

    default_monitoring_method = me.StringField(
        choices=config.MONITORING_METHODS)

    deleted = me.DateTimeField()

    meta = {
        'strict': False,
        'allow_inheritance': True,
        'collection': 'clouds',  # collection 'cloud' is used by core's model
        'indexes': [
            'owner',
            # Following index ensures owner with title combos are unique
            {
                'fields': ['owner', 'title', 'deleted'],
                'sparse': False,
                'unique': True,
                'cls': False,
            }
        ],
    }

    _private_fields = ()
    _controller_cls = None

    def __init__(self, *args, **kwargs):
        super(Cloud, self).__init__(*args, **kwargs)

        # Set attribute `ctl` to an instance of the appropriate controller.
        if self._controller_cls is None:
            raise NotImplementedError(
                "Can't initialize %s. Cloud is an abstract base class and "
                "shouldn't be used to create cloud instances. All Cloud "
                "subclasses should define a `_controller_cls` class attribute "
                "pointing to a `BaseMainController` subclass." % self
            )
        elif not issubclass(self._controller_cls,
                            controllers.BaseMainController):
            raise TypeError(
                "Can't initialize %s.  All Cloud subclasses should define a "
                "`_controller_cls` class attribute pointing to a "
                "`BaseMainController` subclass." % self
            )
        self.ctl = self._controller_cls(self)

        # Calculate and store cloud type specific fields.
        self._cloud_specific_fields = [field for field in type(self)._fields
                                       if field not in Cloud._fields]

    @classmethod
    def add(cls, owner, title, id='', **kwargs):
        """Add cloud

        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.

        You're not meant to be calling this directly, but on a cloud subclass
        instead like this:

            cloud = AmazonCloud.add(owner=org, title='EC2',
                                    apikey=apikey, apisecret=apisecret)

        Params:
        - owner and title are common and required params
        - only provide a custom cloud id if you're migrating something
        - kwargs will be passed to appropriate controller, in most cases these
          should match the extra fields of the particular cloud type.

        """
        if not title:
            raise RequiredParameterMissingError('title')
        if not owner or not isinstance(owner, Organization):
            raise BadRequestError('owner')
        if Cloud.objects(owner=owner, title=title, deleted=None):
            raise CloudExistsError()
        cloud = cls(owner=owner, title=title)
        if id:
            cloud.id = id
        cloud.ctl.add(**kwargs)
        return cloud

    def delete(self):
        super(Cloud, self).delete()
        Tag.objects(resource_id=self.id, resource_type='cloud').delete()
        try:
            self.owner.mapper.remove(self)
        except Exception as exc:
            log.error("Got error %r while removing cloud %s", exc, self.id)
        try:
            if self.owned_by:
                self.owned_by.get_ownership_mapper(self.owner).remove(self)
        except Exception as exc:
            log.error("Got error %r while removing cloud %s", exc, self.id)

    def clean(self):
        if self.dns_enabled and not hasattr(self.ctl, 'dns'):
            self.dns_enabled = False

    def as_dict(self):
        cdict = {
            'id': self.id,
            'title': self.title,
            'provider': self.ctl.provider,
            'enabled': self.enabled,
            'dns_enabled': self.dns_enabled,
            'observation_logs_enabled': self.observation_logs_enabled,
            'state': 'online' if self.enabled else 'offline',
            'polling_interval': self.polling_interval,
            'tags': {
                tag.key: tag.value
                for tag in Tag.objects(
                    owner=self.owner,
                    resource_id=self.id,
                    resource_type='cloud').only('key', 'value')
            },
            'owned_by': self.owned_by.id if self.owned_by else '',
            'created_by': self.created_by.id if self.created_by else '',
        }
        cdict.update({key: getattr(self, key)
                      for key in self._cloud_specific_fields
                      if key not in self._private_fields})
        return cdict

    def __str__(self):
        return '%s cloud %s (%s) of %s' % (type(self), self.title,
                                           self.id, self.owner)


class CloudLocation(OwnershipMixin, me.Document):
    """A base Cloud Location Model."""
    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    cloud = me.ReferenceField('Cloud', required=True,
                              reverse_delete_rule=me.CASCADE)
    owner = me.ReferenceField('Organization', required=True,
                              reverse_delete_rule=me.CASCADE)
    external_id = me.StringField(required=True)
    name = me.StringField()
    country = me.StringField()
    missing_since = me.DateTimeField()
    extra = MistDictField()

    meta = {
        'collection': 'locations',
        'indexes': [
            {
                'fields': ['cloud', 'external_id'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ]
    }

    def __str__(self):
        name = "%s, %s (%s)" % (self.name, self.cloud.id, self.external_id)
        return name

    def as_dict(self):
        return {
            'id': self.id,
            'extra': self.extra,
            'cloud': self.cloud.id,
            'external_id': self.external_id,
            'name': self.name,
            'country': self.country,
            'missing_since': str(self.missing_since.replace(tzinfo=None)
                                 if self.missing_since else '')
        }

    def clean(self):
        # Populate owner field based on self.cloud.owner
        if not self.owner:
            self.owner = self.cloud.owner


class CloudSize(me.Document):
    """A base Cloud Size Model."""
    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    cloud = me.ReferenceField('Cloud', required=True,
                              reverse_delete_rule=me.CASCADE)
    external_id = me.StringField(required=True)
    name = me.StringField()
    cpus = me.IntField()
    ram = me.IntField()
    disk = me.IntField()
    bandwidth = me.IntField()
    missing_since = me.DateTimeField()
    extra = MistDictField()  # price info  is included here

    meta = {
        'collection': 'sizes',
        'indexes': [
            {
                'fields': ['cloud', 'external_id'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ]
    }

    def __str__(self):
        name = "%s, %s (%s)" % (self.name, self.cloud.id, self.external_id)
        return name

    def as_dict(self):
        return {
            'id': self.id,
            'cloud': self.cloud.id,
            'external_id': self.external_id,
            'name': self.name,
            'cpus': self.cpus,
            'ram': self.ram,
            'bandwidth': self.bandwidth,
            'extra': self.extra,
            'disk': self.disk,
            'missing_since': str(self.missing_since.replace(tzinfo=None)
                                 if self.missing_since else '')
        }


class AmazonCloud(Cloud):

    apikey = me.StringField(required=True)
    apisecret = me.StringField(required=True)
    region = me.StringField(required=True)

    _private_fields = ('apisecret', )
    _controller_cls = controllers.AmazonMainController


class AlibabaCloud(AmazonCloud):

    _controller_cls = controllers.AlibabaMainController


class DigitalOceanCloud(Cloud):

    token = me.StringField(required=True)

    _private_fields = ('token', )
    _controller_cls = controllers.DigitalOceanMainController


class MaxihostCloud(Cloud):

    token = me.StringField(required=True)

    _private_fields = ('token', )
    _controller_cls = controllers.MaxihostMainController


class GigG8Cloud(Cloud):

    apikey = me.StringField(required=True)
    user_id = me.IntField(required=True)
    url = me.StringField(required=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.GigG8MainController


class LinodeCloud(Cloud):

    apikey = me.StringField(required=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.LinodeMainController


class RackSpaceCloud(Cloud):

    username = me.StringField(required=True)
    apikey = me.StringField(required=True)
    region = me.StringField(required=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.RackSpaceMainController


class SoftLayerCloud(Cloud):

    username = me.StringField(required=True)
    apikey = me.StringField(required=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.SoftLayerMainController


class AzureCloud(Cloud):

    subscription_id = me.StringField(required=True)
    certificate = me.StringField(required=True)

    _private_fields = ('certificate', )
    _controller_cls = controllers.AzureMainController


class AzureArmCloud(Cloud):

    tenant_id = me.StringField(required=True)
    subscription_id = me.StringField(required=True)
    key = me.StringField(required=True)
    secret = me.StringField(required=True)

    _private_fields = ('secret', )
    _controller_cls = controllers.AzureArmMainController


class GoogleCloud(Cloud):

    email = me.StringField(required=True)
    private_key = me.StringField(required=True)
    project_id = me.StringField(required=True)

    _private_fields = ('private_key', )
    _controller_cls = controllers.GoogleMainController


class HostVirtualCloud(Cloud):

    apikey = me.StringField(required=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.HostVirtualMainController


class PacketCloud(Cloud):

    apikey = me.StringField(required=True)
    project_id = me.StringField(required=False)

    _private_fields = ('apikey', )
    _controller_cls = controllers.PacketMainController


class VultrCloud(Cloud):

    apikey = me.StringField(required=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.VultrMainController


class VSphereCloud(Cloud):

    host = me.StringField(required=True)
    username = me.StringField(required=True)
    password = me.StringField(required=True)
    ca_cert_file = me.StringField(required=False)
    # Some vSphere clouds will timeout when calling list_nodes, unless we
    # perform the requests in batches, fetching a few properties each time.
    # The following property should be set to something like 4 when that
    # happens. It's not clear if it's due a vSphere configuration. In most
    # cases this is not necessary. The default value will fetch all requested
    # properties at once

    max_properties_per_request = me.IntField(default=20)

    _private_fields = ('password', )
    _controller_cls = controllers.VSphereMainController


class VCloud(Cloud):

    host = me.StringField(required=True)
    username = me.StringField(required=True)
    password = me.StringField(required=True)
    port = me.IntField(required=True, default=443)

    _private_fields = ('password', )
    _controller_cls = controllers.VCloudMainController


class OpenStackCloud(Cloud):

    username = me.StringField(required=True)
    password = me.StringField(required=True)
    url = me.StringField(required=True)
    tenant = me.StringField(required=True)
    domain = me.StringField(required=False)
    region = me.StringField(required=False)
    compute_endpoint = me.StringField(required=False)

    _private_fields = ('password', )
    _controller_cls = controllers.OpenStackMainController


class DockerCloud(Cloud):

    host = me.StringField(required=True)
    port = me.IntField(required=True, default=4243)

    # User/Password Authentication (optional)
    username = me.StringField(required=False)
    password = me.StringField(required=False)

    # TLS Authentication (optional)
    key_file = me.StringField(required=False)
    cert_file = me.StringField(required=False)
    ca_cert_file = me.StringField(required=False)
    # Show running and stopped containers
    show_all = me.BooleanField(default=False)

    _private_fields = ('password', 'key_file')
    _controller_cls = controllers.DockerMainController


class LXDCloud(Cloud):
    """
    Model  specializing Cloud for LXC.
    """

    # TODO: verify default port for LXD container
    host = me.StringField(required=True)
    port = me.IntField(required=True, default=8443)

    # User/Password Authentication (optional)
    username = me.StringField(required=False)
    password = me.StringField(required=False)

    # TLS Authentication (optional)
    key_file = me.StringField(required=False)
    cert_file = me.StringField(required=False)
    ca_cert_file = me.StringField(required=False)

    # Show running and stopped containers
    show_all = me.BooleanField(default=False)

    _private_fields = ('password', 'key_file')
    _controller_cls = controllers.LXDMainController


class LibvirtCloud(Cloud):

    host = me.StringField(required=True)
    username = me.StringField(default='root')
    port = me.IntField(required=True, default=22)
    key = me.ReferenceField(Key, required=False, reverse_delete_rule=me.DENY)
    images_location = me.StringField(default="/var/lib/libvirt/images")

    _controller_cls = controllers.LibvirtMainController

    def as_dict(self):
        cdict = super(LibvirtCloud, self).as_dict()
        cdict['key'] = self.key.id
        return cdict


class OnAppCloud(Cloud):

    username = me.StringField(required=True)
    apikey = me.StringField(required=True)
    host = me.StringField(required=True)
    verify = me.BooleanField(default=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.OnAppMainController


class OtherCloud(Cloud):

    _controller_cls = controllers.OtherMainController


class KubeVirtCloud(Cloud):
    host = me.StringField(required=True)
    port = me.IntField(required=True, default=6443)

    # USER / PASS authentication optional
    username = me.StringField(required=False)
    password = me.StringField(required=False)

    # Bearer Token authentication optional
    token_bearer_auth = me.BooleanField(required=False)
    key_file = me.StringField(required=False)

    # TLS Authentication
    # key_file again
    cert_file = me.StringField(required=False)

    # certificate authority
    ca_cert_file = me.StringField(required=False)

    # certificate verification
    verify = me.BooleanField(required=False)

    _private_fields = ('password', 'key_file', 'cert_file', 'ca_cert_file')
    _controller_cls = controllers.KubeVirtMainController


_populate_clouds()
