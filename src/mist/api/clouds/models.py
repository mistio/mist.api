"""Definition of Cloud mongoengine models"""

import uuid
import logging
import datetime

import mongoengine as me

from mist.api.tag.models import Tag
from mist.api.tag.mixins import TagMixin
from mist.api.users.models import Organization
from mist.api.ownership.mixins import OwnershipMixin
from mist.api.mongoengine_extras import MistDictField
from mist.api.secrets.models import SecretValue

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
    "EquinixMetalCloud",
    "VultrCloud",
    "VSphereCloud",
    "OpenStackCloud",
    "DockerCloud",
    "LXDCloud",
    "LibvirtCloud",
    "OnAppCloud",
    "OtherCloud",
    "KubeVirtCloud",
    "KubernetesCloud",
    "OpenShiftCloud",
    "CloudSigmaCloud",
    "_KubernetesBaseCloud",
]
# This is a map from provider name to provider class, eg:
# 'linode': LinodeCloud
# It is autofilled by _populate_clouds which is run on the end of this file.
CLOUDS = {}


log = logging.getLogger(__name__)


def _populate_clouds():
    """Populates CLOUDS variable with mappings from providers to clouds"""
    for key, value in list(globals().items()):
        if not key.startswith('_') and key.endswith(
                'Cloud') and key != 'Cloud':
            if not value._controller_cls:
                continue
            if issubclass(value, Cloud) and value is not Cloud:
                CLOUDS[value._controller_cls.provider] = value

    # Add aliases to CLOUDS dictionary
    for key, value in config.PROVIDERS.items():
        driver_name = value['driver']
        cloud_aliases = [key] + value['aliases']
        if CLOUDS.get(driver_name):
            for alias in cloud_aliases:
                CLOUDS[alias] = CLOUDS[driver_name]
        else:
            value = next((CLOUDS.get(alias) for alias in cloud_aliases
                         if CLOUDS.get(alias)), None)
            if value:
                for alias in cloud_aliases:
                    CLOUDS[alias] = value


class Cloud(OwnershipMixin, me.Document, TagMixin):
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
    AmazonCloud. Initializing directly a Cloud instance won't have any
    credential fields or associated handler to work with.

    Each Cloud subclass should define a `_controller_cls` class attribute. Its
    value should be a subclass of
    `mist.api.clouds.controllers.main.base.BaseMainController`. These
    subclasses are stored in `mist.api.clouds.controllers`. When a cloud is
    instantiated, it is given a `ctl` attribute which gives access to the
    clouds controller. This way it is possible to do things like:

        cloud = Cloud.objects.get(id=cloud_id)
        print cloud.ctl.compute.list_machines()

    """

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    owner = me.ReferenceField(Organization, required=True,
                              reverse_delete_rule=me.CASCADE)

    name = me.StringField(required=True)
    enabled = me.BooleanField(default=True)

    machine_count = me.IntField(default=0)
    cluster_count = me.IntField(default=0)

    starred = me.ListField()
    unstarred = me.ListField()
    polling_interval = me.IntField(default=0)  # in seconds

    dns_enabled = me.BooleanField(default=False)
    object_storage_enabled = me.BooleanField(default=False)
    observation_logs_enabled = me.BooleanField(default=False)
    container_enabled = me.BooleanField(default=False)

    default_monitoring_method = me.StringField(
        choices=config.MONITORING_METHODS)
    created = me.DateTimeField(default=datetime.datetime.now)
    deleted = me.DateTimeField()

    meta = {
        'strict': False,
        'allow_inheritance': True,
        'collection': 'clouds',  # collection 'cloud' is used by core's model
        'indexes': [
            'owner',
            # Following index ensures owner with name combos are unique
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

    @property
    def org(self):
        return self.owner

    @property
    def provider(self):
        return self.ctl.provider

    @classmethod
    def add(cls, owner, name, user=None, id='', **kwargs):
        """Add cloud

        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.

        You're not meant to be calling this directly, but on a cloud subclass
        instead like this:

            cloud = AmazonCloud.add(owner=org, name='EC2',
                                    apikey=apikey, apisecret=apisecret)

        Params:
        - owner and name are common and required params
        - only provide a custom cloud id if you're migrating something
        - kwargs will be passed to appropriate controller, in most cases these
          should match the extra fields of the particular cloud type.

        """
        if not name:
            raise RequiredParameterMissingError('name')
        if not owner or not isinstance(owner, Organization):
            raise BadRequestError('owner')
        if Cloud.objects(owner=owner, name=name, deleted=None):
            raise CloudExistsError()
        cloud = cls(owner=owner, name=name)
        if id:
            cloud.id = id
        fail_on_error = kwargs.pop('fail_on_error', True)
        fail_on_invalid_params = kwargs.pop('fail_on_invalid_params', False)
        cloud.ctl.add(user, **kwargs)
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
        if self.object_storage_enabled and \
                not hasattr(self.ctl, 'objectstorage'):
            self.object_storage_enabled = False

    def as_dict(self):
        cdict = {
            'id': self.id,
            'name': self.name,
            'provider': self.ctl.provider,
            'enabled': self.enabled,
            'dns_enabled': self.dns_enabled,
            'object_storage_enabled': self.object_storage_enabled,
            'observation_logs_enabled': self.observation_logs_enabled,
            'container_enabled': self.container_enabled,
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
                      if (key not in self._private_fields and getattr(self,
                                                                      key))})
        return cdict

    def as_dict_v2(self, deref='auto', only=''):
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = ['id', 'name', 'provider']
        deref_map = {
            'owned_by': 'email',
            'created_by': 'email'
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)

        if 'tags' in only or not only:
            ret['tags'] = {
                tag.key: tag.value
                for tag in Tag.objects(
                    owner=self.owner,
                    resource_id=self.id,
                    resource_type='cloud').only('key', 'value')
            }

        if 'features' in only or not only:
            ret['features'] = {
                'compute': self.enabled,
                'dns': self.dns_enabled,
                'object_storage_enabled': self.object_storage_enabled,
                'observations': self.observation_logs_enabled,
                'container': self.container_enabled,
                'polling': self.polling_interval
            }

        if 'config' in only or not only:
            ret['config'] = {}
            ret['config'].update({
                key: getattr(self, key)
                for key in self._cloud_specific_fields
                if key not in self._private_fields
            })
        return ret

    def __str__(self):
        return '%s cloud %s (%s) of %s' % (type(self), self.name,
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
    created = me.DateTimeField()
    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    first_seen = me.DateTimeField()
    extra = MistDictField()
    images_location = me.StringField()

    parent = me.ReferenceField('CloudLocation',
                               required=False,
                               reverse_delete_rule=me.NULLIFY)
    location_type = me.StringField(choices=('zone', 'region'))
    capabilities = me.ListField(me.StringField(
        choices=config.LOCATION_CAPABILITIES), default=None)

    available_sizes = me.ListField(
        me.ReferenceField('CloudSize')
    )
    available_images = me.ListField(
        me.ReferenceField('CloudImage')
    )
    meta = {
        'collection': 'locations',
        'indexes': [
            'cloud', 'external_id', 'name', 'missing_since',
            'last_seen', 'location_type', 'parent',
            {
                'fields': ['cloud', 'external_id'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ]
    }

    def __str__(self):
        # this is for mongo medthod objects.only('id') to work..
        if self.cloud:
            name = "%s, %s (%s)" % (self.name, self.cloud.id, self.external_id)
        else:
            name = f"{self.name}, None, {self.external_id}"
        return name

    def as_dict_v2(self, deref='auto', only=''):
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = [
            'id', 'name', 'external_id', 'country', 'extra', 'last_seen',
            'location_type', 'created', 'images_location']
        deref_map = {
            'cloud': 'name',
            'owned_by': 'email',
            'created_by': 'email',
            'available_sizes': 'name',
            'available_images': 'name',
            'parent': 'id',
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)
        if 'last_seen' in ret:
            ret['last_seen'] = str(ret['last_seen'])
        if 'created' in ret:
            ret['created'] = str(ret['created'])
        if self.capabilities and len(self.capabilities) > 0:
            ret["capabilities"] = self.capabilities

        return ret

    def as_dict(self, extra=True):
        location_dict = {
            'id': self.id,
            'extra': self.extra if extra else {},
            'cloud': self.cloud.id if self.cloud else None,  # same as above
            'external_id': self.external_id,
            'name': self.name,
            'country': self.country,
            'created': str(self.created),
            'last_seen': str(self.last_seen),
            'parent': self.parent.id if self.parent else None,
            'location_type': self.location_type,
            'images_location': self.images_location,
            'missing_since': str(self.missing_since.replace(tzinfo=None)
                                 if self.missing_since else ''),
        }

        if self.cloud.ctl.has_feature('location-image-restriction'):
            location_dict['available_images'] = {image.id: image.name for image
                                                 in self.available_images
                                                 if hasattr(image, 'name')}
        if self.cloud.ctl.has_feature('location-size-restriction'):
            location_dict['available_sizes'] = {size.id: size.name for size
                                                in self.available_sizes
                                                if hasattr(size, 'name')}
        if self.capabilities and len(self.capabilities) > 0:
            location_dict["capabilities"] = self.capabilities
        return location_dict

    def clean(self):
        # Populate owner field based on self.cloud.owner
        if not self.owner:
            self.owner = self.cloud.owner

    @property
    def children(self):
        if self.location_type == 'region':
            return CloudLocation.objects(parent=self.id)
        return CloudLocation.objects.none()


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
    created = me.DateTimeField()
    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    first_seen = me.DateTimeField()
    extra = MistDictField()  # price info  is included here
    architecture = me.StringField(default='x86', choices=('x86', 'arm'))
    allowed_images = me.ListField(
        me.ReferenceField('CloudImage')
    )

    meta = {
        'collection': 'sizes',
        'indexes': [
            'cloud',
            'external_id',
            'last_seen',
            'missing_since',
            {
                'fields': ['cloud', 'external_id'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ]
    }

    def __str__(self):
        # this is for mongo medthod objects.only('id') to work..
        if self.cloud:
            name = "%s, %s (%s)" % (self.name, self.cloud.id, self.external_id)
        else:
            name = f"{self.name}, None, {self.external_id}"
        return name

    def as_dict_v2(self, deref='auto', only=''):
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = [
            'id', 'name', 'external_id', 'cpus', 'ram', 'bandwidth', 'disk',
            'architecture', 'extra', 'last_seen', 'created']
        deref_map = {
            'cloud': 'name',
            'allowed_images': 'name',
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)
        if 'last_seen' in ret:
            ret['last_seen'] = str(ret['last_seen'])
        if 'created' in ret:
            ret['created'] = str(ret['created'])
        return ret

    def as_dict(self, extra=True):
        size_dict = {
            'id': self.id,
            'cloud': self.cloud.id if self.cloud else None,  # same as above
            'external_id': self.external_id,
            'name': self.name,
            'cpus': self.cpus,
            'ram': self.ram,
            'bandwidth': self.bandwidth,
            'extra': self.extra if extra else {},
            'disk': self.disk,
            'architecture': self.architecture,
            'created': str(self.created),
            'last_seen': str(self.last_seen),
            'missing_since': str(self.missing_since.replace(tzinfo=None)
                                 if self.missing_since else ''),
        }

        if self.cloud.ctl.has_feature('size-image-restriction'):
            size_dict['allowed_images'] = {image.id: image.name for image
                                           in self.allowed_images
                                           if hasattr(image, 'name')}
        return size_dict


class AmazonCloud(Cloud):

    apikey = me.StringField(required=True)
    apisecret = me.EmbeddedDocumentField(SecretValue, required=True)
    region = me.StringField(required=True)

    _private_fields = ('apisecret', )
    _controller_cls = controllers.AmazonMainController


class AlibabaCloud(AmazonCloud):

    _controller_cls = controllers.AlibabaMainController


class DigitalOceanCloud(Cloud):

    token = me.EmbeddedDocumentField(SecretValue, required=True)

    _private_fields = ('token', )
    _controller_cls = controllers.DigitalOceanMainController


class MaxihostCloud(Cloud):

    token = me.EmbeddedDocumentField(SecretValue, required=True)

    _private_fields = ('token', )
    _controller_cls = controllers.MaxihostMainController


class LinodeCloud(Cloud):
    apikey = me.EmbeddedDocumentField(SecretValue, required=True)
    apiversion = me.StringField(null=True, default=None)
    _private_fields = ('apikey', )
    _controller_cls = controllers.LinodeMainController


class RackSpaceCloud(Cloud):

    username = me.StringField(required=True)
    apikey = me.EmbeddedDocumentField(SecretValue, required=True)
    region = me.StringField(required=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.RackSpaceMainController


class SoftLayerCloud(Cloud):

    username = me.StringField(required=True)
    apikey = me.EmbeddedDocumentField(SecretValue, required=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.SoftLayerMainController


class AzureCloud(Cloud):

    subscription_id = me.EmbeddedDocumentField(SecretValue, required=True)
    certificate = me.EmbeddedDocumentField(SecretValue, required=True)

    _private_fields = ('subscription_id', 'certificate', )
    _controller_cls = controllers.AzureMainController


class AzureArmCloud(Cloud):

    tenant_id = me.StringField(required=True)
    subscription_id = me.StringField(required=True)
    key = me.StringField(required=True)
    secret = me.EmbeddedDocumentField(SecretValue, required=True)

    _private_fields = ('secret', )
    _controller_cls = controllers.AzureArmMainController


class GoogleCloud(Cloud):

    email = me.StringField(required=True)
    private_key = me.EmbeddedDocumentField(SecretValue, required=True)
    project_id = me.StringField(required=True)

    _private_fields = ('private_key', )
    _controller_cls = controllers.GoogleMainController


class HostVirtualCloud(Cloud):

    apikey = me.EmbeddedDocumentField(SecretValue, required=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.HostVirtualMainController


class EquinixMetalCloud(Cloud):

    apikey = me.EmbeddedDocumentField(SecretValue, required=True)
    project_id = me.StringField(required=False)

    _private_fields = ('apikey', )
    _controller_cls = controllers.EquinixMetalMainController


class VultrCloud(Cloud):

    apikey = me.EmbeddedDocumentField(SecretValue, required=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.VultrMainController


class VSphereCloud(Cloud):

    host = me.StringField(required=True)
    username = me.StringField(required=True)
    password = me.EmbeddedDocumentField(SecretValue, required=True)
    ca_cert_file = me.EmbeddedDocumentField(SecretValue, required=False)
    # Some vSphere clouds will timeout when calling list_nodes, unless we
    # perform the requests in batches, fetching a few properties each time.
    # The following property should be set to something like 4 when that
    # happens. It's not clear if it's due a vSphere configuration. In most
    # cases this is not necessary. The default value will fetch all requested
    # properties at once

    max_properties_per_request = me.IntField(default=20)

    _private_fields = ('password', 'ca_cert_file')
    _controller_cls = controllers.VSphereMainController


class OpenStackCloud(Cloud):

    username = me.StringField(required=True)
    password = me.EmbeddedDocumentField(SecretValue, required=True)
    url = me.StringField(required=True)
    tenant = me.StringField(required=True)
    tenant_id = me.StringField(required=False)
    domain = me.StringField(required=False)
    region = me.StringField(required=False)
    compute_endpoint = me.StringField(required=False)

    _private_fields = ('password', )
    _controller_cls = controllers.OpenStackMainController


class VexxhostCloud(OpenStackCloud):
    _controller_cls = controllers.VexxhostMainController


class DockerCloud(Cloud):

    host = me.StringField(required=True)
    port = me.IntField(required=True, default=4243)

    # User/Password Authentication (optional)
    username = me.EmbeddedDocumentField(SecretValue, required=False)
    password = me.EmbeddedDocumentField(SecretValue, required=False)

    # TLS Authentication (optional)
    key_file = me.EmbeddedDocumentField(SecretValue, required=False)
    cert_file = me.EmbeddedDocumentField(SecretValue, required=False)
    ca_cert_file = me.EmbeddedDocumentField(SecretValue, required=False)
    # Show running and stopped containers
    show_all = me.BooleanField(default=False)

    _private_fields = (
        'username', 'password', 'key_file', 'cert_file', 'ca_cert_file')
    _controller_cls = controllers.DockerMainController


class LXDCloud(Cloud):
    """
    Model  specializing Cloud for LXC.
    """

    host = me.StringField(required=True)
    port = me.IntField(required=True, default=8443)

    # User/Password Authentication (optional)
    username = me.EmbeddedDocumentField(SecretValue, required=False)
    password = me.EmbeddedDocumentField(SecretValue, required=False)

    # TLS Authentication (optional)
    key_file = me.EmbeddedDocumentField(SecretValue, required=False)
    cert_file = me.EmbeddedDocumentField(SecretValue, required=False)
    ca_cert_file = me.EmbeddedDocumentField(SecretValue, required=False)

    # Show running and stopped containers
    show_all = me.BooleanField(default=False)

    _private_fields = (
        'username', 'password', 'key_file', 'cert_file', 'ca_cert_file')
    _controller_cls = controllers.LXDMainController


class LibvirtCloud(Cloud):

    _controller_cls = controllers.LibvirtMainController
    hosts = me.ListField(me.StringField())


class OnAppCloud(Cloud):

    username = me.StringField(required=True)
    apikey = me.EmbeddedDocumentField(SecretValue, required=True)
    host = me.StringField(required=True)
    verify = me.BooleanField(default=True)

    _private_fields = ('apikey', )
    _controller_cls = controllers.OnAppMainController


class OtherCloud(Cloud):

    _controller_cls = controllers.OtherMainController


class _KubernetesBaseCloud(Cloud):
    host = me.StringField(required=True)
    port = me.IntField(required=True, default=6443)

    # USER / PASS authentication optional
    username = me.EmbeddedDocumentField(SecretValue, required=False)
    password = me.EmbeddedDocumentField(SecretValue, required=False)

    # Bearer Token authentication optional
    token = me.EmbeddedDocumentField(SecretValue, required=False)

    # TLS Authentication
    key_file = me.EmbeddedDocumentField(SecretValue, required=False)
    cert_file = me.EmbeddedDocumentField(SecretValue, required=False)

    # certificate authority
    ca_cert_file = me.EmbeddedDocumentField(SecretValue, required=False)

    # certificate verification
    verify = me.BooleanField(required=False)

    _private_fields = (
        'username', 'password', 'token',
        'key_file', 'cert_file', 'ca_cert_file')


class KubeVirtCloud(_KubernetesBaseCloud):
    _controller_cls = controllers.KubeVirtMainController


class _KubernetesProxyCloud(_KubernetesBaseCloud):
    def as_dict_v2(self, *args, **kwargs):
        ret = super().as_dict_v2(*args, **kwargs)
        ret['namespaces'] = self.ctl.compute.list_namespaces()
        ret['services'] = self.ctl.compute.list_services()
        ret['resources'] = self.ctl.compute.get_node_resources()
        ret['version'] = self.ctl.compute.get_version()
        return ret


class KubernetesCloud(_KubernetesProxyCloud):
    _controller_cls = controllers.KubernetesMainController


class OpenShiftCloud(_KubernetesProxyCloud):
    _controller_cls = controllers.OpenShiftMainController


class CloudSigmaCloud(Cloud):

    username = me.StringField(required=True)
    password = me.EmbeddedDocumentField(SecretValue, required=True)
    region = me.StringField(required=True)

    _private_fields = ('password', )
    _controller_cls = controllers.CloudSigmaMainController


_populate_clouds()
