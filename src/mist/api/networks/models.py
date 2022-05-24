import re
import uuid
import netaddr
import mongoengine as me

from mist.api.ownership.mixins import OwnershipMixin
from mist.api.mongoengine_extras import MistDictField

from mist.api.exceptions import RequiredParameterMissingError

from mist.api.tag.models import Tag
from mist.api.tag.mixins import TagMixin
from mist.api.clouds.models import Cloud
from mist.api.clouds.models import CLOUDS

from mist.api.networks.controllers import SubnetController
from mist.api.networks.controllers import NetworkController


# Automatically populated mappings of all Network and Subnet subclasses,
# keyed by their provider name.
NETWORKS, SUBNETS = {}, {}


def _populate_class_mapping(mapping, class_suffix, base_class):
    """Populates a dict that matches a provider name with its model class."""
    for key, value in list(globals().items()):
        if key.endswith(class_suffix) and key != class_suffix:
            if issubclass(value, base_class) and value is not base_class:
                for provider, cls in list(CLOUDS.items()):
                    if key.replace(class_suffix, '') in repr(cls):
                        mapping[provider] = value


class Network(OwnershipMixin, me.Document, TagMixin):
    """The basic Network model.

    This class is only meant to be used as a basic class for cloud-specific
    `Network` subclasses.

    `Network` contains all common, provider-independent fields and handlers.
    """

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    owner = me.ReferenceField('Organization', reverse_delete_rule=me.CASCADE)
    cloud = me.ReferenceField(Cloud, required=True,
                              reverse_delete_rule=me.CASCADE)
    external_id = me.StringField()  # required=True)

    name = me.StringField()
    cidr = me.StringField()
    description = me.StringField()
    location = me.ReferenceField('CloudLocation', required=False,
                                 reverse_delete_rule=me.DENY)

    extra = MistDictField()  # The `extra` dictionary returned by libcloud.
    created = me.DateTimeField()
    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    first_seen = me.DateTimeField()

    meta = {
        'allow_inheritance': True,
        'collection': 'networks',
        'indexes': [
            'last_seen',
            {
                'fields': ['cloud', 'external_id'],
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
        super(Network, self).__init__(*args, **kwargs)
        # Set `ctl` attribute.
        self.ctl = NetworkController(self)
        # Calculate and store network type specific fields.
        self._network_specific_fields = [field for field in type(self)._fields
                                         if field not in Network._fields]

    @classmethod
    def add(cls, cloud, cidr=None, name='', description='', id='',
            location='', **kwargs):
        """Add a Network.

        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.

        You're not meant to be calling this directly, but on a network subclass
        instead like this:

            network = AmazonNetwork.add(cloud=cloud, name='Ec2Network')

        :param cloud: the Cloud on which the network is going to be created.
        :param cidr:
        :param name: the name to be assigned to the new network.
        :param description: an optional description.
        :param id: a custom object id, passed in case of a migration.
        :param kwargs: the kwargs to be passed to the corresponding controller.

        """
        assert isinstance(cloud, Cloud)
        network = cls(cloud=cloud, cidr=cidr, name=name,
                      description=description)
        if id:
            network.id = id
        if location:
            from mist.api.models import CloudLocation
            try:
                location = CloudLocation.objects.get(id=location)
            except me.DoesNotExist:
                try:
                    location = CloudLocation.objects.get(
                        external_id=location)
                except me.DoesNotExist:
                    location = None
            network.location = location
        return network.ctl.create(**kwargs)

    def clean(self):
        """Checks the CIDR to determine if it maps to a valid IPv4 network."""
        if self.cidr:
            try:
                netaddr.cidr_to_glob(self.cidr)
            except (TypeError, netaddr.AddrFormatError) as err:
                raise me.ValidationError(err)
        self.owner = self.owner or self.cloud.owner

    def delete(self):
        super(Network, self).delete()
        self.owner.mapper.remove(self)
        Tag.objects(resource_id=self.id, resource_type='network').delete()
        if self.owned_by:
            self.owned_by.get_ownership_mapper(self.owner).remove(self)

    def as_dict(self):
        """Returns the API representation of the `Network` object."""
        net_dict = {
            'id': self.id,
            'subnets': {s.id: s.as_dict() for s
                        in Subnet.objects(network=self, missing_since=None)},
            'cloud': self.cloud.id,
            'external_id': self.external_id,
            'name': self.name,
            'cidr': self.cidr,
            'description': self.description,
            'extra': self.extra,
            'created': str(self.created),
            'last_seen': str(self.last_seen),
            'tags': {
                tag.key: tag.value
                for tag in Tag.objects(
                    resource_id=self.id,
                    resource_type='network').only('key', 'value')
            },
            'owned_by': self.owned_by.id if self.owned_by else '',
            'created_by': self.created_by.id if self.created_by else '',
            'location': self.location.id if self.location else '',
        }
        net_dict.update(
            {key: getattr(self, key) for key in self._network_specific_fields}
        )
        return net_dict

    def as_dict_v2(self, deref='auto', only=''):
        """Returns the API representation of the `Network` object."""
        # TODO: add machines
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = ['id', 'name', 'external_id', 'extra',
                           'last_seen', 'created']
        deref_map = {
            'cloud': 'name',
            'location': 'name',
            'owned_by': 'email',
            'created_by': 'email',
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)

        if 'subnets' in only or not only:
            ret['subnets'] = {s.id: s.as_dict() for s
                              in Subnet.objects(network=self,
                                                missing_since=None)}
        if 'tags' in only or not only:
            ret['tags'] = {
                tag.key: tag.value
                for tag in Tag.objects(
                    resource_id=self.id,
                    resource_type='network').only('key', 'value')
            }
        if 'last_seen' in ret:
            ret['last_seen'] = str(ret['last_seen'])
        if 'created' in ret:
            ret['created'] = str(ret['created'])

        return ret

    def __str__(self):
        return '%s "%s" (%s)' % (self.__class__.__name__, self.name, self.id)


class AmazonNetwork(Network):
    instance_tenancy = me.StringField(default='default', choices=('default',
                                                                  'private'))

    def clean(self):
        """Extended validation for EC2 Networks to ensure CIDR assignment."""
        if not self.cidr:
            raise me.ValidationError('Missing IPv4 range in CIDR notation')
        super(AmazonNetwork, self).clean()


class AzureArmNetwork(Network):
    instance_tenancy = me.StringField(default='default', choices=('default',
                                                                  'private'))
    resource_group = me.StringField()

    def clean(self):
        """Extended validation for EC2 Networks to ensure CIDR assignment."""
        if not self.cidr:
            raise me.ValidationError('Missing IPv4 range in CIDR notation')
        super(AzureArmNetwork, self).clean()


class GoogleNetwork(Network):
    mode = me.StringField(default='legacy', choices=('legacy', 'auto',
                                                     'custom'))

    def clean(self):
        """Custom validation for GCE Networks.

        GCE enforces:

            - Regex constrains on network names, names must be
              lowercase letters, numbers, and hyphens.
            - CIDR assignment are not supported for any of the available modes
              'auto' and 'custom'.

        """
        if self.cidr:
            raise me.ValidationError('CIDR cannot be set on Google Networks')

        if not re.match('^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$', self.name):
            raise me.ValidationError('A **lowercase** name must be specified')

        super(GoogleNetwork, self).clean()


class OpenStackNetwork(Network):
    shared = me.BooleanField(default=False)
    admin_state_up = me.BooleanField(default=True)
    router_external = me.BooleanField(default=False)


class VexxhostNetwork(OpenStackNetwork):
    pass


class LibvirtNetwork(Network):
    pass


class VSphereNetwork(Network):
    pass


class LXDNetwork(Network):
    pass


class AlibabaNetwork(Network):
    pass


class VultrNetwork(Network):
    pass


class Subnet(me.Document, TagMixin):
    """The basic Subnet model.

    This class is only meant to be used as a basic class for cloud-specific
    `Subnet` subclasses.

    `Subnet` contains all common, provider-independent fields and handlers.
    """

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    owner = me.ReferenceField('Organization', reverse_delete_rule=me.CASCADE)
    network = me.ReferenceField('Network', required=True,
                                reverse_delete_rule=me.CASCADE)
    external_id = me.StringField()

    name = me.StringField()
    cidr = me.StringField(required=True)
    description = me.StringField()

    extra = MistDictField()  # The `extra` dictionary returned by libcloud.
    created = me.DateTimeField()
    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    first_seen = me.DateTimeField()

    meta = {
        'allow_inheritance': True,
        'collection': 'subnets',
        'indexes': [
            'last_seen',
            {
                'fields': ['network', 'external_id'],
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
        super(Subnet, self).__init__(*args, **kwargs)
        # Set `ctl` attribute.
        self.ctl = SubnetController(self)
        # Calculate and store subnet type specific fields.
        self._subnet_specific_fields = [field for field in type(self)._fields
                                        if field not in Subnet._fields]

    @classmethod
    def add(cls, network, cidr, name='', description='', id='', **kwargs):
        """Add a Subnet.

        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.

        You're not meant to be calling this directly, but on a network subclass
        instead like this:

            subnet = AmazonSubnet.add(network=network,
                                      name='Ec2Subnet',
                                      cidr='172.31.10.0/24')

        :param network: the Network nn which the subnet is going to be created.
        :param cidr: the CIDR to be assigned to the new subnet.
        :param name: the name to be assigned to the new subnet.
        :param description: an optional description.
        :param id: a custom object id, passed in case of a migration.
        :param kwargs: the kwargs to be passed to the corresponding controller.

        """
        assert isinstance(network, Network)
        if not cidr:
            raise RequiredParameterMissingError('cidr')
        subnet = cls(network=network, cidr=cidr, name=name,
                     description=description)
        if id:
            subnet.id = id
        return subnet.ctl.create(**kwargs)

    def clean(self):
        """Checks the CIDR to determine if it maps to a valid IPv4 network."""
        self.owner = self.owner or self.network.cloud.owner
        try:
            netaddr.cidr_to_glob(self.cidr)
        except (TypeError, netaddr.AddrFormatError) as err:
            raise me.ValidationError(err)

    def delete(self):
        super(Subnet, self).delete()
        Tag.objects(resource_id=self.id, resource_type='subnet').delete()

    def as_dict(self):
        """Returns the API representation of the `Subnet` object."""
        subnet_dict = {
            'id': self.id,
            'cloud': self.network.cloud.id,
            'network': self.network.id,
            'external_id': self.external_id,
            'name': self.name,
            'cidr': self.cidr,
            'description': self.description,
            'extra': self.extra,
            'tags': {
                tag.key: tag.value
                for tag in Tag.objects(
                    resource_id=self.id,
                    resource_type='subnet')
            },
            'created': str(self.created),
            'last_seen': str(self.last_seen),
        }
        subnet_dict.update(
            {key: getattr(self, key) for key in self._subnet_specific_fields}
        )
        return subnet_dict

    def __str__(self):
        return '%s "%s" (%s)' % (self.__class__.__name__, self.name, self.id)


class AmazonSubnet(Subnet):
    availability_zone = me.StringField(required=True)


class AzureArmSubnet(Subnet):
    pass


class GoogleSubnet(Subnet):
    region = me.StringField(required=True)

    def clean(self):
        """Extended validation for GCE Subnets."""
        if not re.match('^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$', self.name):
            raise me.ValidationError('A **lowercase** name must be specified')
        super(GoogleSubnet, self).clean()


class OpenStackSubnet(Subnet):
    gateway_ip = me.StringField()
    ip_version = me.IntField(default=4)
    enable_dhcp = me.BooleanField(default=True)
    dns_nameservers = me.ListField(default=lambda: [])
    allocation_pools = me.ListField(default=lambda: [])


class VexxhostSubnet(OpenStackSubnet):
    pass


class AlibabaSubnet(Subnet):
    availability_zone = me.StringField(required=True)


_populate_class_mapping(NETWORKS, 'Network', Network)
_populate_class_mapping(SUBNETS, 'Subnet', Subnet)
