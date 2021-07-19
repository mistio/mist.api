"""Definition of Container mongoengine models"""

import uuid
import logging

import mongoengine as me

from mist.api.models import Cloud
from mist.api.models import CloudLocation
from mist.api.models import Organization
from mist.api.tag.models import Tag
from mist.api.ownership.mixins import OwnershipMixin
from mist.api.mongoengine_extras import MistDictField

from mist.api import config as api_config

__all__ = [
    "Cluster",
    "GKECluster",
]
# This is a map from provider name to provider class, eg:
# 'google': GKECluster
# It is autofilled by _populate_clusters which is run on the end of this file.
CLUSTERS = {}


log = logging.getLogger(__name__)


def _populate_clusters():
    """Populates CLUSTERS variable with mappings from providers to clusters"""
    for key, value in list(globals().items()):
        if not key.startswith('_') and key.endswith(
                'Cluster') and key != 'Cluster':
            if issubclass(value, Cluster) and value is not Cluster:
                CLUSTERS[value.provider] = value


class Cluster(OwnershipMixin, me.Document):
    """Abstract base class for every cluster mongoengine model

    This class defines the fields common to all clusters of all types. For each
    different cluster type, a subclass should be created adding any
    cluster-specific fields and methods.

    Documents of all Cluster subclasses will be stored on the same mongo
    collection.

    One can perform a query directly on Cluster to fetch all cluster types,
    like this:

        Cluster.objects(owner=owner).count()

    This will return an iterable of clusters for that owner. Each cluster will
    be an instance of its respective Cluster subclass, like GKECluster
    instances.

    Clusters of a specific type can be queried like this:

        GKECluster.objects(owner=owner).count()

    This will return an iterable of GKECluster instances.

    To create a new cluster, one should initialize a Cluster subclass like
    GKECluster. Intializing directly a Cluster instance won't have any
    credential fields or associated handler to work with.
    """

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    cloud = me.ReferenceField(Cloud, required=True,
                              reverse_delete_rule=me.CASCADE)
    owner = me.ReferenceField(Organization, required=True,
                              reverse_delete_rule=me.CASCADE)
    location = me.ReferenceField(CloudLocation, required=False,
                                 reverse_delete_rule=me.DENY)
    name = me.StringField(required=True)
    external_id = me.StringField(required=True)
    cloud = me.ReferenceField('Cloud', required=True,
                              reverse_delete_rule=me.CASCADE)
    name = me.StringField()
    total_nodes = me.IntField()
    total_cpus = me.IntField()
    total_memory = me.IntField()
    config = MistDictField()
    extra = MistDictField()
    state = me.StringField(
        default=api_config.CLUSTER_STATES['STATUS_UNSPECIFIED'],
        choices=tuple(api_config.CLUSTER_STATES.values()))
    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    created = me.DateTimeField()

    meta = {
        'strict': False,
        'allow_inheritance': True,
        'collection': 'containers',
        'indexes': [
            'owner', 'last_seen', 'missing_since',
            'name', 'cloud',
            {
                'fields': [
                    'cloud',
                ],
                'sparse': False,
                'unique': True,
                'cls': False,
            }
        ],
    }

    _private_fields = ()

    def __init__(self, *args, **kwargs):
        super(Cluster, self).__init__(*args, **kwargs)

    def clean(self):
        # Populate owner field based on self.cloud.owner
        self.owner = self.cloud.owner

    @property
    def provider(self):
        return self.cloud.provider

    @property
    def tags(self):
        return {
            tag.key: tag.value
            for tag in Tag.objects(
                owner=self.owner,
                resource_id=self.id,
                resource_type='cluster').only('key', 'value')
        }

    def delete(self):
        super(Cluster, self).delete()
        Tag.objects(resource_id=self.id, resource_type='cluster').delete()
        try:
            self.owner.mapper.remove(self)
        except Exception as exc:
            log.error("Got error %r while removing cluster %s", exc, self.id)
        try:
            if self.owned_by:
                self.owned_by.get_ownership_mapper(self.owner).remove(self)
        except Exception as exc:
            log.error("Got error %r while removing cluster %s", exc, self.id)

    def as_dict(self):
        cdict = {
            'id': self.id,
            'name': self.name,
            'external_id': self.external_id,
            'owner': self.owner.id,
            'cloud': self.cloud.id,
            'provider': self.provider,
            'total_nodes': self.total_nodes,
            'total_cpus': self.total_cpus,
            'total_memory': self.total_memory,
            'location': self.location.id,
            'config': self.config,
            'extra': self.extra,
            'state': self.state,
            'last_seen': self.last_seen,
            'missing_since': self.missing_since,
            'created': self.created,
            'tags': self.tags,
            'owned_by': self.owned_by.email if self.owned_by else '',
            'created_by': self.created_by.email if self.created_by else '',
        }
        return cdict

    def as_dict_v2(self, deref='auto', only=''):
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = [
            'id',
            'name',
            'external_id',
            'provider',
            'total_nodes',
            'total_cpus',
            'total_memory',
            'location',
            'config',
            'extra',
            'state',
            'last_seen',
            'missing_since',
            'created',
            'tags'
        ]
        deref_map = {
            'cloud': 'id',
            'owner': 'id',
            'location': 'id',
            'owned_by': 'email',
            'created_by': 'email'
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)
        return ret

    def __str__(self):
        return '%s cluster %s (%s) of %s' % (type(self), self.name,
                                             self.id, self.owner)


class GKECluster(Cluster):
    provider = 'google'
    client_email = me.StringField(required=True)
    private_key = me.StringField(required=True)
    project_id = me.StringField(required=True)
    _private_fields = ('private_key', )


_populate_clusters()
