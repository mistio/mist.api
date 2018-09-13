import uuid
import mongoengine as me

from mist.api.clouds.models import Cloud
from mist.api.tag.models import Tag

from mist.api.machines.models import Machine

from mist.api.ownership.mixins import OwnershipMixin

from mist.api.volumes.controllers import StorageController


class Volume(OwnershipMixin, me.Document):
    """The basic Volume model.

    This class is only meant to be used as a basic class for cloud-specific
    `Volume` subclasses.

    `Volume` contains all common, provider-independent fields and handlers.
    """
    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    cloud = me.ReferenceField(Cloud, required=True)
    owner = me.ReferenceField('Organization')
    attached_to = me.ListField(me.ReferenceField(Machine,
                                                 reverse_delete_rule=me.PULL))
    external_id = me.StringField()
    name = me.StringField()
    size = me.IntField()
    location = me.StringField()
    state = me.StringField()

    extra = me.DictField()
    missing_since = me.DateTimeField()

    # GCE-specific
    disk_type = me.StringField(choices=('pd-standard', 'pd-ssd'))

    # EC2-specific
    volume_type = me.StringField(choices=('standard', 'gp2', 'io1',
                                          'sc1', 'st1'))
    iops = me.IntField()    # only for 'io1' type

    meta = {
        'allow_inheritance': True,
        'collection': 'volumes',
        'indexes': [
            {
                'fields': ['cloud', 'external_id'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ],
    }

    def __init__(self, *args, **kwargs):
        super(Volume, self).__init__(*args, **kwargs)
        # Set `ctl` attribute.
        self.ctl = StorageController(self)

    @classmethod
    def add(cls, cloud, name='', id='', **kwargs):
        """Add a Volume.

        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.

        You're not meant to be calling this directly, but on a volume subclass
        instead like this:

            volume = AmazonVolume.add(cloud=cloud, name='MyAmazonVolume')

        :param cloud: the Cloud on which the volume is going to be created.
        :param name: the name to be assigned to the new volume.
        :param description: an optional description.
        :param id: a custom object id, passed in case of a migration.
        :param kwargs: the kwargs to be passed to the corresponding controller.

        """
        assert isinstance(cloud, Cloud)
        volume = cls(cloud=cloud, name=name)
        if id:
            volume.id = id
        volume.ctl.create(**kwargs)
        return volume

    @property
    def tags(self):
        """Return the tags of this volume."""
        return [{'key': tag.key,
                 'value': tag.value} for tag in Tag.objects(resource=self)]

    def clean(self):
        self.owner = self.owner or self.cloud.owner
        # make sure that machines with disk attached aren't missing
        for machine in self.attached_to:
            if machine.missing_since is not None:
                self.attached_to.pop(machine)

    def delete(self):
        super(Volume, self).delete()
        self.owner.mapper.remove(self)
        Tag.objects(resource=self).delete()
        if self.owned_by:
            self.owned_by.get_ownership_mapper(self.owner).remove(self)

    def as_dict(self):
        """Returns the API representation of the `Volume` object."""
        volume_dict = {
            'id': self.id,
            'cloud': self.cloud.id,
            'external_id': self.external_id,
            'name': self.name,
            'extra': self.extra,
            'owner': self.owner,
            'state': self.state,
            'tags': self.tags,
            'size': self.size,
            'location': self.location,
            'attached_to': [m.as_dict() for m in self.attached_to],
            'disk_type': self.disk_type,
            'iops': self.iops,
            'volume_type': self.volume_type
        }

        return volume_dict

    def __str__(self):
        return '%s "%s" (%s)' % (self.__class__.__name__, self.name, self.id)
