"""Cloud related classes"""
import mongoengine as me


class CloudImage(me.Document):
    """A base Cloud Image Model."""
    image_id = me.StringField(required=True)
    cloud_provider = me.StringField(required=True)
    cloud_region = me.StringField()  # eg for RackSpace
    name = me.StringField()
    os_type = me.StringField(default='linux')
    deprecated = me.BooleanField(default=False)

    meta = {
        'indexes': [
            'cloud_provider',
            'image_id',
            {
                'fields': ['cloud_provider', 'cloud_region', 'image_id'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ],
    }

    def __str__(self):
        name = "%s, %s (%s)" % (self.name, self.cloud_provider, self.image_id)
        return name

    def clean(self):
        # os_type is needed for the pricing per VM
        if self.name and self.cloud_provider.startswith('ec2'):
            if 'suse linux enterprise' or 'sles' in self.name.lower():
                self.os_type = 'sles'
            if 'red hat' or 'rhel' in self.name.lower():
                self.os_type = 'rhel'
            if 'windows' in self.name.lower():
                self.os_type = 'mswin'
                if 'sql' in self.name.lower():
                    self.os_type = 'mswinSQL'
                    if 'web' in self.name.lower():
                        self.os_type = 'mswinSQLWeb'
            if 'vyatta' in self.name.lower():
                self.os_type = 'vyatta'
        if self.name and self.cloud_provider.startswith('rackspace'):
            if 'red hat' in self.name.lower():
                self.os_type = 'redhat'
            if 'windows server' in self.name.lower():
                self.os_type = 'windows'
                if 'sql' in self.name.lower():
                    self.os_type = 'mssql-standard'
                    if 'web' in self.name.lower():
                        self.os_type = 'mssql-web'
            if 'vyatta' in self.name.lower():
                self.os_type = 'vyatta'

        super(CloudImage, self).clean()


class CloudSize(me.Document):
    """A base Cloud Size Model."""
    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    cloud = me.ReferenceField('Cloud', required=True)
    external_id = me.StringField(required=True)
    name = me.StringField()
    cpus = me.IntField()
    ram = me.IntField()
    price = me.FloatField()
    disk = me.IntField()
    bandwidth = me.IntField()
    missing_since = me.DateTimeField()

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

    def __init__(self, *args, **kwargs):
        super(CloudSize, self).__init__(*args, **kwargs)

    def __str__(self):
        name = "%s, %s (%s)" % (self.name, self.cloud, self.external_id)
        return name

    def as_dict(self):
        return {
            'id': self.id,
            'external_id': self.external_id,
            'name': self.name,
            'cpus': self.cpus,
            'ram': self.ram,
            'bandwidth': self.bandwidth,
            'price': self.price,
            'disk': self.disk,
            'missing_since': str(self.missing_since.replace(tzinfo=None)
                                 if self.missing_since else '')
        }
