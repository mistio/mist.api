import uuid

import mongoengine as me

from mist.api.mongoengine_extras import MistDictField


class CloudImage(me.Document):
    """A base Cloud Image Model."""
    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    cloud = me.ReferenceField('Cloud', required=True,
                              reverse_delete_rule=me.CASCADE)
    external_id = me.StringField(required=True)
    name = me.StringField()
    starred = me.BooleanField(default=True)
    missing_since = me.DateTimeField()
    extra = MistDictField()
    os_type = me.StringField(default='linux')
    # TODO: CHECK!
    meta = {
        'collection': 'images',
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

    # TODO: Check below and verify works correctly (ec2 and rackspace)
    def clean(self):
        # os_type is needed for the pricing per VM
        if self.name and self.cloud.ctl.provider.startswith('ec2'):
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
        if self.name and self.cloud.ctl.provider.startswith('rackspace'):
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

    def as_dict(self):
        return {
            'id': self.id,
            'cloud': self.cloud.id,
            'external_id': self.external_id,
            'name': self.name,
            'extra': self.extra,
            'os_type': self.os_type,
            'missing_since': str(self.missing_since.replace(tzinfo=None)
                                 if self.missing_since else '')
        }
