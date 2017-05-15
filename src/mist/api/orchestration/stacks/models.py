import uuid
import datetime
import mongoengine as me

import mist.api.tag.models
import mist.api.orchestration.stacks.base as base
import mist.api.orchestration.templates.models as templates

from mist.api.users.models import Organization
from mist.api.machines.models import Machine


# Here we define the possible statuses of a Stack.
STATUS = (
    'ok',
    'error',
    'start_creation',
    'workflow_started',
)


class Stack(me.Document):
    """The main Stack mongonengine model."""

    id = me.StringField(primary_key=True, default=lambda: uuid4().hex)

    template = me.ReferenceField(templates.Template, required=True)
    name = me.StringField(required=True)
    description = me.StringField()

    deploy = me.BooleanField(required=True, default=False)
    status = me.StringField(required=True, choices=STATUS)

    inputs = me.DictField()  # Record of all inputs provided per workflow.
    workflows = me.ListField()  # List of all workflows ran against this Stack.

    # TODO: or perhaps inputs/workflows could be substituted by:
    # workflows = me.EmbeddedDocumentListField(templates.Workflow) + job_id

    node_instances = me.ListField()
    machines = me.ListField(me.ReferenceField(Machine))

    created_at = me.DateTimeField(default=datetime.datetime.utcnow)
    deleted = me.DateTimeField()

    job_id = me.StringField()  # The id of the latest workflow's logs.

    meta = {
        'allow_inheritance': True,
        'collection': 'stacks',
        'strict': False,
        'indexes': [
            {
                'fields': ['template', 'name', 'deleted'],
                'sparse': False,
                'unique': True,
                'cls': False,
            },
        ],
    }

    def __init__(self, *args, **kwargs):
        super(Stack, self).__init__(*args, **kwargs)
        self.ctl = base.StackController(self)

    @classmethod
    def add(cls, template, name, description='', id='', **kwargs):
        """Add a new Stack."""
        if not isinstance(template, templates.Template):
            raise RequiredParameterMissingError('template')
        if not name:
            raise RequiredParameterMissingError('name')
        stack = cls(template=template, name=name)
        if id:
            stack.id = id
        if description:
            stack.description = description
        stack.ctl.add(**kwargs)
        return stack

    @property
    def tags(self):
        """Return the tags of this Stack."""
        return {
            tag.key: tag.value for
            tag in mist.api.tag.models.Tag(owner=self.template.owner,
                                           resource=self)
        }

    def delete(self):
        super(Stack, self).delete()
        self.owner.mapper.remove(self)
        mist.api.tag.models.Tag.objects(resource=self).delete()

    def as_dict(self):
        return {
            'id': self.id,
            'template': self.template.id,
            'name': self.name,
            'description': self.description,
            'deploy': self.deploy,
            'status': self.status,
            'inputs': self.inputs,
            'workflows': self.workflows,
            'machines': [m.id for m in self.machines],
            'created_at': str(self.created_at),
            'job_id': self.job_id,
            'tags': [{'key': key, 'value': value} for key, value in self.tags],
        }

    # TODO
    # def as_dict_old(self):
    #     return {}

    def __str__(self):
        return '%s %s' % (self.__class__.__name__, self.name)
