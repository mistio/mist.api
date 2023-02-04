"""Schedule entity model."""
import datetime
import logging
from uuid import uuid4

import mongoengine as me

from mist.api.helpers import rtype_to_classpath
from mist.api.tag.models import Tag
from mist.api.exceptions import BadRequestError
from mist.api.users.models import Organization
from mist.api.exceptions import ScheduleNameExistsError
from mist.api.exceptions import RequiredParameterMissingError
from mist.api.selectors.models import SelectorClassMixin
from mist.api.ownership.mixins import OwnershipMixin
from mist.api.tag.mixins import TagMixin
from mist.api.actions.models import ActionClassMixin
from mist.api.actions.models import BaseAction
from mist.api.actions.models import MachineAction
from mist.api.when.models import BaseWhenType
from mist.api.when.models import Crontab
from mist.api.helpers import extract_selector_type

log = logging.getLogger(__name__)

#: Authorized values for Interval.period
PERIODS = ('days', 'hours', 'minutes', 'seconds', 'microseconds')


# DEPRECATED
class BaseScheduleType(me.EmbeddedDocument):
    """Abstract Base class used as a common interface
    for scheduler types. There are three different types
    for now: Interval, Crontab and OneOff
    """
    meta = {'allow_inheritance': True}

    @property
    def schedule(self):
        raise NotImplementedError()


# DEPRECATED
class BaseTaskType(me.EmbeddedDocument):
    """Abstract Base class used as a common interface
    for scheduler's tasks types. Action and Script"""

    meta = {'allow_inheritance': True}

    @property
    def args(self):
        raise NotImplementedError()

    @property
    def kwargs(self):
        raise NotImplementedError()

    @property
    def task(self):
        raise NotImplementedError()


# DEPRECATED
class ActionTask(BaseTaskType):
    action = me.StringField()

    @property
    def args(self):
        return self.action

    @property
    def kwargs(self):
        return {}

    @property
    def task(self):
        return 'mist.api.tasks.group_resources_actions'

    def __str__(self):
        return f'Action: {self.action}'

    def as_dict(self):
        return {
            'action': self.action
        }


# DEPRECATED
class ScriptTask(BaseTaskType):
    script_id = me.StringField()
    params = me.StringField()

    @property
    def args(self):
        return self.script_id

    @property
    def kwargs(self):
        return {'params': self.params}

    @property
    def task(self):
        return 'mist.api.tasks.group_run_script'

    def __str__(self):
        return f'Run script: {self.script_id}'

    def as_dict(self):
        return {
            'script_id': self.script_id,
            'params': self.params
        }


class Schedule(OwnershipMixin, me.Document, SelectorClassMixin, TagMixin,
               ActionClassMixin):
    """Abstract base class for every schedule attr mongoengine model.
    This model is based on celery periodic task and creates defines the fields
    common to all schedules of all types. For each different schedule type, a
    subclass should be created adding any schedule specific fields and methods.

     Documents of all Schedule subclasses will be stored on the same mongo
    collection.

    One can perform a query directly on Schedule to fetch all cloud types, like
    this:

        Schedule.objects(owner=org).count()

    """

    meta = {
        'collection': 'schedules',
        'allow_inheritance': True,
        'indexes': [
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

    id = me.StringField(primary_key=True, default=lambda: uuid4().hex)
    name = me.StringField(required=True)
    description = me.StringField()
    deleted = me.DateTimeField()

    owner = me.ReferenceField(Organization, required=False,
                              reverse_delete_rule=me.CASCADE)

    # celery periodic task specific fields
    queue = me.StringField()
    exchange = me.StringField()
    routing_key = me.StringField()

    # mist specific fields
    schedule_type = me.EmbeddedDocumentField(BaseScheduleType, required=False)
    task_type = me.EmbeddedDocumentField(BaseTaskType, required=False)

    # Defines a list of actions to be executed whenever
    # the schedule is triggered.
    # Defaults to just notifying the users.
    actions = me.EmbeddedDocumentListField(
        BaseAction, required=False, default=lambda: [MachineAction()]
    )

    when = me.EmbeddedDocumentField(BaseWhenType, required=False)

    # celerybeat-mongo specific fields
    expires = me.DateTimeField()
    start_after = me.DateTimeField()
    task_enabled = me.BooleanField(default=False)
    run_immediately = me.BooleanField()
    last_run_at = me.DateTimeField()
    total_run_count = me.IntField(min_value=0, default=0)
    max_run_count = me.IntField(min_value=0, default=0)

    reminder = me.ReferenceField('Schedule', required=False,
                                 reverse_delete_rule=me.NULLIFY)

    created = me.DateTimeField(default=datetime.datetime.now)

    no_changes = False

    def __init__(self, *args, **kwargs):
        # FIXME
        import mist.api.schedules.base
        super(Schedule, self).__init__(*args, **kwargs)
        self.ctl = mist.api.schedules.base.BaseController(self)

    @property
    def org(self):
        return self.owner

    @property
    def org_id(self):
        # FIXME We should consider storing the org id as a plain
        # string, instead of using a ReferenceField, to minimize
        # unintentional dereferencing. This is already happending
        # in case of mist.api.rules.models.Rule.
        return self.org.id

    @classmethod
    def add(cls, auth_context, name, **kwargs):
        """Add schedule

        This is a class method, meaning that it is meant to be called on the
        class itself and not on an instance of the class.

        You're not meant to be calling this directly, but on a schedule class
        instead like this:

            schedule = Schedule.add(owner=org, **kwargs)
        """
        org = auth_context.owner

        if not name:
            raise RequiredParameterMissingError('name')
        if not org or not isinstance(org, Organization):
            raise BadRequestError('org')
        selector_type = extract_selector_type(**kwargs)
        if selector_type not in rtype_to_classpath:
            raise BadRequestError('selector_type')
        kwargs['selector_type'] = selector_type
        if Schedule.objects(owner=org, name=name, deleted=None):
            raise ScheduleNameExistsError()
        schedule = cls(owner=org, name=name,
                       resource_model_name=selector_type)
        schedule.ctl.set_auth_context(auth_context)
        schedule.ctl.add(**kwargs)
        schedule.assign_to(auth_context.user)
        return schedule

    @property
    def schedule(self):
        if self.when:
            return self.when.schedule
        else:
            raise Exception("must define interval, crontab, one_off schedule")

    @property
    def args(self):
        if self.resource_model_name == 'machine' or \
                self.resource_model_name == 'machines':
            ids = [machine.id for machine in self.get_resources() if
                   machine.state != 'terminated']
        else:
            ids = [resource.id for resource in self.get_resources()]
        fire_up = self.actions[0].args
        return [self.org.id, fire_up, self.name, ids]

    @property
    def kwargs(self):
        return self.actions[0].kwargs

    @property
    def task(self):
        return self.actions[0].task

    @property
    def enabled(self):
        if self.deleted:
            return False
        try:
            if not self.get_resources().count():
                return False
        except Exception as e:
            log.error('Error getting resources for schedule %s: %r' % (
                self.id, e))
            return False

        if self.expires and self.expires < datetime.datetime.now():
            return False
        if self.start_after and self.start_after < datetime.datetime.now():
            return False
        if self.max_run_count and (
            (self.total_run_count or 0) >= int(self.max_run_count)
        ):
            return False
        else:
            return self.task_enabled

    def __unicode__(self):
        fmt = '{0.name}: {{no schedule}}'
        if self.when:
            fmt = 'name: {0.name} type: {0.when._cls}'
        else:
            raise Exception("must define interval or crontab schedule")
        return fmt.format(self)

    def validate(self, clean=True):
        """
        Override mongoengine validate. We should validate crontab entry.
            Use crontab_parser for crontab expressions.
            The parser is a general purpose one, useful for parsing hours,
            minutes and day_of_week expressions.

            example for minutes:
                minutes = crontab_parser(60).parse('*/15')
                [0, 15, 30, 45]

        """
        if isinstance(self.when, Crontab):
            try:
                from apscheduler.triggers.cron import CronTrigger
                CronTrigger.from_crontab(self.when.as_cron())
            except ValueError as exc:
                raise me.ValidationError('Crontab validation failed: %s' % exc)

        super(Schedule, self).validate(clean=True)

    def clean(self):
        if self.resource_model_name not in rtype_to_classpath:
            self.resource_model_name = 'machine'

    def delete(self):
        if self.reminder:
            self.reminder.delete()
        super(Schedule, self).delete()
        Tag.objects(resource_id=self.id, resource_type='schedule').delete()
        self.org.mapper.remove(self)
        if self.owned_by:
            self.owned_by.get_ownership_mapper(self.org).remove(self)

    def as_dict(self):
        # Return a dict as it will be returned to the API

        last_run = '' if self.total_run_count == 0 else str(self.last_run_at)

        selectors = [selector.as_dict() for selector in self.selectors]

        action = self.actions[0]

        sdict = {
            'id': self.id,
            'name': self.name,
            'description': self.description or '',
            'schedule': str(self.when),
            'schedule_type': self.when.type,
            'schedule_entry': self.when.as_dict(),
            'expires': str(self.expires or ''),
            'start_after': str(self.start_after or ''),
            'task_enabled': self.task_enabled,
            'active': self.enabled,
            'last_run_at': last_run,
            'total_run_count': self.total_run_count,
            'max_run_count': self.max_run_count,
            'selectors': selectors,
            'owned_by': self.owned_by.id if self.owned_by else '',
            'created_by': self.created_by.id if self.created_by else '',
        }
        task_type = {}
        if action.__class__.__name__ == 'ScriptAction':
            task_type['action'] = 'run script'
            task_type['script_id'] = action.script
            task_type['params'] = action.params
        else:
            task_type['action'] = self.actions[0].atype
        sdict['task_type'] = task_type

        return sdict

    def as_dict_v2(self, deref='auto', only=''):
        """Returns the API representation of the `Schedule` object."""
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = ['id', 'name', 'description',
                           'start_after', 'run_immediately']
        deref_map = {
            'owned_by': 'email',
            'created_by': 'email'
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)

        if 'schedule_entry' in only or not only:
            ret['schedule_entry'] = self.when.as_dict()

        if 'schedule_type' in only or not only:
            ret['schedule_type'] = self.when.type

        ret['actions'] = self.actions[0].action

        ret['enabled'] = self.task_enabled

        selectors = [selector.as_dict() for selector in self.selectors]

        ret['selectors'] = selectors

        if 'tags' in only or not only:
            ret['tags'] = {
                tag.key: tag.value
                for tag in Tag.objects(
                    owner=self.org,
                    resource_id=self.id,
                    resource_type='schedule').only('key', 'value')
            }

        return ret
