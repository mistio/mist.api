import uuid
import mongoengine as me

from mist.api.exceptions import BadRequestError
from mist.api.users.models import Organization
from mist.api.machines.models import Machine
from mist.api.conditions.models import ConditionalClassMixin

from mist.api.rules.base import ResourceRuleController
from mist.api.rules.base import ArbitraryRuleController
from mist.api.rules.actions import BaseAlertAction
from mist.api.rules.actions import NotificationAction
from mist.api.rules.conditions import Window
from mist.api.rules.conditions import Frequency
from mist.api.rules.conditions import TriggerOffset
from mist.api.rules.conditions import QueryCondition


class Rule(me.Document):
    """The base Rule mongoengine model.

    The Rule class defines the base schema of all rule types. All documents of
    any Rule subclass will be stored in the same mongo collection.

    All Rule subclasses MUST define a `_controller_cls` class attribute and a
    backend plugin. Controllers are used to perform actions on instances of
    Rule, such as adding or updating. Backend plugins are used to transform a
    Rule into the corresponding query to be executed against a certain data
    storage. Different types of rules, such as a rule on monitoring metrics or
    a rule on logging data, should also define and utilize their respective
    backend plugins. For instance, a rule on monitoring data, which is stored
    in a TSDB like Graphite, will have to utilize a different plugin than a
    rule on logging data, stored in Elasticsearch, in order to successfully
    query the database.

    The Rule class is mainly divided into two categories:

    1. Arbitrary rules - defined entirely by the user. This type of rules gives
    users the freedom to execute arbitrary queries on arbitrary data. The query
    may include (nested) expressions and aggregations on arbitrary fields whose
    result will be evaluated against a threshold based on a comparison operator
    (=, <, etc).

    2. Resource rules - defined by using Mist.io UUIDs and tags. This type of
    rules can be used to easily setup alerts on resources given their tags or
    UUIDs. In this case, users have to explicitly specify the target metric's
    name, aggregation function, and resources either by their UUIDs or tags.
    This type of rules allows for easier alert configuration on known resources
    in the expense of less elastic query expressions.

    The Rule base class can be used to query the database and fetch documents
    created by any Rule subclass. However, in order to add new rules one must
    use one of the Rule subclasses, which represent different rule type, each
    associated with the corresponding backend plugin.

    """

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    # TODO This must be globally unique, since celerybeat-mongo uses schedule
    # names to prepare the dictionary of schedules to be run. As the keys of
    # this dictionary are the schedules' names, we could end up with schedules
    # being skipped. For now, this field will store the existing rule_id which
    # is incremented by 1 per new rule per organization.
    name = me.StringField()
    owner = me.ReferenceField('Organization', required=True,
                              reverse_delete_rule=me.CASCADE)

    # Specifies a list of queries to be evaluated. Results will be logically
    # ANDed together in order to decide whether an alert should be raised.
    queries = me.EmbeddedDocumentListField(QueryCondition, required=True)

    # Defines the time window and frequency of each search. TODO required.
    window = me.EmbeddedDocumentField(Window)
    frequency = me.EmbeddedDocumentField(Frequency)

    # Associates a reminder offset, which will cause an alert to be fired if
    # and only if the threshold is exceeded for a number of trigger_after
    # intervals.
    trigger_after = me.EmbeddedDocumentField(
        TriggerOffset, default=lambda: TriggerOffset(period='minutes')
    )

    # Defines a list of actions to be executed once the rule is triggered.
    # Defaults to just notifying the users.
    actions = me.EmbeddedDocumentListField(
        BaseAlertAction, default=lambda: [NotificationAction()]
    )

    # Denotes how to handle NoData alerts, whether to suppress them or to
    # translate them to a different state.
    no_data_alert = me.BooleanField(default=True)
    no_data_state = me.StringField(default='no_data', choices=('no_data',
                                                               'as_null',
                                                               'last_state'))

    # Disable the rule organization-wide.
    disabled = me.BooleanField(default=False)

    meta = {
        'strict': False,
        'collection': 'rules',
        'allow_inheritance': True,
        'indexes': [
            'name',
            'owner'
        ]
    }

    _controller_cls = None

    def __init__(self, *args, **kwargs):
        super(Rule, self).__init__(*args, **kwargs)
        if self._controller_cls is None:
            raise TypeError(
                "Cannot instantiate self. %s is a base class and cannot be "
                "used to insert or update alert rules and actions. Use a "
                "subclass of self that defines a `_controller_cls` class "
                "attribute derived from `mist.api.rules.base:BaseController`, "
                "instead." % self.__class__.__name__
            )
        if self.backend_plugin is None:
            raise NotImplementedError(
                "Cannot instantiate self. %s does not define a backend_plugin "
                "in order to evaluate rules against the corresponding backend "
                "storage." % self.__class__.__name__
            )
        self.ctl = self._controller_cls(self)

    @classmethod
    def add(cls, owner, name=None, **kwargs):
        """Add a new Rule.

        New rules should be added by invoking this class method on a Rule
        subclass.

        Arguments:

            owner:  instance of mist.api.users.models.Organization
            name:   the name of the rule. This must be universally unique
            kwargs: additional keyword arguments that will be passed to the
                    corresponding controller in order to setup the self

        """
        assert isinstance(owner, Organization)
        try:
            cls.objects.get(owner=owner, name=name)
        except cls.DoesNotExist:
            rule = cls(owner=owner, name=name)
        else:
            raise BadRequestError('Name "%s" is already in use' % name)
        rule.ctl.add(**kwargs)
        return rule

    @property
    def backend_plugin(self):
        """Return the instance of a backend plugin.

        Subclasses MUST define the plugin to be used, instantiated with `self`.

        """
        return None

    def get_action(self, action_id):
        """Return the action given its UUID.

        If the action does not exist, a me.DoesNotExist exception will be
        thrown. Exception handling should be taken care of by the caller.

        """
        return self.actions.get(id=action_id)

    def is_arbitrary(self):
        """Return True if self is arbitrary.

        Arbitrary rules lack a list of `conditions` that refer to resources
        either by their UUIDs or by tags. Such a list makes it easy to setup
        rules referencing specific resources without the need to provide the
        raw query expression.

        """
        return 'conditions' not in type(self)._fields

    def clean(self):
        # FIXME This is needed in order to ensure rule name convention remains
        # backwards compatible with the old monitoring stack. However, it will
        # have to change in the future due to uniqueness constrains.
        if not self.name:
            self.name = 'rule%d' % self.owner.rule_counter

        # FIXME Ensure a single query condition is specified for backwards
        # compatibility with the existing monitoring/alert stack.
        if not len(self.queries) is 1:
            raise me.ValidationError()

        # Push the NotificationAction, if specified, at the beggining of the
        # actions list. This way we make sure that users are always notified
        # even if subsequent actions fail. We also enforce a single instance
        # of the NotificationAction.
        for i, action in enumerate(self.actions):
            if isinstance(action, NotificationAction):
                self.actions.pop(i)
                self.actions.insert(0, action)
                break
        for action in self.actions[1:]:
            if isinstance(action, NotificationAction):
                raise me.ValidationError(
                    "Multiple notifications are not supported. Users "
                    "will always be notified at the beginning of the "
                    "actions' cycle.")

    def as_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'queries': [query.as_dict() for query in self.queries],
            'window': self.window.as_dict(),
            'frequency': self.frequency.as_dict(),
            'trigger_after': self.trigger_after.as_dict(),
            'no_data_alert': self.no_data_alert,
            'no_data_state': self.no_data_state,
            'actions': [action.as_dict() for action in self.actions],
            'disabled': self.disabled,
        }

    def __str__(self):
        return '%s %s of %s' % (self.__class__.__name__, self.name, self.owner)


class ArbitraryRule(Rule):
    """A rule defined by a single, arbitrary query string.

    Arbitrary rules permit the definition of complex query expressions by
    allowing  users to define fully qualified queries in "raw mode" as a
    single string. In such case, a query expression may be a composite query
    that includes nested aggregations and/or additional queries.

    An `ArbitraryRule` must define a single `QueryCondition`, whose `target`
    defines the entire query expression as a single string.

    """

    _controller_cls = ArbitraryRuleController


class ResourceRule(Rule, ConditionalClassMixin):
    """A rule bound to a specific resource type.

    Resource-bound rules are less elastic than arbitrary rules, but allow
    users to perform quick, more dynamic filtering given a resource object's
    UUID, tags, or model fields.

    Every subclass of `ResourceRule` MUST define its `condition_resource_cls`
    class attribute in order for queries to be executed against the intended
    mongodb collection.

    A `ResourceRule` may also apply to multiple resources, which depends on
    the rule's list of `conditions`. By default such a rule will trigger an
    alert if just one of its queries evaluates to True.

    """

    # chain_globals_by = me.StringField(default='or', choices=('or', 'and'))

    _controller_cls = ResourceRuleController

    def is_global(self):
        """Return True if self applies to multiple resources.

        This is always False for arbitrary rules, since at this point the
        exact list of resources to which an arbitrary rule applies cannot
        be extracted.

        """
        return self.get_resources().count() > 1

    # FIXME Needs https://gitlab.ops.mist.io/mistio/mist.io/merge_requests/466
    def owner_query(self):
        from mist.api.clouds.models import Cloud
        return me.Q(cloud__in=Cloud.objects(owner=self.owner))

    def as_dict(self):
        d = super(ResourceRule, self).as_dict()
        d['conditions'] = [cond.as_dict() for cond in self.conditions]
        return d

    # FIXME All following properties are for backwards compatibility.

    @property
    def rule_id(self):
        return self.name

    @property
    def metric(self):
        assert len(self.queries) is 1
        return self.queries[0].target

    @property
    def operator(self):
        assert len(self.queries) is 1
        return self.queries[0].operator

    @property
    def value(self):
        assert len(self.queries) is 1
        return self.queries[0].threshold

    @property
    def aggregate(self):
        assert len(self.queries) is 1
        return self.queries[0].aggregation

    @property
    def reminder_offset(self):
        return self.trigger_after.timedelta.total_seconds() / 60

    @property
    def machine(self):
        machines = self.get_resources()
        assert machines.count() is 1
        return machines.first().machine_id

    @property
    def cloud(self):
        machines = self.get_resources()
        assert machines.count() is 1
        return machines.first().cloud.id

    @property
    def action(self):
        for action in reversed(self.actions):
            if action.atype == 'command':
                return 'command'
            if action.atype == 'machine_action':
                return action.action
            if action.atype == 'notification':
                return 'alert'

    @property
    def emails(self):
        emails = []
        for action in self.actions:
            if action.atype == 'notification':
                emails = action.emails
        return emails

    @property
    def command(self):
        command = ''
        for action in self.actions:
            if action.atype == 'command':
                command = action.command
        return command

    def as_dict_old(self):
        return {
            '_id': {'$oid': self.id},
            'metric': self.metric,
            'value': self.value,
            'operator': self.operator,
            'aggregate': self.aggregate,
            'reminder_offset': self.reminder_offset,
            'emails': self.emails,
            'action': self.action,
            'command': self.command,
            'machine': self.machine,
            'cloud': self.cloud,
        }


class MachineMetricRule(ResourceRule):

    condition_resource_cls = Machine

    @property
    def backend_plugin(self):
        return 'graphite'
