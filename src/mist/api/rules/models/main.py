import uuid
import datetime
import mongoengine as me

from mist.api import config

from mist.api.exceptions import BadRequestError

from mist.api.users.models import Organization
from mist.api.selectors.models import SelectorClassMixin
from mist.api.actions.models import ActionClassMixin
from mist.api.actions.models import BaseAction
from mist.api.actions.models import NotificationAction
from mist.api.when.models import Interval
from mist.api.when.models import TriggerOffset

from mist.api.rules.base import NoDataRuleController
from mist.api.rules.base import ResourceRuleController
from mist.api.rules.base import ArbitraryRuleController
from mist.api.rules.models import RuleState
from mist.api.rules.models import Window
from mist.api.rules.models import Frequency
from mist.api.rules.models import QueryCondition

from mist.api.rules.plugins import GraphiteNoDataPlugin
from mist.api.rules.plugins import GraphiteBackendPlugin
from mist.api.rules.plugins import InfluxDBNoDataPlugin
from mist.api.rules.plugins import InfluxDBBackendPlugin
from mist.api.rules.plugins import ElasticSearchBackendPlugin
from mist.api.rules.plugins import FoundationDBNoDataPlugin
from mist.api.rules.plugins import FoundationDBBackendPlugin
from mist.api.rules.plugins import VictoriaMetricsNoDataPlugin
from mist.api.rules.plugins import VictoriaMetricsBackendPlugin


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
    name = me.StringField(required=True)
    description = me.StringField(required=False)
    org_id = me.StringField(required=True)
    # Deprecated
    title = me.StringField(required=False)
    owner_id = me.StringField(required=False)
    # Specifies a list of queries to be evaluated. Results will be logically
    # ANDed together in order to decide whether an alert should be raised.
    queries = me.EmbeddedDocumentListField(QueryCondition, required=True)

    # Defines the time window and frequency of each search.
    window = me.EmbeddedDocumentField(Window, required=True)

    # Defines the frequency of each search.
    when = me.EmbeddedDocumentField(
        Interval, required=False, default=lambda: Interval(period='minutes')
    )

    # Deprecated
    frequency = me.EmbeddedDocumentField(Frequency, required=False)

    # Associates a reminder offset, which will cause an alert to be fired if
    # and only if the threshold is exceeded for a number of trigger_after
    # intervals.
    trigger_after = me.EmbeddedDocumentField(
        TriggerOffset, default=lambda: TriggerOffset(period='minutes')
    )

    # Defines a list of actions to be executed once the rule is triggered.
    # Defaults to just notifying the users.
    actions = me.EmbeddedDocumentListField(
        BaseAction, required=True, default=lambda: [NotificationAction()]
    )

    # Disable the rule organization-wide.
    disabled = me.BooleanField(default=False)

    # Fields passed to scheduler as optional arguments.
    queue = me.StringField()
    exchange = me.StringField()
    routing_key = me.StringField()

    # Fields updated by the scheduler.
    last_run_at = me.DateTimeField()
    run_immediately = me.BooleanField()
    total_run_count = me.IntField(min_value=0, default=0)
    total_check_count = me.IntField(min_value=0, default=0)

    # Field updated by dramatiq workers. This is where workers keep state.
    states = me.MapField(field=me.EmbeddedDocumentField(RuleState))
    created = me.DateTimeField(default=datetime.datetime.now)
    deleted = me.DateTimeField()

    meta = {
        'strict': False,
        'collection': 'rules',
        'allow_inheritance': True,
        'indexes': [
            'org_id',
            {
                'fields': ['org_id', 'name'],
                'sparse': False,
                'unique': True,
                'cls': False,
            }
        ]
    }

    _controller_cls = None
    _backend_plugin = None
    _data_type_str = None

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
        if self._backend_plugin is None:
            raise NotImplementedError(
                "Cannot instantiate self. %s does not define a backend_plugin "
                "in order to evaluate rules against the corresponding backend "
                "storage." % self.__class__.__name__
            )
        if self._data_type_str not in ('metrics', 'logs', ):
            raise TypeError(
                "Cannot instantiate self. %s is a base class and cannot be "
                "used to insert or update rules. Use a subclass of self that "
                "defines a `_backend_plugin` class attribute, as well as the "
                "requested data's type via the `_data_type_str` attribute, "
                "instead." % self.__class__.__name__
            )
        self.ctl = self._controller_cls(self)

    @classmethod
    def add(cls, auth_context, name=None, **kwargs):
        """Add a new Rule.

        New rules should be added by invoking this class method on a Rule
        subclass.

        Arguments:

            org_id:  instance of mist.api.users.models.Organization
            name:  the name of the rule. This must be unique per Organization
            kwargs: additional keyword arguments that will be passed to the
                    corresponding controller in order to setup the self

        """
        try:
            cls.objects.get(org_id=auth_context.owner.id, name=name)
        except cls.DoesNotExist:
            rule = cls(org_id=auth_context.owner.id, name=name)
            rule.ctl.set_auth_context(auth_context)
            rule.ctl.add(**kwargs)
        else:
            raise BadRequestError('name "%s" is already in use' % name)
        return rule

    @property
    def org(self):
        """Return the Organization (instance) owning self.

        We refrain from storing the org as a me.ReferenceField in order to
        avoid automatic/unwanted dereferencing.

        """
        return Organization.objects.get(id=self.org_id)

    @property
    def plugin(self):
        """Return the instance of a backend plugin.

        Subclasses MUST define the plugin to be used, instantiated with `self`.

        """
        return self._backend_plugin(self)

    # NOTE The following properties are required by the scheduler.

    @property
    def full_name(self):
        """Return the name of the task.

        """
        return f'Org({self.org.name}):Rule({self.name})'

    @property
    def task(self):
        """Return the dramatiq task to run.

        This is the most basic dramatiq task that should be used for most rule
        evaluations. However, subclasses may provide their own property or
        class attribute based on their needs.

        """
        return 'mist.api.rules.tasks.evaluate'

    @property
    def args(self):
        """Return the args of the dramatiq task."""
        return (self.id, )

    @property
    def kwargs(self):
        """Return the kwargs of the dramatiq task."""
        return {}

    @property
    def expires(self):
        """Return None to denote that self is not meant to expire."""
        return None

    @property
    def enabled(self):
        """Return True if the dramatiq task is currently enabled.

        Subclasses MAY override or extend this property.

        """
        return not self.disabled

    def is_arbitrary(self):
        """Return True if self is arbitrary.

        Arbitrary rules lack a list of `selectors` that refer to resources
        either by their UUIDs or by tags. Such a list makes it easy to setup
        rules referencing specific resources without the need to provide the
        raw query expression.

        """
        return 'selectors' not in type(self)._fields

    def clean(self):
        # FIXME This is needed in order to ensure rule name convention remains
        # backwards compatible with the old monitoring stack. However, it will
        # have to change in the future due to uniqueness constrains.
        if not self.name:
            self.name = 'rule%d' % self.org.rule_counter

    def as_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'queries': [query.as_dict() for query in self.queries],
            'window': self.window.as_dict(),
            'frequency': self.when.as_dict(),
            'trigger_after': self.trigger_after.as_dict(),
            'actions': [action.as_dict() for action in self.actions],
            'disabled': self.disabled,
            'data_type': self._data_type_str,
        }

    def __str__(self):
        return '%s %s of %s' % (self.__class__.__name__,
                                self.name, self.org)


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


class ResourceRule(Rule, SelectorClassMixin, ActionClassMixin):
    """A rule bound to a specific resource type.

    Resource-bound rules are less elastic than arbitrary rules, but allow
    users to perform quick, more dynamic filtering given a resource object's
    UUID, tags, or model fields.

    Every subclass of `ResourceRule` MUST define its `selector_resource_cls`
    class attribute in order for queries to be executed against the intended
    mongodb collection.

    A `ResourceRule` may also apply to multiple resources, which depends on
    the rule's list of `selectors`. By default such a rule will trigger an
    alert if just one of its queries evaluates to True.

    """

    _controller_cls = ResourceRuleController

    @property
    def enabled(self):
        return (super(ResourceRule, self).enabled and
                bool(self.get_resources().count()))

    def clean(self):
        # Enforce singular resource types for uniformity.
        if self.resource_model_name.endswith('s'):
            self.resource_model_name = self.resource_model_name[:-1]
        super(ResourceRule, self).clean()

    def as_dict(self):
        d = super(ResourceRule, self).as_dict()
        d['selectors'] = [cond.as_dict() for cond in self.selectors]
        d['resource_type'] = self.resource_model_name
        return d

    # FIXME All following properties are for backwards compatibility.

    @property
    def metric(self):
        assert len(self.queries) == 1
        return self.queries[0].target

    @property
    def operator(self):
        assert len(self.queries) == 1
        return self.queries[0].operator

    @property
    def value(self):
        assert len(self.queries) == 1
        return self.queries[0].threshold

    @property
    def aggregate(self):
        assert len(self.queries) == 1
        return self.queries[0].aggregation

    @property
    def reminder_offset(self):
        return self.when.timedelta.total_seconds() - 60

    @property
    def action(self):
        for action in reversed(self.actions):
            if action.atype == 'command':
                return 'command'
            if action.atype == 'script':
                return 'script'
            if action.atype == f'{self.resource_model_name}_action':
                return action.action
            if action.atype == 'notification':
                return 'alert'


class MachineMetricRule(ResourceRule):

    _data_type_str = 'metrics'

    @property
    def _backend_plugin(self):
        if config.DEFAULT_MONITORING_METHOD.endswith('-graphite'):
            return GraphiteBackendPlugin
        if config.DEFAULT_MONITORING_METHOD.endswith('-influxdb'):
            return InfluxDBBackendPlugin
        if config.DEFAULT_MONITORING_METHOD.endswith('-tsfdb'):
            return FoundationDBBackendPlugin
        if config.DEFAULT_MONITORING_METHOD.endswith('-victoriametrics'):
            return VictoriaMetricsBackendPlugin
        raise Exception()

    def clean(self):
        super(MachineMetricRule, self).clean()
        if self.resource_model_name != 'machine':
            raise me.ValidationError(
                'Invalid resource type "%s". %s can only operate on machines' %
                (self.resource_model_name, self.__class__.__name__))


class NoDataRule(MachineMetricRule):

    _controller_cls = NoDataRuleController

    @property
    def _backend_plugin(self):
        if config.DEFAULT_MONITORING_METHOD.endswith('-graphite'):
            return GraphiteNoDataPlugin
        if config.DEFAULT_MONITORING_METHOD.endswith('-influxdb'):
            return InfluxDBNoDataPlugin
        if config.DEFAULT_MONITORING_METHOD.endswith('-tsfdb'):
            return FoundationDBNoDataPlugin
        if config.DEFAULT_MONITORING_METHOD.endswith('-victoriametrics'):
            return VictoriaMetricsNoDataPlugin
        raise Exception()

    # FIXME All following properties are for backwards compatibility.
    # However, this rule is not meant to match any queries, but to be
    # used internally, thus the `None`s.

    @property
    def metric(self):
        return None

    @property
    def operator(self):
        return None

    @property
    def value(self):
        return None

    @property
    def aggregate(self):
        return None

    @property
    def reminder_offset(self):
        return None

    @property
    def action(self):
        return ''


class ResourceLogsRule(ResourceRule):

    _data_type_str = 'logs'
    _backend_plugin = ElasticSearchBackendPlugin


class ArbitraryLogsRule(ArbitraryRule):

    _data_type_str = 'logs'
    _backend_plugin = ElasticSearchBackendPlugin


def _populate_rules():
    """Populate RULES with mappings from rule type to rule subclass.

    RULES is a mapping (dict) from rule types to subclasses of Rule.
    A rule's type is the concat of two strings: <str1>-<str2>, where
    str1 denotes whether the rule is arbitrary or not and str2 equals
    the `_data_type_str` class attribute of the rule, which is simply
    the type of the requesting data, like logs or monitoring metrics.

    The aforementioned concatenation is simply a way to categorize a
    rule, such as saying a rule on arbitrary logs or a resource-bound
    rule referring to the monitoring data of machine A.

    """
    public_rule_map = {}
    hidden_rule_cls = (ArbitraryRule, ResourceRule, NoDataRule, )
    for key, value in list(globals().items()):
        if not key.endswith('Rule'):
            continue
        if value in hidden_rule_cls:
            continue
        if not issubclass(value, (ArbitraryRule, ResourceRule, )):
            continue
        str1 = 'resource' if issubclass(value, ResourceRule) else 'arbitrary'
        rule_key = '%s-%s' % (str1, value._data_type_str)
        public_rule_map[rule_key] = value
    return public_rule_map


RULES = _populate_rules()
