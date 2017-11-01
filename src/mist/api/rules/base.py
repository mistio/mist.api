import logging
import mongoengine as me

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.rules.models import Window
from mist.api.rules.models import Frequency
from mist.api.rules.models import TriggerOffset
from mist.api.rules.models import QueryCondition

from mist.api.rules.actions import ACTIONS

from mist.api.conditions.models import FieldCondition
from mist.api.conditions.models import MachinesCondition


log = logging.getLogger(__name__)


CONDITIONS = {
    # 'tags': TaggingCondition,
    # 'field': FieldCondition,
    'machines': MachinesCondition,
}


class BaseController(object):
    """The base controller class for every rule type.

    The `BaseController` defines a common interface shared amongst all rule
    types. It can be used to perform operations, such as adding or updating
    rules.

    All subclasses of `mist.api.rules.models.Rule` must define the appropriate
    controller subclass. Subclasses of the `BaseController` are mainly used in
    order to perform early validation and field sanitization.

    New actions on rules SHOULD be implemented as part of this base controller
    to ensure that all controller subclasses inherit the same common interface
    as much as possible.

    """

    def __init__(self, rule):
        """Initialize the controller given a Rule instance."""
        self.rule = rule

    @property
    def plugin(self):
        return self.rule.backend_plugin

    def add(self, fail_on_error=True, **kwargs):
        """Add a new Rule.

        This method is meant to be invoked only by the `Rule.add` classmethod.

        """
        for field in ('queries', ):  # TODO 'window', 'interval', ):
            if field not in kwargs:
                raise RequiredParameterMissingError(field)
        try:
            self.update(fail_on_error=fail_on_error, **kwargs)
        except (me.ValidationError, BadRequestError) as err:
            log.error('Error adding %s: %s', self.rule.name, err)
            raise

    def update(self, save=True, fail_on_error=True, **kwargs):
        """Update an existing Rule.

        This method is invoked by `self.add` when adding a new Rule, but it
        can also be called directly, as such:

            rule = Rule.objects.get(owner=owner, name='rule15')
            rule.ctl.update(**kwargs)

        """
        # Update actions. The default is to just notify the user.
        if 'actions' in kwargs:
            self.rule.actions = []
        for action in kwargs.pop('actions', []):
            if action.get('type') not in ACTIONS:
                raise BadRequestError('Action type must be one of %s' %
                                      ' | '.join(ACTIONS.keys()))
            action_cls = ACTIONS[action.pop('type')]()
            try:
                action_cls.update(fail_on_error=fail_on_error, **action)
            except me.ValidationError as err:
                raise BadRequestError({'msg': err.message,
                                       'errors': err.to_dict()})
            self.rule.actions.append(action_cls)

        # Update query condition.
        if 'queries' in kwargs:
            self.rule.queries = []
        for query in kwargs.pop('queries', []):
            for field in query:
                if field not in QueryCondition._fields:
                    log.error('%s found unsupported key "%s"',
                              self.__class__.__name__, field)
                    if fail_on_error:
                        raise BadRequestError('Unsupported field "%s"' % field)
                    continue
            cond = QueryCondition(**query)
            self.rule.queries.append(cond)

        # Update time parameters.
        doc_classes = {
            'window': Window,
            'interval': Frequency,
            'trigger_after': TriggerOffset,
        }
        for field, params in kwargs.iteritems():
            if field not in doc_classes:
                log.error('%s found unsupported key "%s"',
                          self.__class__.__name__, field)
                if fail_on_error:
                    raise BadRequestError('Unsupported field "%s"' % field)
                continue
            doc_cls = doc_classes[field]()
            try:
                doc_cls.update(**params)
            except me.ValidationError as err:
                raise BadRequestError({'msg': err.message,
                                       'errors': err.to_dict()})
            setattr(self.rule, field, doc_cls)

        # Attempt to save self.rule.
        try:
            # FIXME This is temporary to ensure that the rule is not actually
            # updated, unless mist.alert responds OK.
            if save is False:
                self.rule.validate()
                return
            # /
            self.rule.save()
        except me.ValidationError as err:
            log.error('Error updating %s: %s', self.rule.name, err)
            raise BadRequestError({'msg': err.message,
                                   'errors': err.to_dict()})
        except me.NotUniqueError as err:
            log.error('Error updating %s: %s', self.rule.name, err)
            raise BadRequestError('Rule "%s" already exists' % self.rule.name)

    def evaluate(self, update_state=False, trigger=False):
        """Evaluate a Rule.

        This method exposes the corresponding plugin's functionality by running
        a full evaluation cycle of `self.rule` and it is meant to be invoked as
        such:

            rule = mist.api.rules.models.Rule.objects.get(id=1)
            rule.ctl.evaluate()

        This method is just a wrapper around the corresponding plugin's `run`
        method.

        """
        self.plugin.run(update_state=update_state, run_actions=trigger)
        #self.rule.backend_plugin.run(update=update, trigger=trigger)


class ArbitraryRuleController(BaseController):

    def update(self, save=True, fail_on_error=True, **kwargs):
        if 'conditions' in kwargs:
            raise BadRequestError('Conditions may not be specified for '
                                  'arbitrary rules. Filtering is meant '
                                  'to be included as part of the query.')
        super(ArbitraryRuleController, self).update(
            save=save, fail_on_error=fail_on_error, **kwargs)


class ResourceRuleController(BaseController):

    def update(self, save=True, fail_on_error=True, **kwargs):
        if kwargs.get('conditions'):
            self.rule.conditions = []
            for condition in kwargs.pop('conditions'):
                if condition.get('type') not in CONDITIONS:
                    raise BadRequestError('Condition type must be one of %s' %
                                          ' | '.join(CONDITIONS.keys()))
                cond_cls = CONDITIONS[condition.pop('type')]()
                cond_cls.update(**condition)
                self.rule.conditions.append(cond_cls)
        super(ResourceRuleController, self).update(
            save=save, fail_on_error=fail_on_error, **kwargs)


class NoDataRuleController(BaseController):

    def update(self, save=True, fail_on_error=True, **kwargs):
        raise BadRequestError('NoData rules may not be edited')

    def auto_setup(self):
        """Idempotently setup a NoDataRule."""
        from ipdb import set_trace; set_trace()
        # The rule's title. There should be a single NoDataRule per Org.
        self.rule.title = 'NoData'

        # The list of query conditions to evaluate. If at least one of
        # the following metrics returns non-None datapoints, the rule
        # will not be triggered.
        self.rule.queries = []
        for target in ('load.shortterm', 'load.midterm', 'cpu.0.idle', ):
            cond = QueryCondition(target=target, operator='gt',
                                  threshold=0, aggregation='any')
            self.rule.queries.append(cond)

        # The rule's time window and frequency. These denote the maximum
        # time window for which we tolerate the absence of points before
        # raising an alert.
        self.rule.window.start = 2
        self.rule.frequency.every = 2

        # The rule's single action.
        #self.rule.action = [NoDataAction]

        # The rule's resource conditions. This pair of conditions makes
        # the NoDataRule to be evaluated only for machines with enabled
        # monitoring, for which we have received monitoring data.
        self.rule.conditions = [
            FieldCondition(
                field='monitoring__hasmonitoring',
                operator='eq', value=True
            ),
            FieldCondition(
                field='monitoring__installation_status__activated_at',
                operator='gt', value=0
            )
        ]

        self.rule.save()
