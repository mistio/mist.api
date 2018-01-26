import logging
import mongoengine as me

from mist.api import config

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import UnauthorizedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.rules.models import Window
from mist.api.rules.models import Frequency
from mist.api.rules.models import TriggerOffset
from mist.api.rules.models import QueryCondition

from mist.api.rules.actions import ACTIONS
from mist.api.rules.actions import NoDataAction

from mist.api.rules.plugins import GraphiteNoDataPlugin
from mist.api.rules.plugins import GraphiteBackendPlugin
from mist.api.rules.plugins import InfluxDBNoDataPlugin
from mist.api.rules.plugins import InfluxDBBackendPlugin

from mist.api.conditions.models import FieldCondition
from mist.api.conditions.models import MachinesCondition

if config.HAS_CORE:
    from mist.core.rbac.methods import AuthContext
else:
    from mist.api.dummy.rbac import AuthContext


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
        self._auth_context = None

    @property
    def auth_context(self):
        """Return the current AuthContext."""
        assert isinstance(self._auth_context, AuthContext)
        return self._auth_context

    def set_auth_context(self, auth_context):
        """Set the context in which to perform permission checking."""
        self._auth_context = auth_context

    def check_auth_context(self):
        """Perform permission checking.

        This method verifies the permissions of the requesting user on a rule.
        By default rules are edittable only by Owners to account for rules on
        arbitrary data. Subclasses may extend/override this method to perform
        more fine-grained permission checking.

        """
        if not self.auth_context.is_owner():
            raise UnauthorizedError('Only Owners may edit arbitrary rules')

    def add(self, fail_on_error=True, **kwargs):
        """Add a new Rule.

        This method is meant to be invoked only by the `Rule.add` classmethod.

        """
        for field in ('queries', 'window', 'frequency', ):
            if field not in kwargs:
                raise RequiredParameterMissingError(field)
        try:
            self.update(fail_on_error=fail_on_error, **kwargs)
        except (me.ValidationError, BadRequestError) as err:
            log.error('Error adding %s: %s', self.rule.title, err)
            raise

    def update(self, save=True, fail_on_error=True, **kwargs):
        """Update an existing Rule.

        This method is invoked by `self.add` when adding a new Rule, but it
        can also be called directly, as such:

            rule = Rule.objects.get(owner=owner, title='rule15')
            rule.ctl.update(**kwargs)

        """
        # Update actions. The default is to just notify the user.
        if 'actions' in kwargs:
            self.rule.actions = []
        for action in kwargs.pop('actions', []):
            if action.get('type') not in ACTIONS:
                raise BadRequestError('Action type must be one of %s' %
                                      ' | '.join(ACTIONS.keys()))
            try:
                action_cls = ACTIONS[action.pop('type')]()
                action_cls.update(fail_on_error=fail_on_error, **action)
            except me.ValidationError as err:
                raise BadRequestError({'msg': err.message,
                                       'errors': err.to_dict()})
            self.rule.actions.append(action_cls)

        # Push the NotificationAction, if specified, at the beggining of the
        # actions list. This way we make sure that users are always notified
        # even if subsequent actions fail. We also enforce a single instance
        # of the NotificationAction.
        for i, action in enumerate(self.rule.actions):
            if isinstance(action, ACTIONS['notification']):
                self.rule.actions.pop(i)
                self.rule.actions.insert(0, action)
                break
        for action in self.rule.actions[1:]:
            if isinstance(action, ACTIONS['notification']):
                raise me.ValidationError(
                    "Multiple notifications are not supported. Users "
                    "will always be notified at the beginning of the "
                    "actions' cycle.")

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
            'frequency': Frequency,
            'trigger_after': TriggerOffset,
        }
        for field, params in kwargs.iteritems():
            if field not in doc_classes:
                log.error('%s found unsupported key "%s"',
                          self.__class__.__name__, field)
                if fail_on_error:
                    raise BadRequestError('Unsupported field "%s"' % field)
                continue
            try:
                doc_cls = doc_classes[field]()
                doc_cls.update(**params)
            except me.ValidationError as err:
                raise BadRequestError({'msg': err.message,
                                       'errors': err.to_dict()})
            setattr(self.rule, field, doc_cls)

        # Validate the rule against the plugin in use.
        try:
            self.rule._backend_plugin.validate(self.rule)
        except AssertionError as err:
            log.error('%s: %r', type(self.rule._backend_plugin), err)
            raise BadRequestError('Validation failed for %s' % self.rule)

        # Attempt to save self.rule.
        try:
            # FIXME This is temporary to ensure that the rule is not actually
            # updated, unless mist.alert responds OK.
            if save is False:
                self.rule.validate()
                return
            # /
            self.check_auth_context()
            self.rule.save()
        except me.ValidationError as err:
            log.error('Error updating %s: %s', self.rule.title, err)
            raise BadRequestError({'msg': err.message,
                                   'errors': err.to_dict()})
        except me.NotUniqueError as err:
            log.error('Error updating %s: %s', self.rule.title, err)
            raise BadRequestError('Rule "%s" already exists' % self.rule.title)

    def delete(self):
        """Delete an existing Rule.

        This method deletes a rule, after verifying the requesting user's
        permissions. Attempting to delete a rule by directly invoking the
        Rule model's delete method will bypass RBAC.

        """
        self.check_auth_context()
        # FIXME Remove alongside the old alert service.
        if config.HAS_CORE:
            from mist.core.methods import delete_rule
            delete_rule(self.rule.owner, self.rule.title)
        else:
            from mist.api.helpers import trigger_session_update
            self.rule.delete()
            trigger_session_update(self.rule.owner, ['monitoring'])

    def evaluate(self, update_state=False, trigger_actions=False):
        """Evaluate a Rule.

        This method exposes the corresponding plugin's functionality by running
        a full evaluation cycle of `self.rule` and it is meant to be invoked as
        such:

            rule = mist.api.rules.models.Rule.objects.get(id=1)
            rule.ctl.evaluate()

        This method is just a wrapper around the corresponding plugin's `run`
        method.

        """
        self.rule.plugin.run(update_state, trigger_actions)


class ArbitraryRuleController(BaseController):

    def update(self, save=True, fail_on_error=True, **kwargs):
        if 'conditions' in kwargs:
            raise BadRequestError('Conditions may not be specified for '
                                  'arbitrary rules. Filtering is meant '
                                  'to be included as part of the query.')
        super(ArbitraryRuleController, self).update(
            save=save, fail_on_error=fail_on_error, **kwargs)


class ResourceRuleController(BaseController):

    @property
    def plugins(self):
        return {'graphite': GraphiteBackendPlugin,
                'influxdb': InfluxDBBackendPlugin}

    def update(self, save=True, fail_on_error=True, **kwargs):
        if 'conditions' in kwargs:
            self.rule.conditions = []
        for condition in kwargs.pop('conditions', []):
            if condition.get('type') not in CONDITIONS:
                raise BadRequestError('Condition type must be one of %s' %
                                      ' | '.join(CONDITIONS.keys()))
            cond_cls = CONDITIONS[condition.pop('type')]()
            cond_cls.update(**condition)
            self.rule.conditions.append(cond_cls)
        super(ResourceRuleController, self).update(
            save=save, fail_on_error=fail_on_error, **kwargs)

    def evaluate(self, update_state=False, trigger_actions=False):
        if config.CILIA_MULTI:
            graphite_ids, influxdb_ids = [], []
            for machine in self.rule.get_resources():
                if machine.monitoring.method.endswith('graphite'):
                    graphite_ids.append(machine.id)
                elif machine.monitoring.method.endswith('influxdb'):
                    influxdb_ids.append(machine.id)
            if graphite_ids:
                plugin = self.plugins['graphite'](self.rule, graphite_ids)
                plugin.run(update_state, trigger_actions)
            if influxdb_ids:
                plugin = self.plugins['influxdb'](self.rule, influxdb_ids)
                plugin.run(update_state, trigger_actions)
        else:
            super(ResourceRuleController, self).evaluate(update_state,
                                                         trigger_actions)

    def check_auth_context(self):
        if not self.rule.conditions and not self.auth_context.is_owner():
            raise UnauthorizedError('Only Owners may edit global rules')
        for condition in self.rule.conditions:
            # TODO Check if condition on ids or tags.
            # TODO Permissions checking shouldn't be limited to machines.
            for mid in condition.ids:
                try:
                    Model = self.rule.condition_resource_cls
                    m = Model.objects.get(id=mid, owner=self.rule.owner_id)
                except Model.DoesNotExist:
                    raise NotFoundError(mid)
                self.auth_context.check_perm('cloud', 'read', m.cloud.id)
                self.auth_context.check_perm('machine', 'edit_rules', m.id)


class NoDataRuleController(ResourceRuleController):

    @property
    def plugins(self):
        return {'graphite': GraphiteNoDataPlugin,
                'influxdb': InfluxDBNoDataPlugin}

    def update(self, save=True, fail_on_error=True, **kwargs):
        raise BadRequestError('NoData rules may not be editted')

    def delete(self):
        raise BadRequestError('NoData rules may not be deleted')

    def auto_setup(self, backend='graphite'):
        """Idempotently setup a NoDataRule."""
        assert backend in ('graphite', 'influxdb')
        assert backend != 'graphite' or config.HAS_CORE

        # The rule's title. There should be a single NoDataRule per Org.
        title = 'NoData'
        if config.HAS_CORE and config.CILIA_MULTI and backend == 'influxdb':
            title = backend.capitalize() + title
        self.rule.title = title

        # The list of query conditions to evaluate. If at least one of
        # the following metrics returns non-None datapoints, the rule
        # will not be triggered.
        self.rule.queries = []
        if backend == 'graphite':
            targets = config.CILIA_GRAPHITE_NODATA_TARGETS
        if backend == 'influxdb':
            targets = config.CILIA_INFLUXDB_NODATA_TARGETS
        for target in targets:
            cond = QueryCondition(target=target, operator='gt',
                                  threshold=0, aggregation='any')
            self.rule.queries.append(cond)

        # The rule's time window and frequency. These denote the maximum
        # time window for which we tolerate the absence of points before
        # raising an alert.
        self.rule.window = Window(start=2, period='minutes')
        self.rule.frequency = Frequency(every=2, period='minutes')

        # The rule's single action.
        self.rule.actions = [NoDataAction()]

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
        # In case of a multi-monitoring setup with both Graphite and InfluxDB,
        # no-data checks are split into two discrete rules, each corresponding
        # to a monitoring method, as defined by `machine.monitoring.method`.
        if config.HAS_CORE and config.CILIA_MULTI:
            if backend == 'graphite':
                self.rule.conditions.append(
                    FieldCondition(
                        field='monitoring__method',
                        operator='ne', value='telegraf-influxdb'
                    )
                )
            if backend == 'influxdb':
                self.rule.conditions.append(
                    FieldCondition(
                        field='monitoring__method',
                        operator='eq', value='telegraf-influxdb'
                    )
                )

        self.rule.save()
