import logging
import mongoengine as me

from mist.api import config

from mist.api.helpers import trigger_session_update
from mist.api.methods import _update__preparse_resources

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import UnauthorizedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.rules.models import Window
from mist.api.rules.models import QueryCondition

from mist.api.actions.models import ACTIONS
from mist.api.actions.models import NoDataAction

from mist.api.when.models import Interval
from mist.api.when.models import TriggerOffset

from mist.api.selectors.models import FieldSelector
from mist.api.selectors.models import TaggingSelector # noqa
from mist.api.selectors.models import ResourceSelector

if config.HAS_RBAC:
    from mist.rbac.methods import AuthContext
else:
    from mist.api.dummy.rbac import AuthContext


log = logging.getLogger(__name__)


TIMEPERIOD = {
    'window': Window,
    'when': Interval,
    'trigger_after': TriggerOffset,
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
        for field in ('queries', 'window', 'when', ):
            if field not in kwargs:
                raise RequiredParameterMissingError(field)
        try:
            self.update(fail_on_error=fail_on_error,
                        called_from_add=True, **kwargs)
        except (me.ValidationError, BadRequestError) as err:
            log.error('Error adding %s: %s', self.rule.name, err)
            raise

    def update(self, fail_on_error=True, called_from_add=False, **kwargs):
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
            if 'action_type' in action:
                if action.get('action_type', '') not in ['webhook',
                                                         'notification',
                                                         'notify',
                                                         'run_script',
                                                         'resize']:
                    action['action'] = action.pop('action_type', '')
                    action['type'] = f'{self.rule.resource_model_name}_action'
                elif action.get('action_type', '') == 'notify':
                    action['type'] = 'notification'
                    action.pop('action_type')
                else:
                    action['type'] = action.pop('action_type', '')
            if action.get('type') not in ACTIONS:
                raise BadRequestError('Action must be in %s' %
                                      list(ACTIONS.keys()))
            try:
                action_cls = ACTIONS[action.pop('type')]()
                action_cls.update(fail_on_error=fail_on_error, **action)
            except me.ValidationError as err:
                raise BadRequestError({'msg': str(err),
                                       'errors': err.to_dict()})
            self.rule.actions.append(action_cls)

        # Push the NotificationAction, if specified, at the beginning of the
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

        if 'description' in kwargs:
            self.rule.description = kwargs.pop('description')

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
        for field, params in kwargs.items():
            if field not in TIMEPERIOD:
                log.error('%s found unsupported key "%s"',
                          self.__class__.__name__, field)
                if fail_on_error:
                    raise BadRequestError('Unsupported field "%s"' % field)
                continue
            try:
                doc_cls = TIMEPERIOD[field]()
                doc_cls.update(**params)
            except me.ValidationError as err:
                raise BadRequestError({'msg': str(err),
                                       'errors': err.to_dict()})
            setattr(self.rule, field, doc_cls)

        if called_from_add:
            try:
                self.check_auth_context()
                self.rule.save()
            except me.ValidationError as err:
                log.error('Error updating %s: %s', self.rule.name, err)
                raise BadRequestError({'msg': str(err),
                                       'errors': err.to_dict()})
            except me.NotUniqueError as err:
                log.error('Error updating %s: %s', self.rule.name, err)
                raise BadRequestError(
                    'Rule "%s" already exists' % self.rule.name)

        # Validate the rule against the plugin in use.
        try:
            self.rule._backend_plugin.validate(self.rule)
        except AssertionError as err:
            log.error('%s: %r', type(self.rule._backend_plugin), err)
            if called_from_add:
                self.rule.delete()
            raise BadRequestError('%s is invalid: %s' % (self.rule, err))

        # Attempt to save self.rule.
        try:
            self.check_auth_context()
            self.rule.save()
        except me.ValidationError as err:
            log.error('Error updating %s: %s', self.rule.name, err)
            if called_from_add:
                self.rule.delete()
            raise BadRequestError({'msg': str(err),
                                   'errors': err.to_dict()})
        except me.NotUniqueError as err:
            log.error('Error updating %s: %s', self.rule.name, err)
            raise BadRequestError('Rule "%s" already exists' % self.rule.name)

        # Trigger a UI session update.
        trigger_session_update(self.rule.org, ['monitoring'])

    def rename(self, name):
        """Rename an existing Rule."""
        self.rule.name = name
        self.rule.save()
        trigger_session_update(self.rule.org, ['monitoring'])

    def enable(self):
        """Enable a Rule that has been previously disabled."""
        self.rule.disabled = False
        self.rule.save()
        trigger_session_update(self.rule.org, ['monitoring'])

    def disable(self):
        """Disable a Rule's evaluation."""
        self.rule.disabled = True
        self.rule.save()
        trigger_session_update(self.rule.org, ['monitoring'])

    def delete(self):
        """Delete an existing Rule.

        This method deletes a rule, after verifying the requesting user's
        permissions. Attempting to delete a rule by directly invoking the
        Rule model's delete method will bypass RBAC.

        """
        self.check_auth_context()
        self.rule.delete()
        trigger_session_update(self.rule.org, ['monitoring'])

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

    def maybe_remove(self, resource):
        """Disassociate a `resource` from a Rule.

        Resources, which rules explicitly refer to by ID, can be removed from
        the reference list. This is not always possible, since rules may also
        refer to arbitrary data or a dynamically, constantly changing list of
        resources.

        Subclasses of `BaseController`, such as the `ResourceRuleController`,
        that may explicitly refer resources given their UUID, may overwrite
        this method in order to make a best effort to disassociate a given
        resource from the list of referenced resources.

        By default, this method does not make any attempt to disassociate the
        given resource in order to account for rules on arbitrary data, which
        are not bound to a known resource.

        """
        return

    def includes_only(self, resource):
        """Return True if a Rule includes solely the given resource.

        This method is meant to return True if and only if `resource` is the
        only resource a rule refers to. The rule must refer to the resource
        explicitly using its UUID.

        """
        return False


class ArbitraryRuleController(BaseController):

    def update(self, fail_on_error=True, **kwargs):
        if 'selectors' in kwargs:
            raise BadRequestError('Selectors may not be specified for '
                                  'arbitrary rules. Filtering is meant '
                                  'to be included as part of the query.')
        super(ArbitraryRuleController, self).update(fail_on_error, **kwargs)


class ResourceRuleController(BaseController):

    def add(self, fail_on_error=True, **kwargs):
        self.rule.resource_model_name = kwargs.pop('resource_type', None)
        super(ResourceRuleController, self).add(fail_on_error, **kwargs)

    def update(self, fail_on_error=True, **kwargs):
        sel_acts_kwargs = kwargs.copy()
        for key in kwargs.keys():
            if key not in ('selectors', 'actions'):
                sel_acts_kwargs.pop(key)

        kwargs.pop('selectors')
        if 'selectors' in sel_acts_kwargs and 'actions' in sel_acts_kwargs:
            _update__preparse_resources(self.rule, self.auth_context,
                                        sel_acts_kwargs)
        super(ResourceRuleController, self).update(fail_on_error, **kwargs)

    def maybe_remove(self, resource):
        # The rule does not refer to resources of the given type.
        if not isinstance(resource, self.rule.selector_resource_cls):
            return

        # Attempt to remove `resource` from any of the rule's selectors,
        # if `resource` is explicitly specified by its UUID.
        for selector in self.rule.selectors:
            if isinstance(selector, ResourceSelector):
                for i, rid in enumerate(selector.ids):
                    if rid == resource.id:
                        log.info('Removing %s from %s', resource, self.rule)
                        selector.ids.pop(i)
                        break

        self.rule.save()

    def includes_only(self, resource):
        # The rule does not refer to resources of the given type.
        if not isinstance(resource, self.rule.selector_resource_cls):
            return False

        # The rule contains multiple selectors.
        if len(self.rule.selectors) != 1:
            return False

        # The rule does not refer to resources by their UUID.
        if not isinstance(self.rule.selectors[0], ResourceSelector):
            return False

        # The rule refers to multiple resources.
        if len(self.rule.selectors[0].ids) != 1:
            return False

        # The rule's single resource does not match `resource`.
        if self.rule.selectors[0].ids[0] != resource.id:
            return False

        # The rule refers to just `resource` by its UUID.
        return True

    def check_auth_context(self):
        if self.auth_context.is_owner():
            return
        if not self.rule.selectors:
            raise UnauthorizedError('Only Owners may edit global rules')
        for selector in self.rule.selectors:
            if not isinstance(selector, ResourceSelector):
                raise UnauthorizedError('Only Owners may edit rules on tags')
            for mid in selector.ids:
                try:
                    Model = self.rule.selector_resource_cls
                    m = Model.objects.get(id=mid, owner=self.rule.org)
                except Model.DoesNotExist:
                    raise NotFoundError('%s %s' % (Model, mid))
                read_perm = (
                    'read' if self.rule._data_type_str == 'metrics' else
                    'read_logs'  # For rules on logs.
                )
                for perm in (read_perm, 'edit_rules'):
                    self.auth_context.check_perm(self.resource_model_name,
                                                 perm, m.id)


class NoDataRuleController(ResourceRuleController):

    def update(self, fail_on_error=True, **kwargs):
        if not all(key in TIMEPERIOD for key in kwargs):
            log.error('%s got kwargs=%s', self.__class__.__name__, kwargs)
            if fail_on_error:
                raise BadRequestError('May only edit %s' %
                                      list(TIMEPERIOD.keys()))
        super(NoDataRuleController, self).update(fail_on_error, **kwargs)

    def delete(self):
        raise BadRequestError('NoData rules may not be deleted')

    def rename(self, name):
        raise BadRequestError('NoData rules may not be renamed')

    def auto_setup(self, backend='graphite'):
        """Idempotently setup a NoDataRule."""
        assert backend in ('graphite', 'influxdb', 'tsfdb', 'victoriametrics')

        # The rule's name. There should be a single NoDataRule per Org.
        self.rule.name = 'NoData'

        # The list of query conditions to evaluate. If at least one of
        # the following metrics returns non-None datapoints, the rule
        # will not be triggered.
        self.rule.queries = []
        if backend == 'graphite':
            targets = config.CILIA_GRAPHITE_NODATA_TARGETS
        if backend == 'influxdb':
            targets = config.CILIA_INFLUXDB_NODATA_TARGETS
        if backend == 'tsfdb':
            targets = config.CILIA_FOUNDATIONDB_NODATA_TARGETS
        if backend == 'victoriametrics':
            targets = config.CILIA_VICTORIAMETRICS_NODATA_TARGETS
        for target in targets:
            cond = QueryCondition(target=target, operator='gt',
                                  threshold=0, aggregation='any')
            self.rule.queries.append(cond)

        # The rule's time window and frequency. These denote the maximum
        # time window for which we tolerate the absence of points before
        # raising an alert.
        if not self.rule.window:
            self.rule.window = Window(start=2, period='minutes')
        if not self.rule.when:
            self.rule.when = Interval(every=2, period='minutes')

        # The rule's single action.
        self.rule.actions = [NoDataAction()]

        # The rule's resource selectors. This pair of selectors makes
        # the NoDataRule to be evaluated only for machines with enabled
        # monitoring, for which we have received monitoring data.
        self.rule.selectors = [
            FieldSelector(
                field='monitoring__hasmonitoring',
                operator='eq', value=True
            ),
            FieldSelector(
                field='monitoring__installation_status__activated_at',
                operator='gt', value=0
            )
        ]

        self.rule.save()
