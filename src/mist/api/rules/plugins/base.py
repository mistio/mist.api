import uuid
import copy
import logging
import datetime

from mist.api.rules.models import RuleState
from mist.api.rules.plugins import methods


log = logging.getLogger(__name__)


class BaseBackendPlugin(object):
    """The base class that implements a backend plugin.

    Plugins are used to translate a `mist.api.rules.models.Rule` instance
    into the proper query expressions that's meant to be executed against
    the corresponding backend storage. Each data storage should implement
    its own backend plugin, whether it's a TSDB or logs' storage.

    All backend plugins should subclass this base class and implement the
    functionality specific to a certain data storage in order to construct
    and execute the appropriate query, as well as reduce the returned time
    series and compare the result to the specified threshold.

    All backend plugin subclasses should retain the same high-level API in
    order to be utilized transparently/interchangeably according to ongoing
    needs.

    """

    def __init__(self, rule, rids=None):
        """Initialize the plugin given a Rule instance.

        Upon initialization plugins are meant to extract the list of resource
        ids the given rule refers to. In case of arbitrary rules which do not
        explicitly declare a list of resource ids, the `self.rids` attribute
        is set to `[None]`, which denotes a single unknown/arbitrary resource.

        Subclasses SHOULD NOT have to override this method.

        """
        self.rule = rule
        self.rids = rids
        if self.rids is None:
            self.rids = rule.get_ids() if not rule.is_arbitrary() else [None]
        self.rtype = None if rule.is_arbitrary() else rule.resource_model_name

    def run(self, update_state=False, trigger_actions=False):
        """Run a single evaluation cycle.

        This method exposes the plugin's most abstract API. It is meant to
        be invoked as such:

            rule = mist.api.rules.models.Rule.objects.get(id=1)
            rule.plugin.run()

        This method evaluates `self.rule` for each one of the `self.rids`
        sequentially. Each evaluation returns a (triggered, incident, state)
        tuple that describes the state of the resource with id `rid`.

        At the end of the evaluation cycle, `self.rule.states` are updated
        given the currently `active_states`. As active we consider states
        which are triggered (either pending or firing) or just got untriggered.

        NOTE that this is the ONLY method that takes care of updating the
        rule's state given `update_state` equals True and actually saves the
        rule. Caution should be taken when evaluating a rule synchronously
        in order to not alter its state unintentionally.

        This is the main method invoked by workers of the alerting service.

        Subclasses SHOULD NOT override or extend this method.

        """
        active_states = {}
        remove_states = set()

        for rid in self.rids:
            try:
                _, incident, state = self.evaluate(rid, trigger_actions)
            except methods.ResourceNotFoundError:
                remove_states.add(rid)
                continue
            except Exception as exc:
                log.error('Failed during %s evaluation: %r', self.rule, exc)
                continue

            if state:
                active_states.update({incident: state})

        # Clean states. Remove states that refer to missing/deleted resources
        # or states that have expired.
        if update_state is True:
            self.rule.states.update(active_states)
            self.rule.states = {
                incident: state for
                incident, state in self.rule.states.items() if
                state.resource in (set(self.rids) ^ remove_states) and not
                state.expired()
            }
            self.rule.total_check_count += len(self.rids)
            self.rule.save()

    def evaluate(self, rid, trigger_actions=False):
        """Evaluate `self.rule` for the given `rid`.

        This method implements the core functionality of a backend plugin,
        which oughts to be common amongst subclasses.

        This method evaluates all queries of `self.rule.queries`, which are
        chained together with a logical AND. In order for a rule to evaluate
        to True all subsequent queries must also evaluate to True. Otherwise,
        the rule is considered untriggered/resolved for the given `rid`.

        Once the rule exits its pending state, meaning it's either resolved
        or enters firing state, an alert is sent, which in turn may trigger
        additional actions to be executed.

        Subclasses SHOULD NOT override or extend this method.

        """
        assert rid in self.rids, 'Unknown resource %s' % rid
        for incident, state in self.rule.states.items():
            # There should only be a single non-resolved incident at a
            # time for each of the resources self.rule refers to.
            if state.resource == rid and not state.is_resolved():
                log.info('Found open incident %s %s', incident, state)
                state = copy.deepcopy(state)
                break
        else:
            incident, state = uuid.uuid4().hex, None

        for query in self.rule.queries:
            # Execute the query for the given resource, if specified.
            triggered, retval = self.execute(query, rid)

            # In case the query returned no series, we set triggered
            # equal to None and stop the evaluation, since we cannot
            # tell whether we should (un)trigger the rule.
            if triggered is None:
                return triggered, incident, None

            # Not triggered or untriggered. Resolve triggered state.
            if not triggered:
                if state:
                    state.value = retval
                    state.resolved_since = datetime.datetime.utcnow()
                break
        else:
            # Triggered. Initialize a new state, if one was not found.
            if not state:
                state = RuleState(resource=rid, value=retval)
                state.pending_since = datetime.datetime.utcnow()

            # Set state to firing, if the pending period is over.
            if not state.is_firing():
                offset = self.rule.trigger_after.timedelta
                elapsed = datetime.datetime.utcnow() - state.pending_since
                if offset.total_seconds() < elapsed.total_seconds():
                    state.firing_since = datetime.datetime.utcnow()

        log.info("%s %s for %s %s", self.rule.full_name, state or 'OK',
                 self.rtype, rid)

        if state and not state.is_pending() and trigger_actions is True:
            self.trigger(triggered, incident, state)

        return triggered, incident, state

    def execute(self, query, rid=None):
        """Execute the provided query.

        This method should implement the logic specific to a certain database
        in order to be able to execute the provided query. The `query` has to
        be transformed to its expected format and executed against the backend
        storage.

        In order to expose a compatible, unified API this method should always
        return a (triggered, retval) tuple. The `triggered` flag should be a
        boolean indicating whether the query evaluated to True or not and the
        `retval` should be the value (of dynamic type) that caused the query
        to (un)trigger.

        Subclasses must also comply to additional conventions:

        If the query returns an unexpected result, no datapoints, or even a
        completely empty response, then the `triggered` flag should be set
        to `None` in order to indicate uncertainty as to whether the rule has
        to be (un)triggered. The `retval` should also be set to `None` in order
        to indicate the absence of datapoints.

        However, no further actions have to be taken to handle such conditions.
        NoData cases are meant to be handled by a special NoData rule.

        Subclasses MUST override this method.

        """
        raise NotImplementedError()

    def trigger(self, triggered, incident, state):
        """Send an alert/trigger.

        This method may be used to send a generic trigger, alert, or even
        execute any sort of arbitrary actions in response to a rule being
        triggered.

        This method is meant to be called intenally by `self.evaluate`.

        Arguments:

            - triggered: a bool indicating whether `incident` got (un)triggered
            - incident:  an incident denoted by its UUID
            - state:     an instance of `mist.api.rules.models.RuleState` which
                         describes the current state of `self.rule` for a given
                         resource

        Subclasses MAY override this method.

        """
        params = state.as_dict()
        params['value'] = params['value'] or 0
        params.update({
            'incident': incident,
            'triggered': 1 if triggered else 0,
            'triggered_now': 1 if incident not in self.rule.states else 0,
        })
        methods.send_trigger(self.rule.id, params)

    @staticmethod
    def validate(rule):
        """Validate `rule`.

        This method may be used to perform any sort of validation and enforce
        limitations on a rule's parameters.

        Subclasses MAY override this method.

        """
        pass


class NoDataMixin(object):
    """A Mixin class that transform a backend plugin into a NoData plugin.

    A subclass of BaseBackendPlugin mixed in with this class will cause a
    no-data state to trigger the corresponding rule.

    """

    def execute(self, query, rid=None):
        _, retval = super(NoDataMixin, self).execute(query, rid)
        return True if retval is None else False, retval
