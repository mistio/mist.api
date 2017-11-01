import uuid
import copy
import logging
import datetime

from mist.api import config

from mist.api.rules.models import RuleState


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

    def __init__(self, rule):
        """Initialize the plugin given a Rule instance.

        Upon initialization plugins are meant to extract the list of resource
        ids the given rule refers to. In case of arbitrary rules which do not
        explicitly declare a list of resource ids, the `self.rids` attribute
        is set to `[None]`, which denotes a single unknown/arbitrary resource.

        Subclasses SHOULD NOT have to override this method.

        """
        self.rule = rule
        # TODO these are queried for when creating a new rule
        self.rids = rule.get_ids() if not rule.is_arbitrary() else [None]

    def run(self, update_state=False, run_actions=False):
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
        rule. Caution should be taken when evaluating a rule synscronously
        in order to not alter its state unintentionally.

        This is the main method invoked by workers of the alerting service.

        Subclasses SHOULD NOT override or extend this method.

        """
        active_states = {}

        for rid in self.rids:
            # TODO: Wrap in a try-except? Push exc to ES?
            _, incident, state = self.evaluate(rid, run_actions)

            if state:
                active_states.update({incident: state})

        if update_state is True:
            self.rule.states.update(active_states)
            self.rule.states = {
                incident: state for
                incident, state in self.rule.states.iteritems() if not
                state.expired()
            }
            self.rule.save()

    def evaluate(self, rid, run_actions=False):
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
        from ipdb import set_trace; set_trace()
        assert rid in self.rids, 'Unknown resource %s' % rid

        for incident, state in self.rule.states.iteritems():
            # There should only be a single non-resolved incident at a
            # time for each of the resources this self.rule refers to.
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

            # Not triggered or unitriggered. Resolve triggered state.
            if not triggered:
                if state:
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

        log.info('%s is %s for resource %s', self.rule.name, state, rid)

        if state and not state.is_pending() and run_actions is True:
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
        to un(trigger).

        Subclasses must also comply to additional conventions:

        If the query returns an unexpected result, no datapoints, or even a
        completely empty reponse, then the `triggered` flag should be set equal
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
        try:
            import mist.core
            import mist.api.rules.backends.methods as methods
        except ImportError:
            pass
        else:
            params = state.as_dict()
            params.update({
                'incident': incident,
                'triggered': 1 if triggered else 0,
                'triggered_now': 1 if incident not in self.rule.states else 0,
            })
            return methods.send_trigger(self.rule.id, params)

    # TODO run this upon adding the rule or always?
    def validate(self):
        """Validate `self.rule`.

        This method may be used to perform any sort of validation and enforce
        limitations on a rule's parameters.

        Subclasses MAY override this method.

        """
        pass


class NoDataMixin(object):
    """A Mixin class that transform a backend plugin into a NoDataPlugin.

    A subclass of BaseBackendPlugin mixed in with this class will cause a
    data case to trigger the corresponding rule.

    """

    def execute(self, query, rid=None):
        _, retval = super(NoDataMixin, self).execute(query, rid)
        return True if retval is None else False, retval
