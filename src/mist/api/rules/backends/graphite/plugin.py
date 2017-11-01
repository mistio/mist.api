import logging

from mist.api.rules.backends import base
from mist.api.rules.backends import methods
from mist.api.rules.backends.graphite import handlers as hrs


log = logging.getLogger(__name__)


def compute2(operator, aggregate, values, threshold):
    """"""
    # Apply avg before operator.
    if aggregate == 'avg':
        values = [float(sum(values)) / len(values)]

    if operator == 'gt':
        retval = max(values)
        if aggregate == 'all':
            triggered = min(values) > threshold
        else:
            triggered = max(values) > threshold

    if operator == 'lt':
        retval = min(values)
        if aggregate == 'all':
            triggered = max(values) < threshold
        else:
            triggered = min(values) < threshold

    return triggered, retval


# TODO move to methods.py
def compute(operator, aggregate, values, threshold):
    if aggregate == 'avg':  # Apply avg before operator.
        values = [float(sum(values)) / len(values)]
    if operator == 'gt':
        states = {value: value > threshold for value in values}
    elif operator == 'lt':
        states = {value: value < threshold for value in values}
    if aggregate == 'all':
        state = False not in states.values()
        if not state:  # Find retval from false values.
            values = [value for value, _state in states.items() if not _state]
    else:
        state = True in states.values()
    if operator == 'gt':
        retval = max(values)
    elif operator == 'lt':
        retval = min(values)
    return state, retval


TARGETS = (
    'load.shortterm',
    'cpu.total.nonidle',
    'memory.nonfree_percent',
    'disk.total.disk_octets.read',
    'disk.total.disk_octets.write',
    'interface.total.if_octets.rx',
    'interface.total.if_octets.tx',
)


class GraphiteBackendPlugin(base.BaseBackendPlugin):

    def execute(self, query, rid=None):
        # Request data given a simple target expression.
        data = hrs.MultiHandler(rid).get_data(query.target, start=self.window)

        # Is the whisper file missing? No data ever reached Graphite.
        if not len(data):
            log.warning('Empty response for %s.%s', rid, query.target)
            return None, None

        # Check whether the query to Graphite returned multiple series. This
        # should never occur actually, since the query's target has to belong
        # to a pre-defined list of allowed targets that are quaranteed to
        # return a single series. The is no implementation that allowed us to
        # reduce multiple series into one on demand. This is a limitation of
        # the old Graphite-based/mist.monitor stack.
        if len(data) > 1:
            log.warning('Got multiple series for %s.%s', rid, query.target)

        # Ensure requested and returned targets match.
        data = data[0]
        target = data['_requested_target']
        if target != query.target:
            log.warning('Got %s while expecting %s', target, query.target)
            return None, None

        # Clean datapoints of None values.
        datapoints = [val for val, _ in data['datapoints'] if val is not None]
        if not datapoints:
            log.warning('No datapoints for %s.%s', rid, query.target)
            return None, None

        # Compare against the threshold and compute retval.
        triggered, retval = compute(query.operator, query.aggregation,
                                    datapoints, query.threshold)
        return triggered, retval

    def validate(self):
        # No arbitrary rules.
        assert not self.rule.is_arbitrary()

        # Capped query window.
        assert self.rule.window.timedelta.total_seconds() <= 60 * 10

        # The frequency should be at least 70% of the time window.
        window_seconds = self.rule.window.timedelta.total_seconds()
        frequency_seconds = self.rule.frequency.timedelta.total_seconds()
        assert round(frequency_seconds / (1. * window_seconds), 2) >= .7

        # Ensure a simple query condition with no additional filters.
        assert len(self.rule.queries) is 1
        assert not self.rule.queries[0].filters
        assert self.rule.queries[0].target in TARGETS
        assert self.rule.queries[0].aggregation in ('all', 'any', 'avg', )

    @property
    def window(self):
        return '-%dsec' % self.rule.window.timedelta.total_seconds()


class GraphiteNoDataPlugin(base.NoDataMixin, GraphiteBackendPlugin):
    pass
