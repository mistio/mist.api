import logging

from mist.api.rules.plugins import base
from mist.api.rules.plugins import methods
from mist.api.monitoring.graphite import handlers as hrs


log = logging.getLogger(__name__)


class GraphiteBackendPlugin(base.BaseBackendPlugin):

    def execute(self, query, rid=None):
        # Request data given a simple target expression.
        data = hrs.MultiHandler(rid).get_data(query.target, start=self.window)

        # No data ever reached Graphite? Is the whisper file missing?
        # Graphite's empty response doesn't mean it has no values
        if not len(data):
            log.warning('Empty response for %s.%s', rid, query.target)
            raise methods.EmptyResponseReturnedError()

        # Check whether the query to Graphite returned multiple series. This
        # should never occur actually, since the query's target belongs to a
        # pre-defined list of allowed targets which are quaranteed to return
        # a single series.
        if len(data) > 1:
            log.warning('Got multiple series for %s.%s', rid, query.target)
            raise methods.MultipleSeriesReturnedError()

        # Ensure requested and returned targets match.
        data = data[0]
        target = data['_requested_target']
        if target != query.target:
            log.warning('Got %s while expecting %s', target, query.target)
            raise methods.RequestedTargetMismatchError()

        # Clean datapoints of None values.
        datapoints = [val for val, _ in data['datapoints'] if val is not None]
        if not datapoints:
            log.warning('No datapoints for %s.%s', rid, query.target)
            return None, None

        # Compare against the threshold and compute retval.
        triggered, retval = methods.compute(query.operator, query.aggregation,
                                            datapoints, query.threshold)
        return triggered, retval

    @staticmethod
    def validate(rule):
        # No arbitrary rules.
        assert not rule.is_arbitrary()

        # The frequency should be at least 25% of the time window.
        window_seconds = rule.window.timedelta.total_seconds()
        frequency_seconds = rule.when.timedelta.total_seconds()
        assert round(frequency_seconds / (1. * window_seconds), 2) >= .25,\
            "The frequency should be at least 25% of the time window"

        # Ensure a simple query condition with no additional filters.
        # assert len(rule.queries) is 1
        assert not rule.queries[0].filters

    @property
    def window(self):
        return '-%dsec' % self.rule.window.timedelta.total_seconds()


class GraphiteNoDataPlugin(base.NoDataMixin, GraphiteBackendPlugin):
    pass
