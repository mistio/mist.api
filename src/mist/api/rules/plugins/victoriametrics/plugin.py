import logging
import asyncio

from mist.api.rules.plugins import base
from mist.api.rules.plugins import methods
from mist.api.monitoring.victoriametrics import methods as victoria_methods


log = logging.getLogger(__name__)


class VictoriaMetricsBackendPlugin(base.BaseBackendPlugin):

    def execute(self, query, rid=None):
        # Request data given a simple target expression.
        from mist.api.models import Machine
        m = Machine.objects.get(id=rid)
        data = victoria_methods.get_stats(machine=m,
                                          start=self.start,
                                          stop=self.stop,
                                          metrics=[query.target])

        # If response is empty, then data is absent for the given interval.
        if not len(data):
            log.warning('No datapoints for %s.%s', rid, query.target)
            return None, None

        # Check whether the query to Victoria Metrics returned multiple series.
        if len(data) > 1:
            log.warning('Got multiple series for %s.%s', rid, query.target)
            raise methods.MultipleSeriesReturnedError()

        # Ensure requested and returned targets match.
        target = data[list(data.keys())[0]].get("target", "")
        data = list(data.values())[0]
        if target != query.target:
            log.warning('Got %s while expecting %s', target, query.target)
            raise methods.RequestedTargetMismatchError()

        # Clean datapoints of None values.
        datapoints = [val for val, _ in data['datapoints'] if val is not None]
        if not datapoints:
            log.warning('No datapoints for %s.%s', rid, query.target)
            return None, None

        # Compare against the threshold and compute retval.
        return methods.compute(query.operator, query.aggregation, datapoints,
                               query.threshold)

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

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError('loop is closed')
        except RuntimeError:
            loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            rule._backend_plugin(rule)._async_execute_queries(rule, loop))
        loop.close()

        exceptions = 0
        for result in results:
            if isinstance(result, Exception):
                exceptions += 1
                log.warning(
                    f"Got {result} on rule: {rule.name} - {rule.full_name}")
        if exceptions >= len(results):
            raise results[0]

    @property
    def start(self):
        return '%d%s' % (self.rule.window.start, self.rule.window.period_short)

    @property
    def stop(self):
        if not self.rule.window.stop:
            return ''
        return '%d%s' % (self.rule.window.stop, self.rule.window.period_short)

    async def _async_execute_queries(self, rule, loop):
        queries_list = []
        for query in rule.queries:
            print(rule._backend_plugin(rule).rids)
            for rid in rule._backend_plugin(rule).rids:
                queries_list.append(loop.run_in_executor(
                    None, rule._backend_plugin(rule).execute, query, rid))
        return await asyncio.gather(*queries_list, return_exceptions=True)


class VictoriaMetricsNoDataPlugin(base.NoDataMixin,
                                  VictoriaMetricsBackendPlugin):
    pass
