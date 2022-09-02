import logging
import datetime
import operator

from mist.api.rules.plugins import base
from mist.api.rules.plugins.elastic.handlers import CountQueryHandler


log = logging.getLogger(__name__)


class ElasticSearchBackendPlugin(base.BaseBackendPlugin):

    def execute(self, query, rid=None):
        # Instantiate a request handler bound to an Organization context.
        handler = CountQueryHandler(self.rule.org_id, rid, self.rtype)

        # Transform the list of a rule's conditions' filters into proper
        # term clauses that can be used by the query handler.
        terms = {'must': [], 'must_not': []}
        for f in query.filters:
            clause = 'must' if f.operator == 'eq' else 'must_not'
            term_q = 'terms' if isinstance(f.value, list) else 'term'
            terms[clause].append({term_q: {f.key: f.value}})

        # Request data given a Query String Query and any extra Term Query.
        # Note that a Term(s) Query matches the documents that contain the
        # exact term in the specified field, while a Query String Query can
        # also perform full-text search based on the each field's mapping.
        data = handler.search(self.start, self.stop, terms, query.target)

        # Compare against the threshold and return the count.
        return getattr(operator, query.operator)(
            data, float(query.threshold)), data

    @staticmethod
    def validate(rule):
        # Validate searchable keys in each query_string and terms query.
        for q in rule.queries:
            assert q.aggregation == 'count', (
                'Currently, only the count of objects can be calculated'
            )

        # The frequency should be at least 50% of the time window.
        window_seconds = rule.window.timedelta.total_seconds()
        frequency_seconds = rule.when.timedelta.total_seconds()
        assert round(frequency_seconds / (1. * window_seconds), 1) >= .1, (
            "The frequency of a rule's evaluation must be at least 10% of "
            "its time window"
        )

    @property
    def start(self):
        window = self.rule.window
        return (datetime.datetime.utcnow() -
                datetime.timedelta(**{window.period: window.start}))

    @property
    def stop(self):
        window = self.rule.window
        return (datetime.datetime.utcnow() -
                datetime.timedelta(**{window.period: window.stop}))
