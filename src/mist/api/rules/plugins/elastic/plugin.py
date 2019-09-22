import re
import logging
import datetime
import operator

from mist.api.rules.plugins import base
from mist.api.rules.plugins.elastic.handlers import CountQueryHandler

from mist.api.logs.constants import FIELDS


log = logging.getLogger(__name__)


class ElasticSearchBackendPlugin(base.BaseBackendPlugin):

    def execute(self, query, rid=None):
        # Instantiate a request handler bound to an Organization context.
        handler = CountQueryHandler(self.rule.owner_id, rid, self.rtype)

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
        return getattr(operator, query.operator)(data, float(query.threshold)), data

    @staticmethod
    def validate(rule):
        # Queries are limited to this tuple of searchable keys.
        valid_keys = FIELDS + ('action', 'error', 'type')

        # Validate searchable keys in each query_string and terms query.
        for q in rule.queries:
            keys = re.findall(r'([\w]+):[\w]+', q.target)
            valid = (
                keys and all(k in valid_keys for k in keys) and
                all(f.key in valid_keys for f in q.filters)
            )
            assert valid, (
                'Searches can only run against keys %s' % str(valid_keys)
            )
            assert q.aggregation == 'count', (
                'Currently, only the count of objects can be calculated'
            )

        # The frequency should be at least 50% of the time window.
        window_seconds = rule.window.timedelta.total_seconds()
        frequency_seconds = rule.frequency.timedelta.total_seconds()
        assert round(frequency_seconds / (1. * window_seconds), 1) >= .5, (
            "The frequency of a rule's evaluation must be at least 50% of "
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
