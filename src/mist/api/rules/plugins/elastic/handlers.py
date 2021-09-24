import logging
import datetime
import elasticsearch.exceptions as eexc

from mist.api.helpers import es_client as es

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ServiceUnavailableError


log = logging.getLogger(__name__)


class ElasticQueryHandler(object):
    """Basic handler for querying Elasticsearch.

    This query handler can be used to request documents from an Elasticsearch
    node/cluster. Every instance of the `ElasticQueryHandler` is bound to an
    Organization, so that all queries are performed within the context of the
    given `owner_id`. Also, each instance of the handler can be further bound
    to a single resource provided its resource type (ex. machine, script, key,
    etc.) and UUID.

    The base query is returned by the `_get_query` method. It may be overridden
    by subclasses in order to extend the query with extra clauses, like `sort`
    or `size`, as well as aggregations. It is recommended that a new subclass
    of the `ElasticQueryHandler` is implemented for a new aggregation query so
    that each - potentially heavy - aggregation is performed in a controlled
    environment by a specific query handler.

    The `ElasticQueryHandler` enables both queries on exact matches with the
    use of a low-level Term Query, as well full-text search by leveraging a
    Query String Query (recommended). A Query String Query understands how the
    fields of an index have been analyzed and can be used for full-text search,
    as well as exact match requests.

    Note that search requests are limited to application logs only.

    """

    def __init__(self, owner_id, rid=None, rtype=None):
        # The index in which to search for matching (application) logs.
        self.index = "app-logs-*"

        # The Organization to which the query will be bound. Only logs
        # belonging to this Organization are going to match.
        self.owner_id = owner_id

        # Optional resource uuid and resource type (ex. machine, script,
        # etc.) to bound the query to. This restricts the query's hits
        # to documents referring to this specific resource. Both `rid`
        # and `rtype` have to be provided.
        self._rid = rid
        self._rtype = rtype
        assert not (bool(self._rid) ^ bool(self._rtype))

    def search(self, start, stop, terms=None, query_string=''):
        """Query elasticsearch for documents within the given timeframe."""
        query = self._get_query(start, stop, terms, query_string)
        try:
            return self._run_query(query)
        except eexc.NotFoundError as err:
            log.error('%s: %s', self.__class__.__name__, err.info)
            raise NotFoundError(err.error)
        except (eexc.RequestError, eexc.TransportError) as err:
            log.error('%s: %s', self.__class__.__name__, err.info)
            raise BadRequestError(err.error)
        except (eexc.ConnectionError, eexc.ConnectionTimeout) as err:
            log.error('%s: %s', self.__class__.__name__, err.info)
            raise ServiceUnavailableError(err.error)

    def _run_query(self, query):
        """Execute the elasticsearch `query` and return the matching documents.

        This method must always return the expected result of a query, ex. the
        list containing all document hits. Any processing or validation of the
        results has to to be done here before returning them.

        Subclasses MAY override this method.

        """
        return es().search(index=self.index, body=query)['hits']['hits']

    def _get_query(self, start, stop, terms=None, query_string=''):
        """Construct the elasticsearch query.

        The query is bound to `self.owner_id`, which means that the matching
        documents cannot be outside the context of the specified Organization.
        The query is also restricted to a specific timeframe indicated by the
        `start` and `stop` timestamps.

        In addition, the query's hits can be further restricted by specifying
        a dict of `terms`, whose values represent a Term Query each. A Query
        String Query can also be supplied, which also allows full-text search,
        and it's the safest option, when the requesting index's mapping isn't
        known. A Query String Query also enables multi-field search using a
        single string.

        This method is meant to be called by `self.search` in order to pass
        its return value to `self._run_query`.

        Subclasses MAY override this method.

        """
        assert terms is None or isinstance(terms, dict)
        assert (isinstance(stop, datetime.datetime) and
                isinstance(start, datetime.datetime))

        query = {
            "query": {
                "bool": {
                    "filter": {
                        "bool": {
                            "must": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": start.isoformat(),
                                            "lte": stop.isoformat(),
                                        },
                                    },
                                },
                                {
                                    "term": {
                                        "owner_id": self.owner_id,
                                    },
                                },
                            ],
                            "must_not": [],
                        },
                    },
                },
            },
        }

        # Append the Query String Query to the `must` clause of the `query`.
        # Note that in case no bool operators have been specified in the
        # query, then all search terms will be grouped together with the
        # logical AND operator.
        if query_string:
            query['query']['bool']['filter']['bool']['must'].append({
                'query_string': {
                    'query': query_string,
                    'analyze_wildcard': True,
                    'default_operator': 'and',
                    'allow_leading_wildcard': False
                }
            })

        # If self is bound to a specific resource, then append its uuid
        # to the query's `must` clause.
        if self.resource_field_name:
            query['query']['bool']['filter']['bool']['must'].append({
                'term': {self.resource_field_name: self.resource_id}
            })

        # Extend `query` with any additional Term Query to further limit
        # its hits.
        for key, value in list((terms or {}).items()):
            if key not in ('must', 'must_not', ):
                log.error('Boolean clause "%s" is not supported', key)
                continue
            if not isinstance(value, list):
                log.error('Expected list of Term Queries, but got: %s', value)
                continue
            if not all(isinstance(d, dict) for d in value):
                log.error('Some Term Queries are not dicts: %s', value)
                continue
            query['query']['bool']['filter']['bool'][key].extend(value)

        return query

    @property
    def resource_id(self):
        return self._rid

    @property
    def resource_field_name(self):
        """Return the field to search against to fetch a resource's logs."""
        return self._rtype + '_id' if self._rtype else None


class CountQueryHandler(ElasticQueryHandler):
    """A simple query handler that returns the count of matching documents."""

    def _run_query(self, query):
        return es().count(index=self.index, body=query)['count']
