import json
import logging

from mist.api.helpers import es_client as es

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import RateLimitError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ServiceUnavailableError

from mist.api.logs.constants import TYPES


logging.getLogger('elasticsearch').setLevel(logging.ERROR)
log = logging.getLogger(__name__)


def _filtered_query(owner_id, close=None, error=None, range=None, type=None,
                    callback=None, tornado_async=False, **kwargs):
    """Filter Elasticsearch documents.

    Executes a filtering aggregation on Elasticsearch documents in order to
    filter by documents indicating a closed story and/or a story that ended
    with an error.

    The aggregation result constists of two buckets:
        - one for closed stories
        - one for stories that contain an error

    Each bucket sub-aggregates documents based on their `stories` field in
    order to group log entries by their associated story IDs.

    This method is invoked by mist.api.logs.methods.get_stories.

    """
    assert owner_id

    index = "app-logs-*"
    query = {
        "query": {
            "bool": {
                "filter": {
                    "bool": {
                        "must": [
                            {"term": {"owner_id": owner_id}}
                        ]
                    }
                }
            }
        },
        "size": 0,
        "aggs": {
            "main_bucket": {
                "filters": {
                    "filters": {}
                },
                "aggs": {
                    "stories": {
                        "terms": {
                            "field": "stories",
                            "size": 10000
                        }
                    }
                }
            }
        }
    }
    # Specify whether to filter by closed stories.
    if close is not None:
        query["aggs"]["main_bucket"]["filters"]["filters"].update(
            {"close": {"term": {"stories": "closes"}}}
        )
    # Specify whether to filter by stories that contain an error.
    if error is not None:
        query["aggs"]["main_bucket"]["filters"]["filters"].update(
            {"error": {"term": {"error": True}}}
        )
    # Specify the time range of the stories.
    if range is not None:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"range": range}
        )
    # Match the type of the associated stories.
    if type:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {"stories": type}}
        )
    # Extend query based on additional terms.
    for key, value in kwargs.iteritems():
        if value in (None, ''):
            continue
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {key: value}}
        )
    # Perform Elasticsearch request.
    if not tornado_async:
        result = es().search(index=index, doc_type=TYPES.get(type), body=query)
        if callback:
            return callback(result)
        return result
    else:
        es(tornado_async).search(index=index, doc_type=TYPES.get(type),
                                 body=json.dumps(query), callback=callback)


def _on_response_callback(response, tornado_async=False):
    """HTTP Response-handling callback.

    This method is meant to return HTTP Response objects generated either in a
    Tornado or synchronous execution context.

    Arguments:
        - response: HTTP Response object.
        - tornado_async: Denotes if a Tornado-safe HTTP request was issued.

    """
    if tornado_async:
        if response.code != 200:
            log.error('Error on Elasticsearch query in tornado_async mode. '
                      'Got %d status code: %s', response.code, response.body)
            if response.code == 400:
                raise BadRequestError()
            if response.code == 404:
                raise NotFoundError()
            if response.code == 429:
                raise RateLimitError()
            raise ServiceUnavailableError()
        response = json.loads(response.body)
    return response
