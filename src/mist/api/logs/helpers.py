import json
import logging

from mist.api.helpers import es_client as es

from mist.api.logs.constants import TYPES


logging.getLogger('elasticsearch').setLevel(logging.ERROR)
log = logging.getLogger(__name__)


def _filtered_query(owner_id, close=None, error=None, range=None, type=None,
                    callback=None, es_async=False, **kwargs):
    """Filter Elasticsearch documents.

    Executes a filtering aggregation on Elasticsearch documents in order to
    filter by documents indicating a closed story and/or a story that ended
    with an error.

    The aggregation result consists of two buckets:
        - one for closed stories
        - one for stories that contain an error

    Each bucket sub-aggregates documents based on their `stories` field in
    order to group log entries by their associated story IDs.

    This method is invoked by mist.api.logs.methods.get_stories.

    """
    index = "app-logs-*"
    query = {
        "query": {
            "bool": {
                "filter": {
                    "bool": {
                        "must": []
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
    # Fetch logs corresponding to the specified Owner.
    if owner_id:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {"owner_id": owner_id}}
        )
    # Extend query based on additional terms.
    for key, value in kwargs.items():
        if value in (None, ''):
            continue
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {key: value}}
        )
    # Perform Elasticsearch request.
    if not es_async:
        result = es().search(index=index, doc_type=TYPES.get(type), body=query)
        if callback:
            return callback(result)
        return result
    else:
        es(es_async).search(index=index, doc_type=TYPES.get(type),
                            body=json.dumps(query), callback=callback)
