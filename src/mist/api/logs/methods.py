import json
import time
import logging
import datetime

from mist.api.helpers import es_client as es

from mist.api.exceptions import NotFoundError

from mist.api.logs.helpers import _filtered_query
from mist.api.logs.helpers import _on_response_callback

from mist.api.logs.constants import FIELDS, JOBS
from mist.api.logs.constants import EXCLUDED_BUCKETS, TYPES
from mist.api.logs.constants import STARTS_STORY, CLOSES_STORY, CLOSES_INCIDENT

try:
    from mist.core.rbac.methods import filter_logs
except ImportError:
    from mist.api.dummy.rbac import filter_logs


logging.getLogger('elasticsearch').setLevel(logging.ERROR)
log = logging.getLogger(__name__)


# TODO
# def log_event(owner_id, event_type, action, error=None,
#               user_id=None, **kwargs):


# TODO: Make auth_context a required param?
def get_events(auth_context=None, owner_id='', user_id='',
               event_type='', action='', limit=0, start=0,
               stop=0, newest=True, error=None, **kwargs):
    """Fetch logged events.

    This generator yields a series of logs after querying Elasticsearch.

    The initial query is extended with additional terms based on the inputs
    provided. Also, extra filtering may be applied in order to perform RBAC
    on the fly given the permissions granted to the requesting User.

    All Elasticsearch indices are in the form of <app|ui>-logs-<date>.

    """
    # Restrict access to UI logs to Admins only.
    is_admin = auth_context and auth_context.user.role == 'Admin'
    # Attempt to enforce owner_id in case of non-Admins.
    if not is_admin and not owner_id:
        owner_id = auth_context.owner.id if auth_context else None

    # Construct base Elasticsearch query.
    index = "%s-logs-*" % ("*" if is_admin else "app")
    query = {
        "query": {
            "bool": {
                "filter": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": int(start * 1000),
                                        "lte": int(stop * 1000) or "now"
                                    }
                                }
                            }
                        ],
                        "must_not": []
                    }
                }
            }
        },
        "sort": [
            {
                "@timestamp": {
                    "order": ("desc" if newest else "asc")
                }
            }
        ],
        "size": (limit or 50)
    }
    # Match action.
    if action:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {'action': action}}
        )
    # Fetch logs corresponding to the current Organization.
    if owner_id:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {"owner_id": owner_id}}
        )
    # Match the user's ID, if provided.
    if user_id:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {"user_id": user_id}}
        )
    # Specify whether to fetch stories that ended with an error.
    if error:
        query["query"]["bool"]["filter"]["bool"]["must_not"].append(
            {"term": {"error": False}}
        )
    elif error is False:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {"error": False}}
        )

    if 'filter' in kwargs:
        f = kwargs.pop('filter')
        query_string = {
            'query': f,
            'analyze_wildcard': True,
            'default_operator': 'and'
        }
        query["query"]["bool"]["filter"]["bool"]["must"].append({
            'query_string': query_string
        })

    # Extend query with additional kwargs.
    for key, value in kwargs.iteritems():
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {key: value}}
        )

    # Apply RBAC for non-Owners.
    if auth_context and not auth_context.is_owner():
        filter_logs(auth_context, query)

    # Query Elasticsearch.
    result = es().search(index=index, doc_type=event_type, body=query)

    for hit in result['hits']['hits']:
        event = hit['_source']
        if not event.get('action'):
            log.error('Skipped event %s, missing action', event['log_id'])
            continue
        try:
            extra = json.loads(event.pop('extra'))
        except Exception as exc:
            log.error('Failed to parse extra of event %s [%s]: '
                      '%s', event['log_id'], event['action'], exc)
        else:
            for key, value in extra.iteritems():
                event[key] = value
        yield event


def get_stories(story_type='', owner_id='', user_id='',
                sort='started_at', sort_order=-1, limit=0,
                error=None, range=None, pending=None, expand=False,
                tornado_callback=None, tornado_async=False, **kwargs):
    """Fetch stories.

    Query Elasticsearch for story documents based on the provided arguments.
    By default, the stories are not fully expanded, but rather returned in a
    simple, compact format. On the other hand, if `expand=True`, the stories'
    full version is returned, consisting of the actual, detailed log entries.

    Stories are not actual Elasticsearch documents, but exist only as a high-
    level concept. Each story is basically a collection of logs, arranged in
    a meaningful sequence, which pertain to and describe a specific event.

    Stories are created by performing Elasticsearch aggregations on logs. Such
    aggregations are mainly executed on the `stories` field contained in every
    log that is associated with a particular story (or stories). The `stories`
    field is a list of lists in the form of:

        (opens|closes|updates, job|shell|session|incident, story_id)

    which intends to describe how a certain log affects a story. Logs may open,
    close, or update stories of type job, shell, session, or incident. Each log
    should also specify the `story_id` of the story it refers to.

    """
    # Do not return fully detailed stories, unless specified, especially when
    # in Tornado context. If the short version is requested, return only the
    # absolute necessary fields needed to create the story.
    if not expand:
        includes = ["log_id", "stories", "error", "time"]
    else:
        includes = []
        assert not tornado_async
    if story_type:
        assert story_type in TYPES

    # Construct base Elasticsearch query.
    index = "app-logs-*"
    query = {
        "query": {
            "bool": {
                "filter": {
                    "bool": {
                        "must": [],
                        "must_not": [],
                    }
                }
            }
        },
        "sort": [{
            "@timestamp": {
                "order": "desc" if sort_order == -1 else "asc"
            }
        }],
        "size": 0
    }
    # Create aggregations. Request buckets of logs per story_id.
    query["aggs"] = {
        "stories": {
            "terms": {
                "field": "stories",
                "size": limit or 1000
            },
            "aggs": {
                "top_logs": {
                    "top_hits": {
                        "sort": [{
                            "@timestamp": {
                                "order": "asc"
                            }
                        }],
                        "_source": {
                            "includes": includes,
                        },
                        "size": 50
                    }
                }
            }
        }
    }
    # Match the type of the associated stories.
    if story_type:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {"stories": story_type}}
        )
    # Fetch logs corresponding to the current Organization.
    if owner_id:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {"owner_id": owner_id}}
        )
    # Fetch documents corresponding to the current user, if provided.
    if user_id:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {"user_id": user_id}}
        )
    # Specify the time range of the stories.
    if range:
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"range": range}
        )
    # Extend query based on additional terms.
    for key, value in kwargs.iteritems():
        if value in (None, ''):
            log.debug('Got key "%s" with empty value', key)
            continue
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {key: value}}
        )

    # Process returned stories.
    def _on_stories_callback(response):
        result = _on_response_callback(response, tornado_async)
        return process_stories(
            buckets=result["aggregations"]["stories"]["buckets"],
            callback=tornado_callback, type=story_type, pending=pending
        )

    # Fetch stories. Invoke callback to process and return results.
    def _on_request_callback(query):
        if not tornado_async:
            result = es().search(index=index, doc_type=TYPES.get(story_type),
                                 body=query)
            return _on_stories_callback(result)
        else:
            es(tornado_async).search(index=index,
                                     body=json.dumps(query),
                                     doc_type=TYPES.get(story_type),
                                     callback=_on_stories_callback)

    # Process aggregation results in order to be applied as filters.
    def _on_filters_callback(response):
        results = _on_response_callback(response, tornado_async)
        filters = results["aggregations"]["main_bucket"]["buckets"]
        process_filters(query, filters, pending, error)
        return _on_request_callback(query)

    # Perform a filter aggregation, if required, on stories based on their
    # pending and/or error status, which will be applied as a filter by the
    # main query. If such filtering does not need to take place, the main
    # query is performed right away.
    if pending is not None or error is not None:
        return _filtered_query(owner_id, close=pending, error=error,
                               range=range, type=story_type,
                               callback=_on_filters_callback,
                               tornado_async=tornado_async, **kwargs)
    else:
        return _on_request_callback(query)


def process_stories(buckets, type=None, pending=None, callback=None):
    """Process fetched logs.

    Process results of Elasticsearch aggregations on logs in order to create
    stories.

    Arguments:
        - buckets: buckets of logs returned by Elasticsearch aggregations.
        - type: the story's type - one of (job, shell, session, incident).
        - pending: denotes whether we are processing stories still pending.
        - callback: the callback to be invoked, after processing, if provided.

    """
    stories = []
    for bucket in buckets:
        if bucket['key'] in EXCLUDED_BUCKETS:
            continue
        start = bucket['top_logs']['hits']['hits'][0]['_source']['time']
        story = {
            'logs': [],
            'type': type,
            'error': False,
            'story_id': bucket['key'],
            'started_at': start,
            'finished_at': 0
        }

        for doc in bucket['top_logs']['hits']['hits']:
            body = doc['_source']

            # Set proper story_type, if missing.
            if not story['type']:
                if doc['_type'] in ('job', 'shell', 'session', 'incident'):
                    story['type'] = doc['_type']

            # Bring more key-value pairs to the top level.
            for key, value in body.iteritems():
                if key in FIELDS and key not in story:
                    story[key] = value

            # Bring extra key-value pairs to the log's top level.
            if 'extra' in body:
                try:
                    extra = json.loads(body.pop('extra'))
                    for key, value in extra.iteritems():
                        body[key] = value
                except Exception as exc:
                    log.error('Error parsing log %s: %s', body['log_id'], exc)

            # Provide the error message at the top level, if one occured.
            error = body.get('error')
            if error and not story.get('error'):
                story['error'] = error

            # Set the story's `finished_at` timestamp, if not still pending.
            for act, _, sid in body.get('stories', []):
                if sid == story['story_id'] and act == 'closes':
                    story['finished_at'] = body['time']
                    break

            # Append the log to the story's `logs`.
            story['logs'].append(body)

        stories.append(story)

    if callback is not None:
        return callback(stories, pending)
    return stories


def process_filters(query, filters, close=None, error=None):
    """Process query filters.

    Process filter results returned by the `_filtered_query` helper. Such
    filters are meant to be appended to the main query used to fetch logs
    in order to further filter the stories to be returned.

    There are two types of filters executed in this context:
        - Filtering of logs indicating closed stories
        - Filtering of logs indicating stories that ended with an error

    Arguments:
        - query: an already initialized Elasticsearch query.
        - filters: the filters to be processed and appended to the query.
        - close,error: denotes whether the filters have been run against
                       pending stories or stories that ended with an error.

    """
    for filter in ("close", "error"):
        stories = []
        if locals()[filter] is not None:
            if filter == "close":
                append_to = "must_not" if close else "must"
            if filter == "error":
                append_to = "must_not" if not error else "must"
            for story in filters[filter]["stories"]["buckets"]:
                if story["key"] in EXCLUDED_BUCKETS:
                    continue
                stories.append(story["key"])
            query["query"]["bool"]["filter"]["bool"][append_to].append(
                {"terms": {"stories": stories}}
            )


def associate_stories(event):
    """Associate potential stories to the event provided."""
    story_id = event['story_id']
    story_type = event['type'] if event['type'] != 'request' else 'job'
    try:
        job = json.loads(event['extra']).pop('job', None)
    except Exception as exc:
        job = None
        log.warn('Failed to extract job param from extra: %s', exc)

    # Decide whether the event tends to open, update, or close a story.
    action = 'updates'
    if event['error']:
        action = 'closes'
    elif event['action'] in JOBS.itervalues():
        if job in JOBS:
            action = 'closes'
    elif event['action'] in CLOSES_STORY + CLOSES_INCIDENT:
        action = 'closes'
    elif event['action'] in STARTS_STORY:
        action = 'opens'

    # Append metadata to the event's `stories`.
    event['stories'].append((action, story_type, story_id))


def close_open_incidents(event):
    """Close any open incidents based on the event provided."""
    if 'stories' not in event:
        event['stories'] = []

    kwargs = {
        'story_type': 'incident',
        'owner_id': event['owner_id'],
        'pending': True,
    }
    for key in ('rule_id', 'cloud_id', 'machine_id'):
        if key in event:
            kwargs[key] = event[key]

    incidents = get_stories(**kwargs)
    for inc in incidents:
        event['stories'].append(('closes', 'incident', inc['story_id']))

    log.warn('%s incident(s) closed by %s', len(incidents), event['log_id'])


def get_story(owner_id, story_id, story_type=None, expand=True):
    """Fetch a single story given its story_id."""
    story = get_stories(owner_id=owner_id, story_id=story_id,
                        story_type=story_type, expand=expand)
    if not story:
        msg = 'Story %s' % story_id
        if story_type:
            msg += ' [%s]' % story_type
        raise NotFoundError(msg)
    if len(story) > 1:
        log.error('Found multiple stories with story_id %s', story_id)
    return story[0]


def close_story(owner_id, story_id):
    """Close an open story."""
    index = 'app-logs-*'
    query = {
        'query': {
            'bool': {
                'filter': {
                    'bool': {
                        'must': [
                            {'term': {'owner_id': owner_id}},
                            {'term': {'story_id': story_id}},
                        ]
                    }
                }
            }
        },
        'sort': [{
            '@timestamp': {
                'order': 'desc'
            }
        }],
        'size': 1
    }

    result = es().search(index=index, body=query)
    if not result['hits']['hits']:
        raise NotFoundError('story_id %s' % story_id)

    # Get the latest log entry.
    doc = result['hits']['hits'][0]
    body = doc['_source']
    # Get proper story_type.
    story_type = doc['_type'] if doc['_type'] != 'request' else 'job'
    # Mark the latest log entry as the one closing the story.
    for story in body['stories']:
        if tuple(story) == ('closes', story_type, story_id):
            log.error('Story %s already closed', story_id)
            break
    else:
        body['stories'].append(('closes', story_type, story_id))
        es().index(index=doc['_index'], doc_type=doc['_type'], id=doc['_id'],
                   body=body)


def delete_story(owner_id, story_id):
    """Delete a story."""
    index = 'app-logs-*'
    query = {
        'query': {
            'bool': {
                'filter': {
                    'bool': {
                        'must': [
                            {'term': {'owner_id': owner_id}},
                            {'term': {'story_id': story_id}},
                        ]
                    }
                }
            }
        }
    }
    # Delete all documents matching the above query.
    result = es().delete_by_query(index=index, body=query, conflicts='proceed')
    if not result['deleted']:
        raise NotFoundError('story_id %s' % story_id)
    # Report results.
    msg = 'Deleted %s log(s) with story_id %s' % (result['deleted'], story_id)
    if result['version_conflicts']:
        msg += ' Counted %s version_conflicts' % result['version_conflicts']
    if result['failures']:
        msg += ' Finished with failures: %s' % result['failures']
    log.warn(msg)
