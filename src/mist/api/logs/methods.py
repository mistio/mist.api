import uuid
import json
import time
import logging
import elasticsearch.exceptions as eexc

from mist.api import config

from mist.api.helpers import es_client as es
from mist.api.helpers import amqp_publish

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ServiceUnavailableError

from mist.api.users.models import User

from mist.api.logs.helpers import _filtered_query

from mist.api.logs.constants import FIELDS, JOBS
from mist.api.logs.constants import EXCLUDED_BUCKETS, TYPES
from mist.api.logs.constants import STARTS_STORY, CLOSES_STORY, CLOSES_INCIDENT

if config.HAS_EXPERIMENTS:
    from mist.experiments.helpers import cross_populate_session_data
else:
    from mist.api.dummy.methods import cross_populate_session_data

if config.HAS_RBAC:
    from mist.rbac.methods import filter_logs
else:
    from mist.api.dummy.rbac import filter_logs


logging.getLogger('elasticsearch').setLevel(logging.ERROR)
log = logging.getLogger(__name__)


# FIXME: Once we are consistent with machine_id, external_id
# etc, sanitize all the chaos below
def log_observations(owner_id, cloud_id, resource_type, patch,
                     cached_resources, new_resources):
    """Log observation events.
    An observation event can be one of: create/destroy machine,
    create/delete volume, create/delete network or attach/detach
    volume.
    Arguments:
        - owner_id
        - cloud_id
        - resource_type: one of machine, volume, network
        - patch: the json patch produced from the diff of
            cached and new resources
    """
    log_dict = {
        'cloud_id': cloud_id,
    }

    for _patch in patch:
        name = ''
        if _patch.get('op') == 'add':

            if isinstance(_patch.get('value'), dict) and \
               _patch.get('value').get('id', '') and \
               len(_patch.get('path').split('/')) <= 2:
                action = 'create_' + resource_type
                name = _patch.get('value').get('name')
                resource_id = _patch.get('value').get('id')
                provider_id = 'external_id' if resource_type == 'volume' \
                    else resource_type + '_id'
                external_id = _patch.get('value').get(provider_id)
            elif '/attached_to/' in _patch.get('path'):
                action = 'attach_volume'
                key = _patch.get('path')[1:-14]  # strip '/', '/attached_to/0'
                name = cached_resources.get(key).get('name')
                ids = _patch.get('path').split('-')
                resource_id = ids.pop(0).strip('/')
                external_id = '-'.join(ids).split('attached_to')[0][:-1]
                log_dict.update({'machine_id': _patch.get('value')})
            else:
                continue

        elif _patch.get('op') == 'remove':

            if '/attached_to/' in _patch.get('path'):
                action = 'detach_volume'
                ids = _patch.get('path').split('-')
                resource_id = ids.pop(0).strip('/')
                external_id = '-'.join(ids).split('attached_to')[0][:-1]
                # find the machine the volume was attached to
                key = resource_id + '-' + external_id
                name = cached_resources.get(key).get('name')
                machine_id = cached_resources.get(key).get('attached_to')[0]
                log_dict.update({'machine_id': machine_id})
            elif len(_patch.get('path').split('/')) < 3:  # '/id-external_id'
                if resource_type == 'machine':
                    action = 'destroy_machine'
                else:
                    action = 'delete_' + resource_type
                key = _patch.get('path')[1:]  # strip '/'
                if cached_resources.get(key) and \
                    cached_resources.get(key).get('state') == 'terminated' \
                        and action == 'destroy_machine':
                    from mist.api.clouds.models import Cloud
                    try:
                        cloud = Cloud.objects.get(id=cloud_id)
                    except Cloud.DoesNotExist:
                        log.error(f"Could not find cloud with id:{cloud_id}")
                        continue
                    if cloud.provider in config.PROVIDERS_WITH_TERMINATED_MACHINES_VISIBLE:  # noqa
                        continue
                ids = _patch.get('path').split('-')
                resource_id = ids.pop(0).strip('/')
                external_id = '-'.join(ids)
                if cached_resources.get(key):
                    name = cached_resources.get(key).get('name')
            else:
                continue

        elif _patch.get('op') == 'replace' and resource_type == 'machine':
            if '/state' in _patch.get('path') and \
               _patch.get('value') in ['running', 'stopped', 'terminated']:
                if _patch.get('value') == 'stopped':
                    action = 'stop_machine'
                elif _patch.get('value') == 'running':
                    action = 'start_machine'
                elif _patch.get('value') == 'terminated':
                    action = 'destroy_machine'
                if _patch['path'].endswith('/extra/state'):
                    key = _patch['path'][1:-len('/extra/state')]
                else:
                    key = _patch['path'][1:-len('/state')]
                name = cached_resources.get(key).get('name')
                ids = _patch.get('path').split('-')
                resource_id = ids.pop(0).strip('/')
                external_id = '-'.join(ids)[:-6]  # strip '/state'
            elif '/size' in _patch.get('path') and \
                    len(_patch.get('path').split('/')) < 4:
                action = 'resize_machine'
                ids = _patch.get('path').split('-')
                resource_id = ids.pop(0).strip('/')
                key = _patch.get('path')[1:-5]  # strip '/' and '/size'
                name = cached_resources.get(key).get('name')
                # do not produce observation log in case the machine.size
                # had not been set, most probably because there were no
                # CloudSize objects in the database
                if not cached_resources.get(key).get('size'):
                    continue
                external_id = '-'.join(ids)[:-5]  # strip '/size'
                log_dict.update({'new_size': _patch.get('value')})
            else:
                continue

        else:
            continue

        log_dict.update({'resource_type': resource_type,
                         resource_type + '_id': resource_id,
                         'name': name,
                         'external_id': external_id})
        if action == 'create_network':
            log_dict.update({
                'patch': _patch,
                'cached_resources': cached_resources,
                'new_resources': new_resources
            })
        log_event(action=action, event_type='observation',
                  owner_id=owner_id, **log_dict)
    return


def log_event(owner_id, event_type, action, error=None, **kwargs):
    """Log a new event.

    Log a new event comprised of the arguments provided.

    Once the new event has been prepared, additional processing is applied
    in order to associate any relevant stories, and, finally, it is pushed
    to RabbitMQ.

    Arguments:
        - owner_id: the current Owner's ID.
        - event_type: the event type - job, shell, session, request, incident.
        - action: the action described by the event, such as create_machine.
        - error: indicates the error included in the event, if one exists.
        - kwargs: extra parameters to be logged.

    """

    def _default(obj):
        return {'_python_object': str(obj)}

    try:
        # Prepare the base event to be logged.
        event = {
            'owner_id': owner_id or None,
            'log_id': uuid.uuid4().hex,
            'action': action,
            'type': event_type,
            'time': time.time(),
            'error': error if error else False,
            'extra': json.dumps(kwargs, default=_default)
        }

        # Bring more key-value pairs to the top level.
        for key in FIELDS:
            if key in kwargs:
                event[key] = kwargs.pop(key)

        if 'story_id' in kwargs:
            event['story_id'] = kwargs.pop('story_id')

        if 'user_id' in event:
            try:
                event['email'] = User.objects.get(id=event['user_id']).email
            except User.DoesNotExist:
                log.debug('User %s does not exist', event['user_id'])

        # Associate event with relevant stories.
        for key in ('job_id', 'shell_id', 'session_id', 'incident_id'):
            if key == 'session_id' and event_type != 'session':  # AB Testing.
                continue
            if event.get(key):
                event.update({'story_id': event[key], 'stories': []})
                associate_stories(event)
                break

        # Special case for closing stories unless an error has been raised,
        # such as PolicyUnauthorizedError.
        # TODO: Can be used to close any type of story, not only incidents.
        if action in ('close_story', ) and not error:
            story = ('closes', 'incident', event['story_id'])
            event.setdefault('stories', []).append(story)

        # Attempt to close open incidents.
        if action in CLOSES_INCIDENT:
            try:
                close_open_incidents(event)
            except Exception as exc:
                log_id = event.get('log_id')
                log.error('Log %s failed to close incidents: %r', log_id, exc)

        # Cross populate session-log data.
        try:
            cross_populate_session_data(event, kwargs)
        except Exception as exc:
            log.error('Failed to cross-populate log/session data: %s', exc)
    except Exception as exc:
        log.error('Failed to log event %s: %s', event, exc)
    else:
        # Construct RabbitMQ routing key.
        keys = [str(owner_id), str(event_type), str(action)]
        keys.append('true' if error else 'false')
        routing_key = '.'.join(map(str.lower, keys))

        # Broadcast event to RabbitMQ's "events" exchange.
        amqp_publish('events', routing_key, event,
                     ex_type='topic', ex_declare=True, auto_delete=False)

        event.pop('extra')
        event.update(kwargs)
        return event


def get_events(auth_context, owner_id='', user_id='', event_type='', action='',
               limit=0, start=0, stop=0, newest=True, error=None, **kwargs):
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

    # eliminate results with su
    if not is_admin:
        query["query"]["bool"]["must_not"] = {
            'term': {
                "su": "True"
            }
        }

    # Perform a complex "Query String" Query that may span fields.
    if 'filter' in kwargs:
        f = kwargs.pop('filter')
        query_string = {
            'query': f,
            'analyze_wildcard': True,
            'default_operator': 'and',
            'allow_leading_wildcard': False
        }
        query["query"]["bool"]["filter"]["bool"]["must"].append({
            'query_string': query_string
        })
    # Extend query with additional kwargs.
    for key, value in kwargs.items():
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {key: value}}
        )

    # Apply RBAC for non-Owners.
    if auth_context and not auth_context.is_owner():
        filter_logs(auth_context, query)

    # Query Elasticsearch.
    try:
        result = es().search(index=index, doc_type=event_type, body=query)
    except eexc.NotFoundError as err:
        log.error('Error %s during ES query: %s', err.status_code, err.info)
        raise NotFoundError(err.error)
    except (eexc.RequestError, eexc.TransportError) as err:
        log.error('Error %s during ES query: %s', err.status_code, err.info)
        raise BadRequestError(err.error)
    except (eexc.ConnectionError, eexc.ConnectionTimeout) as err:
        log.error('Error %s during ES query: %s', err.status_code, err.info)
        raise ServiceUnavailableError(err.error)

    for hit in result['hits']['hits']:
        event = hit['_source']
        if not event.get('action'):
            log.error('Skipped event %s, missing action', event['log_id'])
            continue
        try:
            extra = json.loads(event.pop('extra'))
        except Exception as exc:
            log.error('Failed to parse extra of event %s: %r', event, exc)
        else:
            for key, value in extra.items():
                event[key] = value
        yield event


def get_stories(story_type='', owner_id='', user_id='', sort_order=-1, limit=0,
                error=None, range=None, pending=None, expand=False,
                callback=None, es_async=False, **kwargs):
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
        includes = ["log_id", "stories", "error", "time", "job"]
        if story_type == "incident":
            includes += list(FIELDS) + ["action", "extra"]
    else:
        includes = []
        assert not es_async
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
                "size": limit or 10000
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
                            "excludes": [
                                "@version", "tags", "_traceback", "_exc"
                            ]
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
    for key, value in kwargs.items():
        if value in (None, ''):
            log.debug('Got key "%s" with empty value', key)
            continue
        query["query"]["bool"]["filter"]["bool"]["must"].append(
            {"term": {key: value}}
        )

    # Process returned stories.
    def _on_stories_callback(response):
        return process_stories(
            buckets=response["aggregations"]["stories"]["buckets"],
            callback=callback, type=story_type
        )

    # Fetch stories. Invoke callback to process and return results.
    def _on_request_callback(query):
        if es_async is False:
            result = es().search(index=index, doc_type=TYPES.get(story_type),
                                 body=query)
            return _on_stories_callback(result)
        else:
            async def search_async(query):
                result = await es_async.search(index=index,
                                               body=json.dumps(query),
                                               doc_type=TYPES.get(story_type))
                return _on_stories_callback(result)
            return search_async(query)

    # Process aggregation results in order to be applied as filters.
    def _on_filters_callback(response):
        filters = response["aggregations"]["main_bucket"]["buckets"]
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
                               es_async=es_async, **kwargs)
    else:
        return _on_request_callback(query)


def process_stories(buckets, type=None, callback=None):
    """Process fetched logs.

    Process results of Elasticsearch aggregations on logs in order to create
    stories.

    Arguments:
        - buckets: buckets of logs returned by Elasticsearch aggregations.
        - type: the story's type - one of (job, shell, session, incident).
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
            for key, value in body.items():
                if key in FIELDS and key not in story:
                    story[key] = value

            # Bring extra key-value pairs to the log's top level.
            if 'extra' in body:
                try:
                    extra = json.loads(body.pop('extra'))
                    for key, value in extra.items():
                        body[key] = value
                except Exception as exc:
                    log.error('Error parsing log %s: %s', body['log_id'], exc)

            # Provide the error message at the top level, if one occurred.
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
        return callback(stories)
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
    for name, filter in (("close", close), ("error", error)):
        stories = []
        if filter is not None:
            if name == "close":
                append_to = "must_not" if close else "must"
            if name == "error":
                append_to = "must_not" if not error else "must"
            for story in filters[name]["stories"]["buckets"]:
                if story["key"] in EXCLUDED_BUCKETS:
                    continue
                stories.append(story["key"])
            query["query"]["bool"]["filter"]["bool"][append_to].append(
                {"terms": {"stories": stories}}
            )


def create_stories_patch(auth_context, event):
    """Create a stories patch.

    Generates a patch based on the `stories` included in `event`, which
    describes the diff that should be applied on existing stories.

    Each patch is meant to either describe newly created stories or update
    existing ones simply based on a log entry's metadata.

    The patch's schema conforms with `jsonpatch` (http://jsonpatch.com/).

    """
    patch = []
    for action, stype, sid in event.get('stories', []):
        if not auth_context.is_owner() and stype != 'incident':
            continue
        if action == 'opens':
            story = {'error': event['error'],
                     'story_id': sid, 'type': stype,
                     'started_at': event['time'], 'finished_at': 0}
            # Add event fields that must be present in the story.
            for field in FIELDS:
                if field in event and field not in story:
                    story[field] = event[field]
            # Include the entire log entry only in case of incidents.
            if stype == 'incident':
                story['logs'] = [event]
            else:
                story['logs'] = [{'log_id': event['log_id']}]
            # Push an entirely new story as part of the patch.
            patch.append({'op': 'add',
                          'path': '/%ss/%s' % (stype, sid),
                          'value': story})
        else:
            # NOTE: The - character is used instead of an index to insert
            # an item at the end of an array.
            patch.append({'op': 'add',
                          'path': '/%ss/%s/logs/-' % (stype, sid),
                          'value': event['log_id']})
            if event['error']:
                patch.append({'op': 'replace',
                              'path': '/%ss/%s/error' % (stype, sid),
                              'value': event['error']})
            # If the latest log closes the story, instead of just updating
            # it, notify the client-side to atomically update the story's
            # finished_at timestamp, too.
            if action == 'closes':
                patch.append({'op': 'replace',
                              'path': '/%ss/%s/finished_at' % (stype, sid),
                              'value': event['time']})
    return patch


def associate_stories(event):
    """Associate potential stories to the event provided."""
    story_id = event['story_id']
    story_type = event['type'] if event['type'] != 'request' else 'job'
    job = event.get('job')
    if not job:
        try:
            job = json.loads(event['extra']).pop('job', None)
            event['job'] = job
        except Exception as exc:
            job = None
            log.warn('Failed to extract job param from extra: %s', exc)

    # Decide whether the event tends to open, update, or close a story.
    action = 'updates'
    if event['error']:
        action = 'closes'
    elif event['action'] in (a for v in JOBS.values() for a in v):
        if job in JOBS:
            action = 'closes'
    elif event['action'] in CLOSES_STORY:
        action = 'closes'
    elif event['action'] in STARTS_STORY:
        action = 'opens'

    # Append metadata to the event's `stories`.
    event['stories'].append((action, story_type, story_id))


def close_open_incidents(event):
    """Close any open incidents based on the event provided."""
    if event['error']:
        return
    if 'stories' not in event:
        event['stories'] = []
    kwargs = {
        'owner_id': event['owner_id'],
        'story_type': 'incident', 'pending': True,
    }
    for key in ('rule_id', 'cloud_id', 'machine_id', 'schedule_id',
                'zone_id', 'record_id', 'subnet_id', 'network_id',
                'script_id', 'stack_id', 'template_id', 'key_id',
                'volume_id', ):
        if key in event:
            kwargs[key] = event[key]
    incidents = get_stories(**kwargs)
    for inc in incidents:
        event['stories'].append(('closes', 'incident', inc['story_id']))
    log.warn('%s incident(s) closed by %s', len(incidents), event['log_id'])


def get_story(owner_id, story_id, story_type=None, expand=True):
    """Fetch a single story given its story_id."""
    assert story_id
    story = get_stories(owner_id=owner_id, stories=story_id,
                        story_type=story_type, expand=expand)
    if not story:
        msg = 'Story %s' % story_id
        if story_type:
            msg += ' [%s]' % story_type
        raise NotFoundError(msg)
    if len(story) > 1:
        log.error('Found multiple stories with story_id %s', story_id)
    return story[0]


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


def get_stream_uri(job_id):
    stream_uri = config.PORTAL_URI.replace('http', 'ws')
    stream_uri = '%s/stream/%s' % (
        stream_uri,
        job_id
    )
    log.info(stream_uri)
    return stream_uri
