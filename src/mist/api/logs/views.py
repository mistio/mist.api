import datetime

from pyramid.response import Response

from mist.api.helpers import view_config
from mist.api.helpers import params_from_request
from mist.api.helpers import trigger_session_update

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import PolicyUnauthorizedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.logs.constants import FIELDS as _FIELDS
from mist.api.logs.methods import get_story
from mist.api.logs.methods import log_event
from mist.api.logs.methods import get_events
from mist.api.auth.methods import auth_context_from_request

from mist.api import config


FIELDS = list(_FIELDS) + ['action', 'filter']
FIELDS.remove('owner_id')  # SEC

LOG_TYPES = ('ui', 'job', 'shell', 'session', 'incident', 'request', )


@view_config(route_name='api_v1_logs', request_method='GET', renderer='json')
def get_logs(request):
    """
    Tags: logs+stories
    ---
    Gets the latest logs.
    ---
    event_type:
      type: string
      required: false
      description: the type of the events to fetch - one of LOG_TYPES or None
    action:
      type: string
      required: false
      description: the action described by the log
    newest:
      type: boolean
      required: false
      description: the sorting order
    error:
      type: boolean
      required: false
      description: specify whether to fetch logs that contain an error message
    limit:
      type: integer
      required: false
      description: limit the number of logs returned
    start:
      type: integer
      required: false
      description: the timestamp of the first log
    stop:
      type: integer
      required: false
      description: the timestamp of the last log in the sequence
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)

    kwargs = {}
    # Get the type of the events to fetch.
    event_type = params.get('type', params.get('event_type'))
    if event_type:
        if event_type not in LOG_TYPES:
            raise BadRequestError('Invalid event type: %s' % event_type)
        kwargs['event_type'] = event_type

    # Specify ordering and whether to fetch stories that ended with an error.
    for key in ('error', 'newest', ):
        value = params.get(key)
        if value is None:
            continue
        if value is False or value in ('false', 'False', '0', ):
            kwargs[key] = False
        else:
            kwargs[key] = True

    # Specify start/stop timestamps and limit the number of returned results.
    for key in ('start', 'stop', 'limit', ):
        if key in params:
            try:
                kwargs[key] = int(params[key])
            except ValueError:
                raise BadRequestError('Invalid value: %s=%s' % (key,
                                                                params[key]))
    if not 0 < kwargs.get('limit', 0) <= 100:
        kwargs['limit'] = 100

    # Provide additional key-value pairs.
    for key in FIELDS:
        if key in params:
            kwargs[key] = params[key]

    # Enforce owner_id, if necessary.
    if auth_context.user.role == 'Admin':
        if 'owner_id' in params:
            kwargs['owner_id'] = params['owner_id']
    else:
        kwargs['owner_id'] = auth_context.owner.id

    return list(get_events(auth_context, **kwargs))


# TODO: Do not use only for incidents.
@view_config(
    route_name='api_v1_story', request_method='DELETE', renderer='json')
def close_story(request):
    """
    Tags: logs+stories
    ---
    Closes an open story.
    ---
    story_id:
      in: path
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)

    # Only available to Owners for now.
    if not auth_context.is_owner():
        raise PolicyUnauthorizedError("Only Owners may perform this action")

    # NOTE: The story is closed by the view's decorator logging the close_story
    # action with the given story_id. No additional method needs to be invoked.
    # The story's ID exists in path, but it is not used here. It is captured by
    # our decorator, when logging the API response.
    # story_id = request.matchdict['story']
    return Response('OK', 200)


# TODO: Permissions.
# TODO: This can be used to fetch any type of story.
@view_config(route_name='api_v1_job', request_method='GET', renderer='json')
def show_job(request):
    """
    Tags: logs+stories
    ---
    Fetches a story.
    ---
    job:
      in: path
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)
    job_id = request.matchdict['job']
    if not job_id:
        raise RequiredParameterMissingError('job_id')
    return get_story(auth_context.owner.id, job_id)


# TODO: Improve. Use it for more than just orchestration workflows.
@view_config(route_name='api_v1_job', request_method='DELETE', renderer='json')
def end_job(request):
    """
    Tags: logs+stories
    ---
    Ends a running job.
    Closes/ends an open job. This is very similar to the close_story API
    endpoint. However, this endpoint may be used to perform additional
    actions upon closing an open story.
    ---
    job_id:
      in: path
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)

    if config.HAS_ORCHESTRATION:
        from mist.orchestration.models import Stack
        from mist.orchestration.methods import finish_workflow
    else:
        raise NotImplementedError()

    job_id = request.matchdict['job']
    job = get_story(auth_context.owner.id, job_id)  # Raises NotFoundError.

    stack_id = job['logs'][0].get('stack_id')
    workflow = job['logs'][0].get('workflow', 'install')
    try:
        stack = Stack.objects.get(owner=auth_context.owner,
                                  id=stack_id, deleted=None)
    except Stack.DoesNotExist:
        raise NotFoundError('Stack does not exist')

    if params.get('action', '') == 'cloud_init_finished':
        if not params.get('machine_name'):
            raise RequiredParameterMissingError('machine_name')
        try:
            error = bool(int(params.get('error')))
        except (TypeError, ValueError):
            raise RequiredParameterMissingError('error')
        # Log cloud-init's outcome. This is expected by the kubernetes
        # blueprint in order for execution to continue. The cloud-init
        # script POSTs back once it's done, since there is no other way
        # to know when it's finished running, especially in case there
        # is no SSH connectivity to the machine.
        log_event(
            job_id=job_id,
            workflow=workflow,
            stack_id=stack.id,
            owner_id=stack.owner.id,
            template_id=stack.template.id,
            machine_name=params['machine_name'], action=params['action'],
            event_type='job', error=error,
        )
    else:
        # Finish the workflow. Update the Stack and its status.
        finish_workflow(stack, job_id, workflow, params.get('exit_code'),
                        params.get('cmdout'), params.get('error'),
                        params.get('node_instances'), params.get('outputs'))

        # Delete the Stack, if it's been deleted, rather than just uninstalled.
        action = job['logs'][1].get('action', '')
        if workflow == 'uninstall' and action == 'delete_stack':
            stack.update(set__deleted=datetime.datetime.utcnow())
            trigger_session_update(auth_context.owner, ['stacks'])

    # FIXME:The MistClient expects a JSON-decodable response.
    # return Response('OK', 200)
    return {}
