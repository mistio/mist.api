import uuid
import json
import logging

import mongoengine as me
from pyramid.response import Response

from mist.api import tasks

from mist.api.machines.models import Machine
from mist.api.scripts.models import Script, ExecutableScript
from mist.api.scripts.models import AnsibleScript

from mist.api.auth.methods import auth_context_from_request

from mist.api.exceptions import RequiredParameterMissingError, ForbiddenError
from mist.api.exceptions import BadRequestError, NotFoundError
from mist.api.exceptions import PolicyUnauthorizedError, UnauthorizedError

from mist.api.helpers import view_config, params_from_request
from mist.api.tasks import async_session_update
from mist.api.helpers import mac_verify

from mist.api.scripts.methods import filter_list_scripts

from mist.api.logs.methods import get_stories

from mist.api.tag.methods import add_tags_to_resource

from mist.api import config

OK = Response("OK", 200)
log = logging.getLogger(__name__)


@view_config(route_name='api_v1_scripts', request_method='GET',
             renderer='json')
def list_scripts(request):
    """
    Tags: scripts
    ---
    Lists user scripts.
    READ permission required on each script.
    ---
    """
    auth_context = auth_context_from_request(request)
    scripts_list = filter_list_scripts(auth_context)
    return scripts_list


# SEC
@view_config(route_name='api_v1_scripts', request_method='POST',
             renderer='json')
def add_script(request):
    """
    Tags: scripts
    ---
    Add script to user scripts.
    ADD permission required on SCRIPT
    ---
    name:
      type: string
      required: true
    script:
      type: string
      required: false
    script_inline:
      type: string
      required: false
    script_github:
      type: string
      required: false
    script_url:
      type: string
      required: false
    location_type:
      type: string
      required: true
    entrypoint:
      type: string
    exec_type:
      type: string
      required: true
    description:
      type: string
    extra:
      type: object
    """

    params = params_from_request(request)

    # SEC
    auth_context = auth_context_from_request(request)
    script_tags, _ = auth_context.check_perm("script", "add", None)

    kwargs = {}

    for key in ('name', 'script', 'location_type', 'entrypoint',
                'exec_type', 'description', 'extra', 'script_inline',
                'script_url', 'script_github'
                ):
        kwargs[key] = params.get(key)   # TODO maybe change this

    kwargs['script'] = choose_script_from_params(kwargs['location_type'],
                                                 kwargs['script'],
                                                 kwargs['script_inline'],
                                                 kwargs['script_url'],
                                                 kwargs['script_github'])
    for key in ('script_inline', 'script_url', 'script_github'):
        kwargs.pop(key)

    name = kwargs.pop('name')
    exec_type = kwargs.pop('exec_type')

    if exec_type == 'executable':
        script = ExecutableScript.add(auth_context.owner, name, **kwargs)
    elif exec_type == 'ansible':
        script = AnsibleScript.add(auth_context.owner, name, **kwargs)
    else:
        raise BadRequestError(
            "Param 'exec_type' must be in ('executable', 'ansible')."
        )

    # Set ownership.
    script.assign_to(auth_context.user)

    if script_tags:
        add_tags_to_resource(auth_context.owner,
                             [{'resource_type': 'script',
                               'resource_id': script.id}],
                             list(script_tags.items()))

    script = script.as_dict()

    if 'job_id' in params:
        script['job_id'] = params['job_id']
    async_session_update.send(auth_context.owner.id, ['scripts'])

    return script


# TODO this isn't nice
def choose_script_from_params(location_type, script,
                              script_inline, script_url,
                              script_github):
    if script != '' and script is not None:
        return script

    if location_type == 'github':
        return script_github
    elif location_type == 'url':
        return script_url
    else:
        return script_inline


# SEC
@view_config(route_name='api_v1_script', request_method='GET', renderer='json')
def show_script(request):
    """
    Tags: scripts
    ---
    Show script details and job history.
    READ permission required on script.
    ---
    script_id:
      type: string
      required: true
      in: path
    """
    script_id = request.matchdict['script']
    auth_context = auth_context_from_request(request)

    if not script_id:
        raise RequiredParameterMissingError('No script id provided')

    try:
        script = Script.objects.get(owner=auth_context.owner,
                                    id=script_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Script id not found')

    # SEC require READ permission on SCRIPT
    auth_context.check_perm('script', 'read', script_id)

    ret_dict = script.as_dict()
    jobs = get_stories('job', auth_context.owner.id, script_id=script_id)
    ret_dict['jobs'] = [job['job_id'] for job in jobs if job.get('job_id')]
    return ret_dict


@view_config(route_name='api_v1_script_file', request_method='GET',
             renderer='json')
def download_script(request):
    """
    Tags: scripts
    ---
    Download script file or archive.
    READ permission required on script.
    ---
    script_id:
      type: string
      required: true
      in: path
    """
    script_id = request.matchdict['script']
    auth_context = auth_context_from_request(request)

    if not script_id:
        raise RequiredParameterMissingError('No script id provided')

    try:
        script = Script.objects.get(owner=auth_context.owner,
                                    id=script_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Script id not found')

    # SEC require READ permission on SCRIPT
    auth_context.check_perm('script', 'read', script_id)
    try:
        file_kwargs = script.ctl.get_file()
    except BadRequestError():
        return Response("Unable to find: {}".format(request.path_info))
    return Response(**file_kwargs)


# SEC
@view_config(route_name='api_v1_script', request_method='DELETE',
             renderer='json')
def delete_script(request):
    """
    Tags: scripts
    ---
    Deletes script.
    REMOVE permission required on script.
    ---
    script_id:
      in: path
      required: true
      type: string
    """
    script_id = request.matchdict['script']
    auth_context = auth_context_from_request(request)

    if not script_id:
        raise RequiredParameterMissingError('No script id provided')

    try:
        script = Script.objects.get(owner=auth_context.owner, id=script_id,
                                    deleted=None)

    except me.DoesNotExist:
        raise NotFoundError('Script id not found')

    # SEC require REMOVE permission on script
    auth_context.check_perm('script', 'remove', script_id)

    script.ctl.delete()
    return OK


# SEC
@view_config(route_name='api_v1_scripts',
             request_method='DELETE', renderer='json')
def delete_scripts(request):
    """
    Tags: scripts
    ---
    Deletes multiple scripts.
    Provide a list of script ids to be deleted. The method will try to delete
    all of them and then return a json that describes for each script id
    whether or not it was deleted or the not_found if the script id could not
    be located. If no script id was found then a 404(Not Found) response will
    be returned.
    REMOVE permission required on each script.
    ---
    script_ids:
      required: true
      type: array
      items:
        type: string
    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    script_ids = params.get('script_ids', [])
    if type(script_ids) != list or len(script_ids) == 0:
        raise RequiredParameterMissingError('No script ids provided')

    # remove duplicate ids if there are any
    script_ids = sorted(script_ids)
    i = 1
    while i < len(script_ids):
        if script_ids[i] == script_ids[i - 1]:
            script_ids = script_ids[:i] + script_ids[i + 1:]
        else:
            i += 1

    report = {}
    for script_id in script_ids:
        try:
            script = Script.objects.get(owner=auth_context.owner,
                                        id=script_id, deleted=None)
        except me.DoesNotExist:
            report[script_id] = 'not_found'
            continue
        # SEC require REMOVE permission on script
        try:
            auth_context.check_perm('script', 'remove', script_id)
        except PolicyUnauthorizedError:
            report[script_id] = 'unauthorized'
        else:
            script.ctl.delete()
            report[script_id] = 'deleted'
        # /SEC

    # if no script id was valid raise exception
    if len([script_id for script_id in report
            if report[script_id] == 'not_found']) == len(script_ids):
        raise NotFoundError('No valid script id provided')
    # if user was not authorized for any script raise exception
    if len([script_id for script_id in report
            if report[script_id] == 'unauthorized']) == len(script_ids):
        raise UnauthorizedError("You don't have authorization for any of these"
                                " scripts")
    return report


# SEC
@view_config(route_name='api_v1_script', request_method='PUT', renderer='json')
def edit_script(request):
    """
    Tags: scripts
    ---
    Edit script (rename only as for now).
    EDIT permission required on script.
    ---
    script_id:
      in: path
      required: true
      type: string
    new_name:
      type: string
      required: true
    new_description:
      type: string
    """
    script_id = request.matchdict['script']
    params = params_from_request(request)
    new_name = params.get('new_name')
    new_description = params.get('new_description')

    auth_context = auth_context_from_request(request)
    # SEC require EDIT permission on script
    auth_context.check_perm('script', 'edit', script_id)
    try:
        script = Script.objects.get(owner=auth_context.owner,
                                    id=script_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Script id not found')

    if not new_name:
        raise RequiredParameterMissingError('No new name provided')

    script.ctl.edit(new_name, new_description)
    ret = {'new_name': new_name}
    if isinstance(new_description, str):
        ret['new_description'] = new_description
    return ret


# SEC
@view_config(route_name='api_v1_script', request_method='POST',
             renderer='json')
def run_script(request):
    """
    Tags: scripts
    ---
    Start a script job to run the script.
    READ permission required on cloud.
    RUN_SCRIPT permission required on machine.
    RUN permission required on script.
    ---
    script:
      in: path
      required: true
      type: string
    machine:
      required: true
      type: string
    params:
      type: string
    su:
      type: boolean
    env:
      type: string
    job:
      type: string
    """
    script_id = request.matchdict['script']
    params = params_from_request(request)
    script_params = params.get('params', '')
    su = params.get('su', False)
    env = params.get('env')
    job_id = params.get('job', params.get('job_id', None))
    run_async = params.get('async', True)
    if not job_id:
        job = 'run_script'
        job_id = uuid.uuid4().hex
    else:
        job = None
    if isinstance(env, dict):
        env = json.dumps(env)
    auth_context = auth_context_from_request(request)
    cloud_id = params.get('cloud', params.get('cloud_id', None))
    external_id = params.get('external_id', None)
    machine_id = params.get('machine', params.get('machine_id', None))
    if machine_id:
        try:
            machine = Machine.objects.get(id=machine_id,
                                          state__ne='terminated',
                                          owner=auth_context.org)
        except me.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % machine_id)
        cloud_id = machine.cloud.id
    else:
        cloud_id = params.get('cloud_id')
        external_id = params.get('external_id')
        if not cloud_id:
            raise RequiredParameterMissingError('cloud')
        if not external_id:
            raise RequiredParameterMissingError('external_id')
        try:
            machine = Machine.objects.get(cloud=cloud_id,
                                          external_id=external_id,
                                          state__ne='terminated',
                                          owner=auth_context.org)
        except me.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % machine_id)

    # used by logging_view_decorator
    request.environ['cloud'] = cloud_id
    request.environ['machine'] = machine.id
    request.environ['external_id'] = machine.external_id

    # SEC require permission READ on cloud
    auth_context.check_perm("cloud", "read", cloud_id)
    # SEC require permission RUN_SCRIPT on machine
    auth_context.check_perm("machine", "run_script", machine.id)
    # SEC require permission RUN on script
    auth_context.check_perm('script', 'run', script_id)
    try:
        script = Script.objects.get(owner=auth_context.owner,
                                    id=script_id, deleted=None)
    except me.DoesNotExist:
        raise NotFoundError('Script id not found')
    job_id = job_id or uuid.uuid4().hex
    if run_async:
        tasks.run_script.send_with_options(
            args=(auth_context.serialize(), script.id, machine.id),
            kwargs={
                "params": script_params,
                "env": env,
                "su": su,
                "job_id": job_id,
                "job": job
            },
            delay=1_000
        )
    else:
        return tasks.run_script(
            auth_context.serialize(),
            script.id, machine.id,
            params=script_params, env=env,
            su=su, job=job, job_id=job_id)
    return {'job_id': job_id, 'job': job}


@view_config(route_name='api_v1_script_url', request_method='GET',
             renderer='json')
def url_script(request):
    """
    Tags: scripts
    ---
    Returns to a mist authenticated user,
    a self-auth/signed url for fetching a script's file.
    READ permission required on script.
    ---
    script_id:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    script_id = request.matchdict['script']

    try:
        script = Script.objects.get(owner=auth_context.owner,
                                    id=script_id, deleted=None)
    except Script.DoesNotExist:
        raise NotFoundError('Script does not exist.')

    # SEC require READ permission on script
    auth_context.check_perm('script', 'read', script_id)
    r_url = script.ctl.generate_signed_url()

    return r_url


@view_config(route_name='api_v1_fetch', request_method='GET', renderer='json')
def fetch(request):
    """
    A generic API endpoint to perform actions in the absence of AuthContext.
    The request's params are HMAC-verified and the action performed is based
    on the context of the params provided
    ---
    action:
      in: path
      required: true
      type: string
    """
    params = params_from_request(request)

    if not isinstance(params, dict):
        params = dict(params)

    try:
        mac_verify(params)
    except Exception as exc:
        raise ForbiddenError(exc.args)

    action = params.get('action', '')
    if not action:
        raise RequiredParameterMissingError('No action specified')

    if action == 'vpn_script':
        if config.HAS_VPN:
            from mist.vpn.views import fetch_vpn_script
        else:
            raise NotImplementedError()
        return fetch_vpn_script(params.get('object_id'))
    elif action == 'fetch_script':
        try:
            script = Script.objects.get(
                id=params.get('object_id'), deleted=None)
        except Script.DoesNotExist:
            raise NotFoundError('Script does not exist')
        file_kwargs = script.ctl.get_file()
        return Response(**file_kwargs)
    else:
        raise NotImplementedError()
