import copy
import logging

import mist.api.models
import mist.api.config as config
import mist.api.monitoring.methods

from mist.api.helpers import view_config
from mist.api.helpers import params_from_request
from mist.api.helpers import trigger_session_update

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import ForbiddenError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import UnauthorizedError
from mist.api.exceptions import MethodNotAllowedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.auth.methods import auth_context_from_request

from mist.api.clouds.models import Cloud
from mist.api.scripts.models import TelegrafScript
from mist.api.machines.models import Machine

from mist.api.clouds.methods import filter_list_clouds


log = logging.getLogger(__name__)


def _machine_from_matchdict(request, deleted=False):
    """Find machine given either uuid or cloud-id/ext-id in request path"""
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict.get(
        'cloud', request.matchdict.get('cloud_id', None))
    machine_id = request.matchdict.get(
        'machine', request.matchdict.get('machine_id', None))
    external_id = request.matchdict.get('external_id', machine_id)
    if cloud_id:
        try:
            if not deleted:
                cloud = Cloud.objects.get(owner=auth_context.owner,
                                          id=cloud_id,
                                          deleted=None)
            else:
                cloud = Cloud.objects.get(owner=auth_context.owner,
                                          id=cloud_id)
        except Cloud.DoesNotExist:
            raise NotFoundError('Cloud does not exist')
        try:
            machine = Machine.objects.get(
                cloud=cloud,
                external_id=external_id)
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" %
                                request.matchdict['machine'])
        # used by logging_view_decorator
    else:
        clouds = Cloud.objects(owner=auth_context.owner, deleted=None)
        try:
            machine = Machine.objects.get(
                cloud__in=clouds,
                id=machine_id,
            )
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" %
                                request.matchdict['machine'])

    # used by logging_view_decorator
    request.environ['cloud'] = machine.cloud.id
    request.environ['machine'] = machine.id
    request.environ['external_id'] = machine.external_id

    auth_context.check_perm('cloud', 'read', machine.cloud.id)
    return machine


@view_config(route_name='api_v1_home_dashboard',
             request_method='GET', renderer='json')
def home_dashboard(request):
    """
    Tags: monitoring
    ---
    Return home monitoring dashboard
    """
    auth_context_from_request(request)
    return copy.deepcopy(config.HOME_DASHBOARD_DEFAULT)


@view_config(route_name='api_v1_cloud_machine_dashboard',
             request_method='GET', renderer='json')
@view_config(route_name='api_v1_machine_dashboard',
             request_method='GET', renderer='json')
def machine_dashboard(request):
    """
    Tags: monitoring
    ---
    Return monitoring dashboard for a machine.
    READ permission required on cloud.
    READ permission required on machine.
    """
    machine = _machine_from_matchdict(request)
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")

    if machine.monitoring.method in ('telegraf-graphite'):
        if machine.os_type == "windows":
            ret = copy.deepcopy(config.WINDOWS_MACHINE_DASHBOARD_DEFAULT)
        else:
            ret = copy.deepcopy(config.GRAPHITE_MACHINE_DASHBOARD_DEFAULT)
    elif machine.monitoring.method in ('telegraf-tsfdb'):
        ret = copy.deepcopy(config.FDB_MACHINE_DASHBOARD_DEFAULT)
    elif machine.monitoring.method in ('telegraf-victoriametrics'):
        ret = copy.deepcopy(config.VICTORIAMETRICS_MACHINE_DASHBOARD_DEFAULT)
    else:
        ret = copy.deepcopy(config.INFLUXDB_MACHINE_DASHBOARD_DEFAULT)
    dashboard = ret['dashboard']
    for m in machine.monitoring.metrics:
        panels = dashboard['rows'][-1]['panels']
        panels.append({
            "id": len(panels),
            "title": m.replace('mist.python', '').replace('.', ' '),
            "type": "graph",
            "span": 6,
            "stack": False,
            "removable": True,
            "datasource": "mist.monitor",
            "targets": [{
                "refId": "m",
                "target": m
            }],
            "x-axis": True,
            "y-axis": True
        })
    for i in range(0, len(dashboard['rows'])):
        for j in range(0, len(dashboard['rows'][i]['panels'])):
            dashboard['rows'][i]['panels'][j]['machine'] = [machine.cloud.id,
                                                            machine.
                                                            external_id]
    return ret


# SEC FIXME check actual permission instead of owner
@view_config(route_name='api_v1_monitoring',
             request_method='GET', renderer='json')
def check_monitoring(request):
    """
    Tags: monitoring
    ---
    Return monitored machines and user details
    """
    auth_context = auth_context_from_request(request)
    if not auth_context.is_owner():
        raise UnauthorizedError()
    return mist.api.monitoring.methods.check_monitoring(auth_context.owner)


@view_config(route_name='api_v1_cloud_machine_monitoring',
             request_method='GET', renderer='json')
@view_config(route_name='api_v1_machine_monitoring',
             request_method='GET', renderer='json')
def show_monitoring_details(request):
    """
    Tags: monitoring
    ---
    Shows monitoring details for a machine"""
    auth_context = auth_context_from_request(request)
    machine = _machine_from_matchdict(request)
    # SEC require permission EDIT on machine
    auth_context.check_perm('machine', 'edit', machine.id)
    ret = machine.monitoring.get_commands()
    ret['rules'] = machine.monitoring.get_rules_dict()
    return ret


@view_config(route_name='api_v1_cloud_machine_monitoring',
             request_method='POST', renderer='json')
@view_config(route_name='api_v1_machine_monitoring',
             request_method='POST', renderer='json')
def update_monitoring(request):
    """
    Tags: monitoring
    ---
    Enable or disable monitoring for a machine
    ---
    machine:
      in: path
      type: string
      required: true
    action:
      enum:
      - enable
      - disable
      type: string
      required: true
    no_ssh:
      type: boolean
      default: false
    dry:
      type: boolean
      default: false

    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)
    no_ssh = bool(params.get('no_ssh'))
    dry = bool(params.get('dry'))
    action = params.get('action')
    if not action:
        raise RequiredParameterMissingError('action')

    if action == 'enable':
        machine = _machine_from_matchdict(request)
    elif action == 'disable':
        machine = _machine_from_matchdict(request, deleted=True)
    else:
        raise BadRequestError('Action must be one of (enable, disable)')

    # SEC require permission EDIT on machine
    auth_context.check_perm("machine", "edit", machine.id)

    if action == 'enable':
        return mist.api.monitoring.methods.enable_monitoring(
            owner=auth_context.owner, cloud_id=machine.cloud.id,
            machine_id=machine.id, no_ssh=no_ssh, dry=dry)
    elif action == 'disable':
        return mist.api.monitoring.methods.disable_monitoring(
            owner=auth_context.owner, cloud_id=machine.cloud.id,
            machine_id=machine.id, no_ssh=no_ssh)


@view_config(route_name='api_v1_monitoring',
             request_method='POST', renderer='json')
def update_monitoring_options(request):
    """
    Tags: monitoring
    ---
    Set global email alerts' recipients
    ---
    alerts_email:
      type: string
      description: One or more comma-separated e-mail addresses

    """
    auth_context = auth_context_from_request(request)
    emails = params_from_request(request).get('alerts_email', '')
    if not auth_context.is_owner():
        raise UnauthorizedError()
    return mist.api.monitoring.methods.update_monitoring_options(
        auth_context.owner, emails)


@view_config(route_name='api_v1_cloud_metrics',
             request_method='GET', renderer='json')
@view_config(route_name='api_v1_metrics',
             request_method='GET', renderer='json')
def find_metrics(request):
    """
    Tags: monitoring
    ---
    Get all metrics associated with specific machine.

    READ permission required on cloud.
    READ permission required on machine.

    ---

    resource_type:
      in: query
      required: false
      type: string

    id:
      in: query
      required: false
      type: string

    tags:
      in: query
      required: false
      type: string

    """

    auth_context = auth_context_from_request(request)

    params = params_from_request(request)
    resource_type = params.get('resource_type', '')
    resource_id = params.get('resource_id', '')
    tags = params.get('tags', '')

    if not (resource_type or resource_id or tags):
        raise BadRequestError(
            'At least one of (resource_type, resource_id, tags) required')

    # Convert the tag list to a dict
    if tags:
        tags = dict((key, value[0] if value else '')
                    for key, *value in (pair.split(':')
                                        for pair in tags.split(',')))

    return mist.api.monitoring.methods.find_metrics_by_attributes(
        auth_context, resource_id, resource_type, tags)


# SEC FIXME: (Un)deploying a plugin isn't the same as editing a custom metric.
# It actually deploys and runs code on the server, thus it should have its own
# permission that should work a bit like it does with scripts.
@view_config(route_name='api_v1_cloud_deploy_plugin',
             request_method='POST', renderer='json')
@view_config(route_name='api_v1_deploy_plugin',
             request_method='POST', renderer='json')
def deploy_plugin(request):
    """
    Tags: monitoring
    ---
    Deploy a custom plugin on a machine

    Adds a scripts, which is then deployed on the specified machine to collect
    custom metrics.

    READ permission required on cloud.
    EDIT_CUSTOM_METRICS permission required on machine.

    ---

    machine:
      in: path
      type: string
      required: true
      description: the UUID of the machine on which to deploy the custom script
    plugin:
      in: path
      type: string
      required: true
      description: the name of the custom plugin/script
    plugin_type:
      in: query
      type: string
      required: true
      description: the plugin's type, e.g. "python" for python scripts
    read_function:
      in: query
      type: string
      required: false
      description: the source code of the custom plugin/script
    value_type:
      in: query
      type: string
      default: gauge
      required: false
      description: the type of the computed value
    name:
      in: query
      type: string
      required: false
      description: the name of the resulted associated metric
    unit:
      in: query
      type: string
      required: false
      description: the unit of the resulted associated metric, e.g. "bytes"

    """
    auth_context = auth_context_from_request(request)
    machine = _machine_from_matchdict(request)
    params = params_from_request(request)

    name = request.matchdict['plugin']

    # SEC check permission EDIT_CUSTOM_METRICS on machine
    auth_context.check_perm('machine', 'edit_custom_metrics', machine.id)

    if not machine.monitoring.hasmonitoring:
        raise ForbiddenError("Machine doesn't seem to have monitoring enabled")

    # Prepare params
    kwargs = {
        'location_type': 'inline',
        'extra': {
            'value_type': params.get('value_type', 'gauge'),
            'value_unit': params.get('unit', ''),
            'value_name': params.get('name', ''),
        },
        'script': params.get('read_function'),
        'description': 'python plugin'
    }

    # FIXME Telegraf can load any sort of executable, not just python scripts.
    if params.get('plugin_type') == 'python':
        # Add the script.
        script = TelegrafScript.add(auth_context.owner, name, **kwargs)
        # Deploy it.
        ret = script.ctl.deploy_and_assoc_python_plugin_from_script(machine)
        trigger_session_update(auth_context.owner, ['scripts'])
        return ret
    raise BadRequestError('Invalid plugin_type')


# SEC FIXME: (Un)deploying a plugin isn't the same as editing a custom metric.
# It actually deploys and runs code on the server, thus it should have its own
# permission that should work a bit like it does with scripts.
@view_config(route_name='api_v1_cloud_deploy_plugin',
             request_method='DELETE', renderer='json')
@view_config(route_name='api_v1_deploy_plugin',
             request_method='DELETE', renderer='json')
def undeploy_plugin(request):
    """
    Tags: monitoring
    ---
    Undeploy a custom plugin/script from a machine

    READ permission required on cloud
    EDIT_CUSTOM_METRICS permission required on machine

    ---

    machine:
      in: path
      type: string
      required: true
      description: the UUID of the machine to undeploy the custom script from
    plugin:
      in: path
      type: string
      required: true
      description: the name of the custom plugin/script
    plugin_type:
      in: query
      type: string
      required: true
      description: the plugin's type, e.g. "python" for python scripts

    """
    auth_context = auth_context_from_request(request)
    machine = _machine_from_matchdict(request)
    params = params_from_request(request)

    plugin_id = request.matchdict['plugin']

    # SEC check permission EDIT_CUSTOM_METRICS on machine
    auth_context.check_perm('machine', 'edit_custom_metrics', machine.id)

    if not machine.monitoring.hasmonitoring:
        raise ForbiddenError("Machine doesn't seem to have monitoring enabled")

    # Undeploy executable.
    # FIXME Is the following check really necessary?
    if params.get('plugin_type') == 'python':
        return mist.api.monitoring.methods.undeploy_python_plugin(machine,
                                                                  plugin_id)
    raise BadRequestError('Invalid plugin_type')


@view_config(route_name='api_v1_metric', request_method='PUT', renderer='json')
def update_metric(request):
    """
    Tags: monitoring
    ---
    Update a metric configuration

    READ permission required on cloud
    EDIT_CUSTOM_METRICS permission required on machine

    ---

    metric:
      in: path
      type: string
      required: true
    cloud:
      in: query
      type: string
    machine:
      in: query
      type: string
    extermal_id:
      in: query
      type: string
    name:
      in: query
      type: string
    unit:
      in: query
      type: string

    """
    auth_context = auth_context_from_request(request)

    metric_id = request.matchdict['metric']

    params = params_from_request(request)
    name = params.get('name')
    unit = params.get('unit')
    cloud_id = params.get('cloud', params.get('cloud_id'))
    machine_id = params.get('machine', params.get('machine_id'))
    external_id = params.get('external_id')

    # FIXME This doesn't seem right. Perhaps we should always `update_metric`
    # and optionally `associate_metric` if machine_id and cloud_id have been
    # provided. However, we already have a discrete `associate_metric` API
    # endpoint.
    if cloud_id or machine_id:
        try:
            machine = Machine.objects.get(cloud=cloud_id,
                                          external_id=external_id,
                                          owner=auth_context.org)
        except Machine.DoesNotExist:
            machine = Machine.objects.get(id=machine_id,
                                          owner=auth_context.org)

        # used by logging_view_decorator
        request.environ['cloud'] = machine.cloud.id
        request.environ['machine'] = machine.id
        request.environ['external_id'] = machine.external_id

        # Check permissions.
        auth_context.check_perm('cloud', 'read', cloud_id)
        auth_context.check_perm('machine', 'edit_custom_metrics', machine.id)

        # Associate metric.
        mist.api.monitoring.methods.associate_metric(
            auth_context.owner, cloud_id, machine_id, metric_id
        )
    else:
        # FIXME Shouldn't be restricted to Owners.
        if not auth_context.is_owner():
            raise UnauthorizedError()
        # Update metric information.
        mist.api.monitoring.methods.update_metric(
            auth_context.owner, metric_id, name=name, unit=unit
        )
    return {}


@view_config(route_name='api_v1_cloud_metrics',
             request_method='PUT', renderer='json')
@view_config(route_name='api_v1_machine_metrics',
             request_method='PUT', renderer='json')
def associate_metric(request):
    """
    Tags: monitoring
    ---
    Associate a new metric to a machine.
    READ permission required on cloud.
    EDIT_GRAPHS permission required on machine
    ---
    machine:
      in: path
      type: string
      required: true
    metric_id:
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)
    machine = _machine_from_matchdict(request)

    # SEC require permission EDIT_GRAPHS on machine
    auth_context.check_perm("machine", "edit_graphs", machine.id)

    params = params_from_request(request)
    metric_id = params.get('metric_id')
    if not metric_id:
        raise RequiredParameterMissingError('metric_id')

    metric = mist.api.monitoring.methods.associate_metric(machine, metric_id)
    return metric.as_dict()


@view_config(route_name='api_v1_cloud_metrics',
             request_method='DELETE', renderer='json')
@view_config(route_name='api_v1_machine_metrics',
             request_method='DELETE', renderer='json')
def disassociate_metric(request):
    """
    Tags: monitoring
    ---
    Disassociate a metric from a machine.
    READ permission required on cloud.
    EDIT_GRAPHS permission required on machine
    ---
    machine:
      in: path
      type: string
      required: true
    metric_id:
      type: string
      required: true
    """
    auth_context = auth_context_from_request(request)
    machine = _machine_from_matchdict(request)

    # SEC require permission EDIT_GRAPHS on machine
    auth_context.check_perm("machine", "edit_graphs", machine.id)

    params = params_from_request(request)
    metric_id = params.get('metric_id')
    if not metric_id:
        raise RequiredParameterMissingError('metric_id')

    mist.api.monitoring.methods.disassociate_metric(machine, metric_id)
    return {}


@view_config(route_name='api_v1_cloud_stats', request_method='GET',
             renderer='json')
@view_config(route_name='api_v1_stats',
             request_method='GET', renderer='json')
def get_stats(request):
    """
    Tags: monitoring
    ---
    Request monitoring data for a machine
    ---
    machine:
      in: path
      type: string
      required: true
    start:
      in: query
      type: string
      default: now
      required: false
      description: time (eg. '10s') since when to fetch stats
    stop:
      in: query
      type: string
      required: false
      description: time until when to fetch stats
    step:
      in: query
      type: string
      required: false
      description: step to fetch stats, used in aggregations
    metrics:
      in: query
      type: string
      required: false
    request_id:
      in: query
      type: string
      required: false
    monitoring_method:
      in: query
      type: string
      required: false

    """
    machine = _machine_from_matchdict(request)
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")

    # SEC require permission READ on machine
    auth_context = auth_context_from_request(request)
    auth_context.check_perm('machine', 'read', machine.id)

    params = params_from_request(request)
    start = params.get('start', '')
    stop = params.get('stop', '')
    step = params.get('step', '')
    monitoring_method = params.get('monitoring_method', '')
    try:
        metrics = params.getall('metrics')
    except:
        metrics = params.get('metrics')

    data = mist.api.monitoring.methods.get_stats(
        machine,
        start=start, stop=stop,
        step=step, metrics=metrics,
        monitoring_method=monitoring_method
    )
    data['request_id'] = params.get('request_id')
    return data


@view_config(route_name='api_v1_load', request_method='GET', renderer='json')
def get_load(request):
    """
    Tags: monitoring
    ---
    Request load data for all monitored machines
    ---
    start:
      in: query
      type: string
      default: now
      required: false
      description: time (eg. '10s') since when to fetch stats
    stop:
      in: query
      type: string
      required: false
      description: time until when to fetch stats
    step:
      in: query
      type: string
      required: false
      description: step to fetch stats, used in aggregations
    request_id:
      in: query
      type: string
      required: false

    """
    auth_context = auth_context_from_request(request)
    cloud_ids = [cloud['id'] for cloud in filter_list_clouds(auth_context)
                 if cloud['enabled']]
    uuids = [machine.id for machine in Machine.objects(
        cloud__in=cloud_ids, monitoring__hasmonitoring=True,
    ).only('id')]
    if not auth_context.is_owner():
        allowed_uuids = auth_context.get_allowed_resources(rtype='machines')
        uuids = set(uuids) & set(allowed_uuids)

    params = params_from_request(request)
    start = params.get('start', '')
    stop = params.get('stop', '')
    step = params.get('step', '')
    data = mist.api.monitoring.methods.get_load(auth_context.owner,
                                                start=start, stop=stop,
                                                step=step, uuids=uuids)
    data['request_id'] = params.get('request_id')
    return data
