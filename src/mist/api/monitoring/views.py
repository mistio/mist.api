import copy
import logging

import mist.api.config as config
import mist.api.monitoring.methods

from mist.api.helpers import view_config
from mist.api.helpers import params_from_request

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import ForbiddenError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import UnauthorizedError
from mist.api.exceptions import MethodNotAllowedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.auth.methods import auth_context_from_request

from mist.api.clouds.models import Cloud
from mist.api.scripts.models import CollectdScript
from mist.api.scripts.models import TelegrafScript
from mist.api.machines.models import Machine


log = logging.getLogger(__name__)


def _machine_from_matchdict(request):
    """Find machine given either uuid or cloud-id/ext-id in request path"""
    auth_context = auth_context_from_request(request)
    if 'cloud' in request.matchdict:
        try:
            cloud = Cloud.objects.get(owner=auth_context.owner,
                                      id=request.matchdict['cloud'],
                                      deleted=None)
        except Cloud.DoesNotExist:
            raise NotFoundError('Cloud does not exist')
        try:
            machine = Machine.objects.get(
                cloud=cloud,
                machine_id=request.matchdict['machine'],
                state__ne='terminated',
            )
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" %
                                request.matchdict['machine'])
    else:
        clouds = Cloud.objects(owner=auth_context.owner, deleted=None)
        try:
            machine = Machine.objects.get(
                cloud__in=clouds,
                id=request.matchdict['machine'],
                state__ne='terminated'
            )
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" %
                                request.matchdict['machine'])
    auth_context.check_perm('cloud', 'read', machine.cloud.id)
    return machine


@view_config(route_name='api_v1_home_dashboard',
             request_method='GET', renderer='json')
def home_dashboard(request):
    """Return home monitoring dashboard"""
    auth_context_from_request(request)
    return copy.deepcopy(config.HOME_DASHBOARD_DEFAULT)


@view_config(route_name='api_v1_cloud_machine_dashboard',
             request_method='GET', renderer='json')
@view_config(route_name='api_v1_machine_dashboard',
             request_method='GET', renderer='json')
def machine_dashboard(request):
    """Return monitoring dashboard for a machine

    READ permission required on cloud
    READ permission required on machine
    """
    machine = _machine_from_matchdict(request)
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")

    if machine.monitoring.method in ('collectd-graphite', 'telegraf-graphite'):
        if not config.HAS_CORE:
            raise Exception()
        if machine.os_type == "windows":
            ret = copy.deepcopy(config.WINDOWS_MACHINE_DASHBOARD_DEFAULT)
        else:
            ret = copy.deepcopy(config.GRAPHITE_MACHINE_DASHBOARD_DEFAULT)
    else:
        ret = copy.deepcopy(config.INFLUXDB_MACHINE_DASHBOARD_DEFAULT)
    dashboard = ret['dashboard']
    for m in machine.monitoring.metrics:
        panels = dashboard['rows'][0]['panels']
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
                                                            machine.machine_id]
    return ret


# SEC FIXME check actual permission instead of owner
@view_config(route_name='api_v1_monitoring',
             request_method='GET', renderer='json')
def check_monitoring(request):
    """Return monitored machines and user details"""
    auth_context = auth_context_from_request(request)
    if not auth_context.is_owner():
        raise UnauthorizedError()
    return mist.api.monitoring.methods.check_monitoring(auth_context.owner)


@view_config(route_name='api_v1_cloud_machine_monitoring',
             request_method='GET', renderer='json')
@view_config(route_name='api_v1_machine_monitoring',
             request_method='GET', renderer='json')
def show_monitoring_details(request):
    """Shows monitoring details for a machine"""
    auth_context = auth_context_from_request(request)
    machine = _machine_from_matchdict(request)
    # SEC require permission EDIT on machine
    auth_context.check_perm('machine', 'edit', machine.id)
    ret = machine.get_commands()
    ret['rules'] = machine.monitoring.get_rules_dict()
    return ret


@view_config(route_name='api_v1_cloud_machine_monitoring',
             request_method='POST', renderer='json')
@view_config(route_name='api_v1_machine_monitoring',
             request_method='POST', renderer='json')
def update_monitoring(request):
    """Enable or disable monitoring for a machine

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

    machine = _machine_from_matchdict(request)
    # SEC require permission EDIT on machine
    auth_context.check_perm("machine", "edit", machine.id)

    params = params_from_request(request)

    no_ssh = bool(params.get('no_ssh'))
    dry = bool(params.get('dry'))
    action = params.get('action')
    if not action:
        raise RequiredParameterMissingError('action')

    if action == 'enable':
        return mist.api.monitoring.methods.enable_monitoring(
            owner=auth_context.owner, cloud_id=machine.cloud.id,
            machine_id=machine.machine_id, no_ssh=no_ssh, dry=dry)
    elif action == 'disable':
        return mist.api.monitoring.methods.disable_monitoring(
            owner=auth_context.owner, cloud_id=machine.cloud.id,
            machine_id=machine.machine_id, no_ssh=no_ssh)
    else:
        raise BadRequestError('Action must be one of (enable, disable)')


@view_config(route_name='api_v1_monitoring',
             request_method='POST', renderer='json')
def update_monitoring_options(request):
    """Set global email alerts' recipients

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
    """Get metrics associated with a machine

    Get all metrics associated with specific machine.

    READ permission required on cloud.
    READ permission required on machine.

    ---

    machine:
      in: path
      required: true
      type: string

    """
    auth_context = auth_context_from_request(request)
    machine = _machine_from_matchdict(request)

    # SEC require permission READ on machine
    auth_context.check_perm("machine", "read", machine.id)

    return mist.api.monitoring.methods.find_metrics(machine)


# SEC FIXME: (Un)deploying a plugin isn't the same as editing a custom metric.
# It actually deploys and runs code on the server, thus it should have its own
# permission that should work a bit like it does with scripts.
@view_config(route_name='api_v1_cloud_deploy_plugin',
             request_method='POST', renderer='json')
@view_config(route_name='api_v1_deploy_plugin',
             request_method='POST', renderer='json')
def deploy_plugin(request):
    """Deploy a custom plugin on a machine

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
    extra = {'value_type': params.get('value_type', 'gauge'), 'value_unit': ''}
    kwargs = {
        'location_type': 'inline',
        'extra': extra,
        'script': params.get('read_function'),
        'description': 'python plugin'
    }

    # Get script class based on monitoring system
    if machine.monitoring.method == 'collectd-graphite':
        script_cls = CollectdScript
    else:
        script_cls = TelegrafScript

    # FIXME Telegraf can load any sort of executable, not just python scripts.
    if params.get('plugin_type') == 'python':
        # Add the script.
        script = script_cls.add(auth_context.owner, name, **kwargs)
        # Deploy it.
        ret = script.ctl.deploy_python_plugin(machine)
        # This will create/update the metric and associate it with the machine.
        mist.api.monitoring.methods.associate_metric(
            machine,
            ret['metric_id'],
            name=params.get('name', ''),
            unit=params.get('unit', ''),
        )
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
    """Undeploy a custom plugin/script from a machine

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
    """Update a metric configuration

    READ permission required on cloud
    EDIT_CUSTOM_METRICS permission required on machine

    ---

    metric:
      in: path
      type: string
      required: true
    cloud_id:
      in: query
      type: string
    machine_id:
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
    cloud_id = params.get('cloud_id')
    machine_id = params.get('machine_id')

    # FIXME This doesn't seem right. Perhaps we should always `update_metric`
    # and optionally `associate_metric` if machine_id and cloud_id have been
    # provided. However, we already have a discrete `associate_metric` API
    # endpoint.
    if cloud_id and machine_id:
        try:
            machine = Machine.objects.get(cloud=cloud_id,
                                          machine_id=machine_id)
            machine_uuid = machine.id
        except Machine.DoesNotExist:
            machine_uuid = ''
        # Check permissions.
        auth_context.check_perm('cloud', 'read', cloud_id)
        auth_context.check_perm('machine', 'edit_custom_metrics', machine_uuid)
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
@view_config(route_name='api_v1_metrics',
             request_method='PUT', renderer='json')
def associate_metric(request):
    """Associate a new metric to a machine

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
@view_config(route_name='api_v1_metrics',
             request_method='DELETE', renderer='json')
def disassociate_metric(request):
    """Disassociate a metric from a machine

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
    """Request monitoring data for a machine

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
    try:
        metrics = params.getall('metrics')
    except:
        metrics = params.get('metrics')

    data = mist.api.monitoring.methods.get_stats(machine,
                                                 start=start, stop=stop,
                                                 step=step, metrics=metrics)
    data['request_id'] = params.get('request_id')
    return data
