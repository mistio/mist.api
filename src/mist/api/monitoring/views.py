import copy
import logging

import mist.api.config as config
import mist.api.monitoring.methods

from mist.api.helpers import view_config
from mist.api.helpers import params_from_request

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import UnauthorizedError
from mist.api.exceptions import MethodNotAllowedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.auth.methods import auth_context_from_request

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine

from mist.api.clouds.methods import filter_list_clouds


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
        clouds = Cloud.objects(owner=auth_context.owner)
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
    ret = machine.get_commands()
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


@view_config(route_name='api_v1_cloud_metrics',
             request_method='PUT', renderer='json')
@view_config(route_name='api_v1_metrics',
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
@view_config(route_name='api_v1_metrics',
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
