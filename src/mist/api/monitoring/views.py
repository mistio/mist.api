import copy
import logging

from pyramid.response import Response

import mist.api.config as config
import mist.api.monitoring.methods

from mist.api.helpers import view_config
from mist.api.helpers import params_from_request

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import MethodNotAllowedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.auth.methods import auth_context_from_request

from mist.api.machines.models import Machine


log = logging.getLogger(__name__)


@view_config(route_name='api_v1_home_dashboard',
             request_method='GET', renderer='json')
def home_dashboard(request):
    """Return home monitoring dashboard"""
    auth_context_from_request(request)
    return copy.deepcopy(config.HOME_DASHBOARD_DEFAULT)


@view_config(route_name='api_v1_machine_dashboard',
             request_method='GET', renderer='json')
def machine_dashboard(request):
    """Return machine monitoring dashboard"""
    auth_context = auth_context_from_request(request)
    machine_uuid = request.matchdict['machine']

    try:
        machine = Machine.objects.get(id=machine_uuid)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine doesn't exist")
    if not machine.owner == auth_context.owner:
        raise NotFoundError("Machine doesn't exist")
    if not machine.monitoring.hasmonitoring:
        raise MethodNotAllowedError("Machine doesn't have monitoring enabled")

    ret = copy.deepcopy(config.MACHINE_DASHBOARD_DEFAULT)
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
                                                            machine.id]
    return ret


@view_config(route_name='api_v1_monitoring',
             request_method='GET', renderer='json')
def check_monitoring(request):
    """Return monitored machines and user details"""
    auth_context = auth_context_from_request(request)
    return mist.api.monitoring.methods.check_monitoring(auth_context.owner)


@view_config(route_name='api_v1_machine_monitoring',
             request_method='GET', renderer='json')
def show_monitoring_details(request):
    """Shows monitoring details for a machine"""
    auth_context = auth_context_from_request(request)
    machine_uuid = request.matchdict['machine']
    try:
        machine = Machine.objects.get(id=machine_uuid)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine doesn't exist")
    if machine.owner != auth_context.owner:
        raise NotFoundError("Machine doesn't exist")
    # Also includes monitoring rules in SaaS.
    return machine.monitoring.get_commands()


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
    machine_uuid = request.matchdict['machine']
    params = params_from_request(request)

    no_ssh = bool(params.get('no_ssh'))
    dry = bool(params.get('dry'))
    action = params.get('action')
    if not action:
        raise RequiredParameterMissingError('action')

    try:
        machine = Machine.objects.get(id=machine_uuid)
    except Machine.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_uuid)

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


@view_config(route_name='api_v1_metrics',
             request_method='GET', renderer='json')
def find_metrics(request):
    """Get metrics associated with a machine"""
    auth_context = auth_context_from_request(request)
    machine_uuid = request.matchdict['machine']
    return mist.api.monitoring.methods.find_metrics(auth_context.owner,
                                                    machine_uuid)


@view_config(route_name='api_v1_metrics',
             request_method='PUT', renderer='json')
def associate_metric(request):
    """Associate a new metric to a machine

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
    params = params_from_request(request)

    machine_uuid = request.matchdict['machine']
    metric_id = params.get('metric_id')
    if not metric_id:
        raise RequiredParameterMissingError('metric_id')

    metric = mist.api.monitoring.methods.associate_metric(
        auth_context.owner, machine_uuid, metric_id)
    return metric.as_dict()


@view_config(route_name='api_v1_metrics',
             request_method='DELETE', renderer='json')
def disassociate_metric(request):
    """Disassociate a metric from a machine

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
    params = params_from_request(request)

    machine_uuid = request.matchdict['machine']
    metric_id = params.get('metric_id')
    if not metric_id:
        raise RequiredParameterMissingError('metric_id')

    mist.api.monitoring.methods.disassociate_metric(
        auth_context.owner, machine_uuid, metric_id)
    return Response('OK', 200)


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
    auth_context = auth_context_from_request(request)
    machine_uuid = request.matchdict['machine']

    params = params_from_request(request)
    start = params.get('start', '')
    stop = params.get('stop', '')
    step = params.get('step', '')
    try:
        metrics = params.getall('metrics')
    except:
        metrics = params.get('metrics')
    try:
        machine = Machine.objects.get(id=machine_uuid,
                                      state__ne='terminated')
    except Machine.DoesNotExist:
        raise NotFoundError("Machine %s doesn't exist" % machine_uuid)

    data = mist.api.monitoring.methods.get_stats(owner=auth_context.owner,
                                                 cloud_id=machine.cloud.id,
                                                 machine_id=machine.id,
                                                 start=start, stop=stop,
                                                 step=step, metrics=metrics)
    data['request_id'] = params.get('request_id')
    return data
