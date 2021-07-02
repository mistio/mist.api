import time
import logging

from mist.api import config

from mist.api.exceptions import NotFoundError, ServiceUnavailableError
from mist.api.exceptions import ForbiddenError

from mist.api.helpers import trigger_session_update

from mist.api.rules.tasks import add_nodata_rule

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine

from mist.api.monitoring.graphite.handlers import MultiHandler, get_multi_uuid


log = logging.getLogger(__name__)


def get_stats(machine, start="", stop="", step="", metrics=None):
    if not metrics:
        metrics = (list(config.GRAPHITE_BUILTIN_METRICS.keys()) +
                   machine.monitoring.metrics)
    old_targets = {
        'cpu': 'cpu.total.nonidle',
        'load': 'load.shorterm',
        'ram': 'memory.nonfree_percent',
        'disk-read': 'disk.total.disk_octets.read',
        'disk-write': 'disk.total.disk_octets.write',
        'network-rx': 'interface.total.if_octets.rx',
        'network-tx': 'interface.total.if_octets.tx',
    }
    targets = [old_targets.get(metric, metric) for metric in metrics]
    telegraf = machine.monitoring.method == 'telegraf-graphite'
    handler = MultiHandler(
        machine.id,
        telegraf=telegraf,
        telegraf_since=telegraf and machine.monitoring.method_since
    )
    data = handler.get_data(targets, start, stop, interval_str=step)
    for item in data:
        if item['alias'].rfind("%(head)s.") == 0:
            item['alias'] = item['alias'][9:]
    data = _clean_monitor_metrics(machine.owner, data)

    # set activated_at for collectd/telegraf installation status
    # if no data previously received for machine
    istatus = machine.monitoring.installation_status
    if not istatus.activated_at:
        for val in (point[0] for item in list(data.values())
                    for point in item['datapoints']
                    if point[1] >= istatus.started_at):
            if val is not None:
                if not istatus.finished_at:
                    istatus.finished_at = time.time()
                istatus.activated_at = time.time()
                istatus.state = 'succeeded'
                machine.save()
                add_nodata_rule.send(machine.owner.id)
                trigger_session_update(machine.owner, ['monitoring'])
                break

    return data


def _clean_monitor_metrics(owner, data):
    """Get a list of metric dicts as return by mist.monitor and return a dict
    of metric_id/metric data key/value pairs. Any extra metric keys such as
    data points are preserved"""

    def _clean_monitor_metric(owner, item):
        metric_id = item['alias']
        del item['alias']
        item['_target'] = item['target']
        del item['target']
        user_metrics = owner.get_metrics_dict()
        if metric_id in user_metrics:
            metric = user_metrics[metric_id]
            priority = -100
        elif metric_id in config.GRAPHITE_BUILTIN_METRICS:
            metric = config.GRAPHITE_BUILTIN_METRICS[metric_id]
            priority = -50
        else:
            return metric_id, item
        if metric.get('name'):
            item['name'] = metric['name']
        if metric.get('unit'):
            item['unit'] = metric['unit']
        if item['priority'] > priority:
            item['priority'] = priority
        return metric_id, item

    return dict([_clean_monitor_metric(owner, item) for item in data])


def find_metrics(machine):
    if not machine.monitoring.hasmonitoring:
        raise ForbiddenError("Machine doesn't have monitoring enabled.")
    metrics = MultiHandler(machine.id).find_metrics()
    for item in metrics:
        if item['alias'].rfind("%(head)s.") == 0:
            item['alias'] = item['alias'][9:]
    metrics = _clean_monitor_metrics(machine.owner, metrics)
    for metric_id in metrics:
        metrics[metric_id]['id'] = metric_id

    # # complex custom metrics won't appear unless manually added
    # for metric_id in machine.monitoring.metrics:
        # metric = user.metrics.get(metric_id, Metric())
        # log.warning("find_metrics manually adding complex custom metrics!")
        # if "%(head)s" in metrid_id:
        #     metrics.append({
        #         'metric_id': metric_id,
        #         'name': metric.name,
        #         'unit': metric.unit,
        #         '_target': metric_id,
        #         'max_value': None,
        #         'min_value': None,
        #         'priority': -100,
        #     })

    return metrics


def _get_multimachine_stats(owner, metric, start='', stop='', step='',
                            uuids=None):
    if not uuids:
        uuids = [machine.id for machine in Machine.objects(
            cloud__in=Cloud.objects(owner=owner, deleted=None),
            monitoring__hasmonitoring=True
        )]
    if not uuids:
        raise NotFoundError("No machine has monitoring enabled.")
    try:
        data = get_multi_uuid(uuids, metric, start=start, stop=stop,
                              interval_str=step)
    except Exception as exc:
        log.error("Error getting %s: %r", metric, exc)
        raise ServiceUnavailableError()
    ret = {}
    for item in data:
        target = item['target'].split('.')
        if len(target) > 1:
            uuid = target[1]
        else:
            uuid = target[0]
        item['name'] = uuid
        ret[uuid] = item
    return ret


def get_load(owner, start='', stop='', step='', uuids=None):
    return _get_multimachine_stats(
        owner, 'bucky.%(uuid)s.load.shortterm',
        start=start, stop=stop, step=step, uuids=uuids,
    )


def get_cores(owner, start='', stop='', step='', uuids=None):
    return _get_multimachine_stats(
        owner, 'groupByNode(bucky.%(uuid)s.cpu.*.system,1,"countSeries")',
        start=start, stop=stop, step=step, uuids=uuids,
    )
