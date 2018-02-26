import time

from mist.api import config

from mist.api.helpers import trigger_session_update

from mist.api.rules.tasks import add_nodata_rule

from mist.api.monitoring.graphite.handlers import MultiHandler


def graphite_get_stats(machine, start="", stop="", step="", metrics=None):
    if not metrics:
        metrics = (config.GRAPHITE_BUILTIN_METRICS.keys() +
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
    handler = MultiHandler(machine.id)
    data = handler.get_data(targets, start, stop, interval_str=step)
    for item in data:
        if item['alias'].rfind("%(head)s.") == 0:
            item['alias'] = item['alias'][9:]
    data = _clean_monitor_metrics(machine.owner, data)

    # set activated_at for collectd/telegraf installation status
    # if no data previously received for machine
    istatus = machine.monitoring.installation_status
    if not istatus.activated_at:
        for val in (point[0] for item in data.values()
                    for point in item['datapoints']
                    if point[1] >= istatus.started_at):
            if val is not None:
                if not istatus.finished_at:
                    istatus.finished_at = time.time()
                istatus.activated_at = time.time()
                istatus.state = 'succeeded'
                machine.save()
                add_nodata_rule.delay(machine.owner.id)
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
