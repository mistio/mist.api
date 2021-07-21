import logging
import requests
import time
import urllib.parse
import json

from mist.api.exceptions import ForbiddenError
from mist.api.exceptions import ServiceUnavailableError
from mist.api import config


log = logging.getLogger(__name__)


def get_stats(machine, start="", stop="", step="", metrics=None):
    data = {}

    # If no metrics are specified, then we get all of them
    if not metrics:
        metrics = [('fetch(\"{id}.*\"' +
                    ', start=\"{start}\", stop=\"{stop}\"' +
                    ', step=\"{step}\")')]

    for metric in metrics:
        query = metric.format(id=machine.id, start=start, stop=stop, step=step)
        try:
            raw_machine_data = requests.get(
                "%s/v1/datapoints?query=%s"
                % (config.TSFDB_URI, urllib.parse.quote(query)),
                headers={'x-org-id': machine.owner.id}, timeout=20
            )
        except Exception as exc:
            log.error(
                'Got %r on get_stats for resource %s'
                % (exc, machine.id))
            raise ServiceUnavailableError()

        if not raw_machine_data.ok:
            log.error('Got %d on get_stats: %s',
                      raw_machine_data.status_code, raw_machine_data.content)
            raise ServiceUnavailableError()

        raw_machine_data = raw_machine_data.json()
        raw_metrics = list(raw_machine_data.get("series", {}).keys())
        for raw_metric in raw_metrics:
            # We use as key the metric name without the machine id
            # e.g "id.system.load1 => system.load1"
            _, returned_metric = raw_metric.split(".", 1)
            data.update(
                {
                    returned_metric: {
                        "name": returned_metric,
                        "datapoints": raw_machine_data["series"].get(
                            raw_metric, []),
                    }
                }
            )

    if not isinstance(machine, str):
        # set activated_at for collectd/telegraf installation status
        # if no data previously received for machine
        from mist.api.rules.tasks import add_nodata_rule
        from mist.api.monitoring.methods import notify_machine_monitoring

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
                    notify_machine_monitoring(machine)
                    break

    return data


def get_load(org, machines, start, stop, step):
    metric = "*.system.load1"
    query = ('topk(roundY(fetch("%s", start="%s", stop="%s", step="%s")' +
             ', base=5))') % \
        (
        metric,
        start,
        stop,
        step,
    )
    try:
        raw_machine_data = requests.get(
            "%s/v1/datapoints?query=%s" % (config.TSFDB_URI, query),
            headers={'x-org-id': org.id,
                     'x-allowed-resources': json.dumps(machines)},
            timeout=15
        )
    except Exception as exc:
        log.error(
            'Got %r on get_load' % exc)
        return {}

    if not raw_machine_data.ok:
        log.error('Got %d on get_load: %s',
                  raw_machine_data.status_code, raw_machine_data.content)
        return {}

    raw_machine_data = raw_machine_data.json()

    data = {}
    for metric in raw_machine_data["series"]:
        machine, _ = metric.split(".", 1)
        data.update(
            {
                machine: {
                    "name": machine,
                    "datapoints": raw_machine_data["series"].get(metric, []),
                }
            }
        )
    return data


def get_cores(org, machines, start, stop, step):

    metric = "*.cpu\.\d*.usage_idle"
    query = ('fetch("%s", start="%s", stop="%s", step="%s")') % \
        (
        metric,
        start,
        stop,
        step,
    )
    try:
        raw_machine_data = requests.get(
            "%s/v1/datapoints?query=%s" % (config.TSFDB_URI, query),
            headers={'x-org-id': org.id,
                     'x-allowed-resources': json.dumps(machines)},
            timeout=30
        )
    except Exception as exc:
        log.error(
            'Got %r on get_cores' % exc)
        return {}

    if not raw_machine_data.ok:
        log.error('Got %d on get_cores: %s',
                  raw_machine_data.status_code, raw_machine_data.content)
        return {}

    raw_machine_data = raw_machine_data.json()
    cores_datapoints = {}
    for machine_metric, datapoints in raw_machine_data["series"].items():
        machine, metric = machine_metric.split(".", 1)
        if not cores_datapoints.get(machine):
            cores_datapoints[machine] = {}
        for _, timestamp in datapoints:
            if not cores_datapoints[machine].get(timestamp):
                cores_datapoints[machine][timestamp] = set()
            cores_datapoints[machine][timestamp].add(metric)
    data = {}
    for machine, datapoints in cores_datapoints.items():
        data[machine] = {
            "datapoints": []
        }
        for timestamp, metrics in datapoints.items():
            data[machine]["datapoints"].append([len(metrics), timestamp])

    return data


def find_metrics(machine):
    if not machine.monitoring.hasmonitoring:
        raise ForbiddenError("Machine doesn't have monitoring enabled.")
    try:
        data = requests.get("%s/v1/resources/%s" %
                            (config.TSFDB_URI, machine.id),
                            headers={'x-org-id': machine.owner.id}, timeout=5)
    except Exception as exc:
        log.error(
            'Got %r on find_metrics for resource %s'
            % (exc, machine.id))
        raise ServiceUnavailableError()

    if not data.ok:
        log.error('Got %d on find_metrics: %s',
                  data.status_code, data.content)
        raise ServiceUnavailableError()

    return data.json().get("metrics", {})
