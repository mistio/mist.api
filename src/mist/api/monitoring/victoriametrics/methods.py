import logging
import requests
import time

from mist.api.exceptions import ForbiddenError
from mist.api.exceptions import ServiceUnavailableError
from mist.api import config
from mist.api.monitoring.victoriametrics.helpers import (
    generate_metric_mist, generate_metric_promql, parse_metric,
    calculate_time_args, parse_value, round_base)


log = logging.getLogger(__name__)


def get_stats(machine, start="", stop="", step="", metrics=None):
    data = {}
    time_args = calculate_time_args(start, stop, step)
    if not metrics:
        metrics = list(find_metrics(machine).keys())
    if not isinstance(metrics, list):
        metrics = [metrics]
    raw_machine_data_list = []
    use_deriv = False
    for metric in metrics:
        metric_name, labels = parse_metric(metric)
        labels["machine_id"] = machine.id
        metric_promql = generate_metric_promql(metric_name, labels)
        use_deriv = metric_name.startswith(
            ("diskio", "net")) and not metric_name.startswith(
                "diskio_iops_in_progress")
        if use_deriv:
            query = f"rate({metric_promql})"
        else:
            query = metric_promql
        try:
            # Need to trim org due to 32 bit limitation of
            # the accountID on victoria metrics tenants
            uri = config.VICTORIAMETRICS_URI.replace(
                "<org_id>", str(int(machine.owner.id[:8], 16)))
            raw_machine_data = requests.get(
                f"{uri}/api/v1/query_range"
                f"?query={query}{time_args}", timeout=20)
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
        for result in raw_machine_data.get("data", {}).get("result", []):
            if result.get("metric"):
                if not result["metric"].get("__name__"):
                    result["metric"]["__name__"] = metric_name
        raw_machine_data_list.append(raw_machine_data)

    for raw_machine_data in raw_machine_data_list:
        for result in raw_machine_data.get('data', {}).get('result', {}):
            metric = generate_metric_mist(result.get("metric", {}))
            data[metric] = {
                "name": metric,
                "datapoints": [[parse_value(val),
                                str(dt)]
                               for dt, val in result.get("values")]
            }

    if not isinstance(machine, str):
        # set activated_at for collectd/telegraf installation status
        # if no data previously received for machine
        from mist.api.monitoring.methods import notify_machine_monitoring
        from mist.api.rules.tasks import add_nodata_rule

        istatus = machine.monitoring.installation_status
        if not istatus.activated_at:
            for val in (point[0] for item in list(data.values())
                        for point in item['datapoints']
                        if int(float(point[1])) >= istatus.started_at):
                if val is not None:
                    if not istatus.finished_at:
                        istatus.finished_at = time.time()
                    istatus.activated_at = time.time()
                    istatus.state = 'succeeded'
                    machine.save()
                    add_nodata_rule.send(machine.owner.id, 'victoriametrics')
                    notify_machine_monitoring(machine)
                    break

    return data


def find_metrics(machine):
    if not machine.monitoring.hasmonitoring:
        raise ForbiddenError("Machine doesn't have monitoring enabled.")
    try:
        uri = config.VICTORIAMETRICS_URI.replace(
            "<org_id>", str(int(machine.owner.id[:8], 16)))
        data = requests.get(
            f"{uri}/api/v1/series",
            params={"match[]": f"{{machine_id=\"{machine.id}\"}}"})
    except Exception as exc:
        log.error(
            'Got %r on find_metrics for resource %s'
            % (exc, machine.id))
        raise ServiceUnavailableError()

    if not data.ok:
        log.error('Got %d on find_metrics: %s',
                  data.status_code, data.content)
        raise ServiceUnavailableError()
    data = data.json().get("data")
    metrics = {}
    for raw_metric in data:
        metric = generate_metric_mist(raw_metric)
        metrics.update({metric: {"id": metric, "name": metric, "unit": ""}})

    return metrics


def get_load(org, machines, start, stop, step):
    data = {}
    time_args = calculate_time_args(start, stop, step)
    try:
        uri = config.VICTORIAMETRICS_URI.replace(
            "<org_id>", str(int(org.id[:8], 16)))
        raw_load_data = requests.get(
            f"{uri}/api/v1/query_range?query="
            f"{{__name__=\"system_load1\"}}{time_args}", timeout=20)
    except Exception as exc:
        log.error(
            'Got %r on get_load for org %s'
            % (exc, org))
        raise ServiceUnavailableError()

    if not raw_load_data.ok:
        log.error('Got %d on get_load: %s',
                  raw_load_data.status_code, raw_load_data.content)
        raise ServiceUnavailableError()

    raw_load_data = raw_load_data.json()
    for result in raw_load_data.get('data', {}).get('result', {}):
        machine_id = result.get("metric", {}).get("machine_id")
        data[machine_id] = {
            "id": "system_load1",
            "name": machine_id,
            "datapoints": [[parse_value(val),
                            round_base(int(dt), 1, 5)]
                           for dt, val in result.get("values")]
        }

    return data


def get_cores(org, machines, start, stop, step):
    if not machines:
        return {}
    data = {}
    time_args = calculate_time_args(start, stop, step)
    promql_machine_ids = ""
    for machine in machines:
        promql_machine_ids += machine + "|"
    promql_machine_ids = promql_machine_ids[:-1]
    try:
        uri = config.VICTORIAMETRICS_URI.replace(
            "<org_id>", str(int(org.id[:8], 16)))
        raw_machine_data = requests.get(
            f"{uri}/api/v1/query_range?query="
            f"count({{__name__=\"cpu_usage_idle\", cpu=~\"cpu[0-9]*\","
            f" machine_id=~\"{promql_machine_ids}\"}}) by (machine_id)"
            f"{time_args}", timeout=20)
    except Exception as exc:
        log.error(
            'Got %r on get_load for org %s'
            % (exc, org))
        raise ServiceUnavailableError()

    if not raw_machine_data.ok:
        log.error('Got %d on get_load: %s',
                  raw_machine_data.status_code, raw_machine_data.content)
        raise ServiceUnavailableError()

    raw_machine_data = raw_machine_data.json()
    results = raw_machine_data.get('data', {}).get('result', {})
    if not results:
        return {}

    for result in raw_machine_data.get('data', {}).get('result', {}):
        machine_id = result.get("metric", {}).get("machine_id")
        values = result.get("values", [])
        if not machine_id:
            continue
        values = [(int(value), int(dt)) for dt, value in values]
        data[machine_id] = {"datapoints": values}

    return data
