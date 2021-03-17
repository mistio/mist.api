import logging
import requests
import time
import json
import re
import ast
from mist.api.exceptions import ForbiddenError
from mist.api.exceptions import ServiceUnavailableError
from mist.api import config


log = logging.getLogger(__name__)


def round_base(x, precision, base):
    return round(base * round(float(x) / base), precision)


def generate_metric(metric_dict):
    keys_ignore = set(['db', 'host', 'machine_id', '__name__'])
    metric = metric_dict.get('__name__', "")
    keys_all = set(metric_dict.keys())
    keys_loop = keys_all - keys_ignore
    if len(keys_loop) != 0:
        metric += "{"
        for key in list(keys_loop):
            metric += f"{str(key)}='{str(metric_dict[key])}',"
        metric = metric.strip(',') + '}'
    return metric


def parse_value(value):
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def parse_relative_time(dt):
    dt = re.sub(r's.*', 's', dt)
    dt = re.sub(r'm.*', 'm', dt)
    dt = re.sub(r'h.*', 'h', dt)
    dt = re.sub(r'y.*', 'y', dt)
    return dt


def get_stats(machine, start="", stop="", step="", metrics=None):
    """
    TODO: If the number of data points requested is larger than N_max = 30000,
    the request to the database returns Error 422. Thus, for large Dt = |stop-start|, the
    step must be large enough so Dt/step < N_max. Currently, if one asks for data from 1year
    before via the UI, get_stats is not working.
    """
    querries = metrics
    data = {}
    time_arguments = ""
    if start != "":
        time_arguments += f"&start={parse_relative_time(start)}"
    if stop != "":
        time_arguments += f"&end={parse_relative_time(stop)}"
    if step == "":
        time_arguments += "&step=5s"
    else:
        time_arguments += f"&step={parse_relative_time(step)}"
    raw_machine_data_list = []
    for querry in querries:
        try:
            proc_quer = querry.format(machine_id=machine.id)
            url = "{VICTORIA_URI}/api/v1/query_range?query={querry}"
            url = url.format(VICTORIA_URI=config.VICTORIAMETRICS_URI,querry=proc_quer)+time_arguments
        except Exception as exc:
            log.error(
                'Got %r on get_stats for resource %s'
                % (exc, machine.id))
        try:
            # It is recommended to use 'post' intead of 'get' to avoid length limitations on the querries
            # Ref: https://github.com/prometheus/client_golang/issues/801
            raw_machine_data = requests.post(url, timeout=20)
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
        raw_machine_data_list.append(raw_machine_data)
    for raw_machine_data in raw_machine_data_list:
        for result in raw_machine_data.get('data', {}).get('result', {}):
            metric = generate_metric(result.get("metric", {}))
            data[metric] = {
                "name": metric,
                "datapoints": [[parse_value(val),
                                str(round_base(int(dt), 1, 5))]
                               for dt, val in result.get("values")]
            }
    if not isinstance(machine, str):
        # set activated_at for collectd/telegraf installation status
        # if no data previously received for machine
        from mist.api.helpers import trigger_session_update
        from mist.api.rules.tasks import add_nodata_rule

        istatus = machine.monitoring.installation_status
        if not istatus.activated_at:
            for val in (point[0] for item in list(data.values())
                        for point in item['datapoints']
                        if int(point[1]) >= istatus.started_at):
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

def get_load(org, machines, start, stop, step):
    ''' 
    Arguments 'org' and 'machines' are not used.
    '''
    time_arguments = ""
    if start != "":
        time_arguments += f"&start={parse_relative_time(start)}"
    if stop != "":
        time_arguments += f"&end={parse_relative_time(stop)}"
    if step == "":
        time_arguments += "&step=5s"
    else:
        time_arguments += f"&step={parse_relative_time(step)}"
    try:
        raw_load_data = requests.get(
            f"{config.VICTORIAMETRICS_URI}/api/v1/query_range?query="
            f"{{__name__=\"system_load1\"}}{time_arguments}", timeout=20)
    except Exception as exc:
        log.error(
            'Got %r on get_load for org %s'
            % (exc, org))
        raise ServiceUnavailableError()
    if not raw_load_data.ok:
        log.error('Got %d on get_load: %s',
                  raw_load_data.status_code, raw_load_data.content)
        raise ServiceUnavailableError()

    load_data = raw_load_data.json().get('data', {}).get('result')
    data = {}
    for point in load_data:
        machine_id = point.get('metric')['machine_id']
        metric = point.get('metric')['__name__']
        data[machine_id] = {
            "id": metric,
            "name": machine_id,
            "datapoints": [[parse_value(val),
                            round_base(int(dt), 1, 5)]
                           for dt, val in point.get("values")]
        }

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
