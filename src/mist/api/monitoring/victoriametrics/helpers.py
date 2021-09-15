import logging
import re
import ctypes
import os.path

from prometheus_client.parser import text_string_to_metric_families


log = logging.getLogger(__name__)


def round_base(x, precision, base):
    return round(base * round(float(x) / base), precision)


def generate_metric_mist(metric_dict):
    keys_ignore = set(['db', 'host', 'machine_id', '__name__'])
    metric = metric_dict.get('__name__', "")
    labels = {key: value for key, value in metric_dict.items()
              if key not in keys_ignore}
    return generate_metric_promql(metric, labels)


def generate_metric_promql(metric, labels):
    if labels:
        processed_labels = ""
        sorted_keys = list(labels.keys())
        sorted_keys.sort()
        for key in sorted_keys:
            processed_labels += f"{key}=\"{labels[key]}\","
        processed_labels = processed_labels[:-1]
        metric += "{" + processed_labels + "}"
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
    if re.match(r'.*month.*', dt):
        dt = re.sub(r'month.*', '', dt)
        try:
            dt = int(dt) * 30
            dt = f"{dt}d"
        except ValueError:
            raise ValueError(
                "Could not convert 'month'" +
                " relative time to promql time syntax")
        return dt
    dt = re.sub(r's.*', 's', dt)
    dt = re.sub(r'm.*', 'm', dt)
    dt = re.sub(r'h.*', 'h', dt)
    dt = re.sub(r'd.*', 'd', dt)
    dt = re.sub(r'w.*', 'w', dt)
    dt = re.sub(r'y.*', 'y', dt)
    return dt


def parse_metric(metric):
    family = text_string_to_metric_families(metric + " 0")
    parsed_metric = next(family).samples[0]
    return parsed_metric.name, parsed_metric.labels


def calculate_time_args(start, stop, step):
    time_args = ""
    if start != "":
        time_args += f"&start={parse_relative_time(start)}"
    if stop != "":
        time_args += f"&end={parse_relative_time(stop)}"
    if step == "":
        time_args += "&step=5s"
    else:
        time_args += f"&step={parse_relative_time(step)}"
    return time_args


def apply_rbac(query, machine_ids):
    if not os.path.isfile('/promql_rbac.so'):
        return query
    so = ctypes.cdll.LoadLibrary(
        '/promql_rbac.so')
    apply_rbac_func = so.applyRBAC
    apply_rbac_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    apply_rbac_func.restype = ctypes.c_void_p
    free = so.free
    free.argtypes = [ctypes.c_void_p]
    ptr = apply_rbac_func(query.encode('utf-8'), machine_ids.encode('utf-8'))
    filtered_query = ctypes.string_at(ptr)
    free(ptr)
    if not filtered_query:
        raise RuntimeError("Could not parse promql query")
    return filtered_query.decode('utf-8')
