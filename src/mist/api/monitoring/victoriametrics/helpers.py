import logging
import re
import ctypes
import os.path


log = logging.getLogger(__name__)


def round_base(x, precision, base):
    return round(base * round(float(x) / base), precision)


def generate_metric_mist(metric_dict, target=""):
    keys_ignore = set(['db', 'host', 'machine_id', '__name__'])
    metric = metric_dict.get('__name__', target)
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


def inject_promql_machine_id(query, machine_id):
    if not os.path.isfile('/promql_middleware.so'):
        raise RuntimeError("Could not find promql_middleware.so")
    so = ctypes.cdll.LoadLibrary(
        '/promql_middleware.so')
    process_promql_query = so.processPromqlQuery
    process_promql_query.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    process_promql_query.restype = ctypes.c_void_p
    free = so.free
    free.argtypes = [ctypes.c_void_p]
    ptr = process_promql_query(query.encode(
        'utf-8'), machine_id.encode('utf-8'),
        "".encode('utf-8'))
    filtered_query = ctypes.string_at(ptr)
    free(ptr)
    if not filtered_query:
        raise RuntimeError("Could not parse promql query")
    return filtered_query.decode('utf-8')
