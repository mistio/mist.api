from mist.api.monitoring.foundationdb.handlers import get_data
from mist.api.monitoring.helpers import parse_start_stop_params


def fdb_get_stats(machine, start, stop, step, metrics):
    time_params_array = parse_start_stop_params(start, stop)

    return get_data(machine, time_params_array[0],
                    time_params_array[1], metrics)
