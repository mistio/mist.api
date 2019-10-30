import logging

from mist.api.monitoring.foundationdb.handlers import get_data, get_metrics
from mist.api.monitoring.helpers import parse_start_stop_params

from mist.api.exceptions import ForbiddenError


log = logging.getLogger(__name__)


def get_stats(machine, start, stop, step, metrics):
    time_params_array = parse_start_stop_params(start, stop)

    return get_data(
        [machine.id], time_params_array[0], time_params_array[1], metrics
    )[machine.id]


def get_load(machines, start, stop, step):
    time_params_array = parse_start_stop_params(start, stop)

    data = get_data(
        machines, time_params_array[0], time_params_array[1], ["system.load1"]
    )

    for machine in data.keys():
        data[machine] = data[machine]["system.load1"]
        data[machine]["name"] = machine

    return data


def find_metrics(machine):
    if not machine.monitoring.hasmonitoring:
        raise ForbiddenError("Machine doesn't have monitoring enabled.")
    return get_metrics(machine.id)
