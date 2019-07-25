from mist.api.monitoring.foundationdb.handlers import init_db_and_read_metrics
import datetime


def fdb_get_stats(machine, start, stop, step, metrics):
    time_params_array = parse_start_stop_params(start, stop)
    return init_db_and_read_metrics(machine, time_params_array, step, metrics)


"""Helper method which parses the start/stop params from timestamp to datetime
    or grabs the relative values depending
    on the param type(sec, min, hr, etc..).
"""


def parse_start_stop_params(start, stop):
    time_params = []

    # scenario 1 > receive start/stop as timestamp and convert to datettime
    # scenario 2 > relative values for time(min, s, h, etc..)
    if not start:
        start = datetime.datetime.now() - datetime.timedelta(minutes=10)
    else:
        start = datetime.datetime.fromtimestamp(int(start))

    if not stop:
        stop = datetime.datetime.now()
    else:
        stop = datetime.datetime.fromtimestamp(int(stop))

    # round down start and stop time
    start = start.replace(second=10, microsecond=0)
    stop = stop.replace(second=10, microsecond=0)

    time_params.append(start)
    time_params.append(stop)
    return time_params
