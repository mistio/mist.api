from mist.api.monitoring.foundationdb.handlers import get_data
import datetime
import dateparser


def fdb_get_stats(machine, start, stop, step, metrics):
    time_params_array = parse_start_stop_params(start, stop, step)
    return get_data(machine, time_params_array[0],
                    time_params_array[1], time_params_array[2])


def parse_start_stop_params(start, stop, step):
    """Helper method which parses the start/stop params
       from relative values(sec,min,hour, etc..) to datetime
       and returns them in an array.
    """

    time_params = []

    if not start:
        start = datetime.datetime.now() - datetime.timedelta(minutes=10)
    else:
        start = dateparser.parse(start)

    if not stop:
        stop = datetime.datetime.now()
    else:
        stop = dateparser.parse(stop)

    # get step depending on time range
    if not step:
        time_range = stop - start
        time_range_in_hours = int(time_range.total_seconds() / 3600)
        print('Time range is: ' + str(time_range_in_hours) + 'hours.')

        # if time range is less than an hour, we fetch the data per second
        if time_range_in_hours <= 1:
            step = 's'
        # in a range greater than an hour we fetch data per minute
        elif time_range_in_hours > 1:
            step = 'm'

    #  round down start and stop time
    start = start.replace(second=0, microsecond=0)
    stop = stop.replace(second=0, microsecond=0)

    #  add params to the array
    time_params.append(start)
    time_params.append(stop)
    time_params.append(step)

    return time_params
