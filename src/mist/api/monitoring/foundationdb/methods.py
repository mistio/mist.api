from mist.api.monitoring.foundationdb.handlers import get_data
import datetime
import dateparser


def fdb_get_stats(machine, start, stop, step, metrics):
    time_params_array = parse_start_stop_params(start, stop, step)
    return get_data(machine, time_params_array[0], time_params_array[1])


def parse_start_stop_params(start, stop, step):
    """Helper method which parses the start/stop params from relative values(sec,min,hour, etc..) to datetime
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
    
    # TODO > get time_range for step 
    """if not step:
        time_range = stop - start
        time_range_in_hours = time_range.total_seconds() / 3600 # get the time range in hours
        print('Time range is: ' + str(time_range_in_hours))
        
        if time_range_in_hours <= 1:
            step = 's' 
        elif time_range_in_hours > 1 and time_range_in_hours <= 3:
            step = 'm'
        print('Step is:' + step)"""
        

    # round down start and stop time
    start = start.replace(second=0, microsecond=0)
    stop = stop.replace(second=0, microsecond=0)

    time_params.append(start)
    time_params.append(stop)
    time_params.append(step)
    return time_params
