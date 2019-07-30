"""Set of helper methods for the monitoring classes"""
import datetime
import dateparser


def parse_start_stop_params(start, stop):
    """Helper method which parses the start/stop params
       from relative values(sec,min,hour, etc..) to datetime
       and returns them in an array.
    """

    time_params = []

    #  set start/stop params if not exist
    if not start:
        start = datetime.datetime.now() - datetime.timedelta(minutes=10)
    else:
        start = dateparser.parse(start)

    if not stop:
        stop = datetime.datetime.now()
    else:
        stop = dateparser.parse(stop)

    #  round down start and stop time
    start = start.replace(second=0, microsecond=0)
    stop = stop.replace(second=0, microsecond=0)

    #  add params to the array
    time_params.append(start)
    time_params.append(stop)

    return time_params
