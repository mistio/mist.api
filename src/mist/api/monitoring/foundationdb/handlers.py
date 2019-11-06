"""Set of handlers to query from Foundationdb"""
import fdb
import fdb.tuple
import datetime

fdb.api_version(610)


def create_key_tuple_second(time, machine, metric):
    return (
        machine,
        metric,
        time.year,
        time.month,
        time.day,
        time.hour,
        time.minute,
        time.second,
    )


def create_key_tuple_minute(time, machine, metric):
    return (
        machine,
        metric,
        time.year,
        time.month,
        time.day,
        time.hour,
        time.minute,
    )


def create_key_tuple_hour(time, machine, metric):
    return (
        machine,
        metric,
        time.year,
        time.month,
        time.day,
        time.hour,
    )


def create_timestamp_second(tuple_key):
    # The last 6 items of the tuple contain the date up to the second
    # (year, month, day, hour, minute, second)
    return int(datetime.datetime(*tuple_key[-6:]).timestamp())


def create_timestamp_minute(tuple_key):
    # The last 5 items of the tuple contain the date up to the minute
    # (year, month, day, hour, minute)
    return int(datetime.datetime(*tuple_key[-5:]).timestamp())


def create_timestamp_hour(tuple_key):
    # The last 4 items of the tuple contain the date up to the hour
    # (year, month, day, hour)
    return int(datetime.datetime(*tuple_key[-4:]).timestamp())


def create_start_stop_key_tuples(
    time_range_in_hours, monitoring, machine, metric, start, stop
):
    # if time range is less than an hour, we create the keys for getting the
    # datapoints per second
    if time_range_in_hours <= 1:
        return [
            monitoring.pack(create_key_tuple_second(start, machine, metric)),
            monitoring.pack(create_key_tuple_second(stop, machine, metric)),
        ]
    # in a range greater than an hour, we create the keys for getting the
    # summarizeddatapoints per minute
    elif 1 < time_range_in_hours <= 3:
        return [
            monitoring["metric_per_minute"].pack(
                create_key_tuple_minute(start, machine, metric)
            ),
            monitoring["metric_per_minute"].pack(
                create_key_tuple_minute(stop, machine, metric)
            ),
        ]
    # in a range between 3 hours and 5 days, we create the keys for getting
    # the summarized datapoints per hour
    elif 3 < time_range_in_hours <= 120:
        return [
            monitoring["metric_per_hour"].pack(
                create_key_tuple_hour(start, machine, metric)
            ),
            monitoring["metric_per_hour"].pack(
                create_key_tuple_hour(stop, machine, metric)
            ),
        ]
    else:
        print("error")
    # in a range greater than 5
    """elif time_range_in_hours > 120:"""


def create_timestamp(time_range_in_hours, tuple_key):
    # if time range is less than an hour, we create the timestamp per second
    if time_range_in_hours <= 1:
        timestamp = create_timestamp_second(tuple_key)
    # in a range greater than an hour, we create the timestamp per minute
    elif 1 < time_range_in_hours <= 3:
        timestamp = create_timestamp_minute(tuple_key)
    # in a range between 3 hours and 5 days, we create the timestamp per hour
    elif 3 < time_range_in_hours <= 120:
        timestamp = create_timestamp_hour(tuple_key)
    else:
        print("error")
    # in a range greater than 5
    """elif time_range_in_hours > 120:"""
    return timestamp


def create_datapoint(time_range_in_hours, tuple_value, tuple_key):
    timestamp = create_timestamp(time_range_in_hours, tuple_key)
    # if the range is less than an hour, we create the appropriate datapoint [value, timestamp]
    if time_range_in_hours <= 1:
        return [tuple_value[0], timestamp]
    # else we need to use the summarized values [sum, count, min, max]
    # and convert them to a datapoint [value, timestamp]
    else:
        sum_values = tuple_value[0]
        count = tuple_value[1]
        return [sum_values / count, timestamp]


def create_metric_data(metric, datapoints):
    """name is on get load is the machine_id we will see"""
    return {
        metric: {
            "id": metric,
            "name": metric,
            "column": metric,
            "measurement": "system",
            "datapoints": datapoints,
            "max_value": None,
            "min_value": None,
            "priority": 0,
            "unit": "",
        }
    }


def get_data(machines, start, stop, metrics):
    db = fdb.open()
    results = {}

    monitoring = None
    # Open the monitoring directory if it exists
    if fdb.directory.exists(db, "monitoring"):
        monitoring = fdb.directory.open(db, ("monitoring",))
    else:
        print("The directory you are trying to read does not exist.")
        return

    time_range = stop - start
    time_range_in_hours = round(time_range.total_seconds() / 3600, 2)
    print("Time range is: " + str(time_range_in_hours) + "hours.")

    print("Start time for metrics:" + str(start))
    print("Stop time for metrics:" + str(stop))

    for machine in machines:
        results_machine = {}
        for metric in metrics:
            datapoints = []
            (
                key_timestamp_start,
                key_timestamp_stop,
            ) = create_start_stop_key_tuples(
                time_range_in_hours, monitoring, machine, metric, start, stop
            )
            try:
                #  get the range
                for k, v in db[key_timestamp_start:key_timestamp_stop]:

                    tuple_key = list(fdb.tuple.unpack(k))
                    tuple_value = list(fdb.tuple.unpack(v))

                    datapoints.append(
                        create_datapoint(
                            time_range_in_hours, tuple_value, tuple_key
                        )
                    )

            except fdb.FDBError as error:
                db.on_error(error).wait()
            results_machine.update(create_metric_data(metric, datapoints))
        data_machine = {machine: results_machine}
        results.update(data_machine)
    return results


def create_metric(data_tuple):
    return {
        data_tuple[1] + "." +
        data_tuple[2]: {
            "id": data_tuple[1] + "." + data_tuple[2],
            "name": data_tuple[1] + "." + data_tuple[2],
            "column": data_tuple[1] + "." + data_tuple[2],
            "measurement": data_tuple[1] + "." + data_tuple[2],
            "max_value": None,
            "min_value": None,
            "priority": 0,
            "unit": "",
        }
    }


def get_metrics(machine):
    db = fdb.open()
    metrics = {}
    if fdb.directory.exists(db, "monitoring"):
        monitoring = fdb.directory.open(db, "monitoring")

        for k, v in db[monitoring["available_metrics"][machine].range()]:
            data_tuple = monitoring["available_metrics"][machine].unpack(k)
            metrics.update(create_metric(data_tuple))

    else:
        print("Machine doesn't have the metrics directory.")
        return

    return metrics
