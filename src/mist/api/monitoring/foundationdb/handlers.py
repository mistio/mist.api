"""Set of handlers to query from Foundationdb"""
from mist.api import config


def get_data(machine, start, stop, metrics):
    import fdb
    fdb.api_version(610)  # set api version for fdb
    import fdb.tuple
    import datetime

    # open db connection and create transaction
    db = fdb.open()

    print('Received machined Id:' + machine.id)
    print('Received metrics:' + str(metrics))

    datapoints = [[]]

    test_metric = config.FDB_BUILTIN_METRICS['system.load1']['name']

    data = {
        test_metric: {'name': test_metric, 'column': 'load1',
                      'measurement': 'system',
                      'datapoints': datapoints}
    }

    # get data frequency depending on time range
    time_range = stop - start
    time_range_in_hours = round(time_range.total_seconds() / 3600, 2)
    print('Time range is: ' + str(time_range_in_hours) + 'hours.')

    # if time range is less than an hour, we fetch the data per second
    if time_range_in_hours <= 1:
        data_freq = 's'
    # in a range greater than an hour we fetch data per minute
    elif time_range_in_hours > 1 and time_range_in_hours <= 3:
        data_freq = 'm'
    # in a range between 3 hours and 5 days
    elif time_range_in_hours > 3 and time_range_in_hours <= 120:
        data_freq = 'h'
    # in a range greater than 5
    elif time_range_in_hours > 120:
        data_freq = 'd'

    print('data frequency is:' + data_freq)

    # Open the monitoring directory if it exists
    if fdb.directory.exists(db, 'monitoring'):
        monitoring = fdb.directory.open(db, ('monitoring',))

        print('Start time for metrics:' + str(start))
        print('Stop time for metrics:' + str(stop))

        print('Keys in this timestamp range:')
        count = 0
        try:
            if data_freq == 's':
                print('fetching data per second..')

                # encode keys from start/stop params
                tuple_key_start = (machine.id, test_metric,
                                   start.year, start.month,
                                   start.day, start.hour,
                                   start.minute, start.second)

                tuple_key_stop = (machine.id, test_metric,
                                  stop.year, stop.month,
                                  stop.day, stop.hour,
                                  stop.minute, stop.second)

                key_timestamp_start = monitoring.pack(tuple_key_start)
                key_timestamp_stop = monitoring.pack(tuple_key_stop)

            elif data_freq == 'm':
                print('fetching data per minute..')

                #  open the subspace for metrics_per_minute
                metric_per_minute = monitoring['metric_per_minute']

                #  encode keys from start/stop params
                tuple_key_start = (machine.id, test_metric,
                                   start.year, start.month,
                                   start.day, start.hour, start.minute)

                tuple_key_stop = (machine.id, test_metric,
                                  stop.year, stop.month,
                                  stop.day, stop.hour, stop.minute)

                key_timestamp_start = metric_per_minute.pack(tuple_key_start)
                key_timestamp_stop = metric_per_minute.pack(tuple_key_stop)

            elif data_freq == 'h':
                #  open the subspace for metrics_per_minute
                metric_per_hour = monitoring['metric_per_hour']

                #  encode keys from start/stop params
                tuple_key_start = (machine.id, test_metric,
                                   start.year, start.month,
                                   start.day, start.hour)

                tuple_key_stop = (machine.id, test_metric,
                                  stop.year, stop.month,
                                  stop.day, stop.hour)

                key_timestamp_start = metric_per_hour.pack(tuple_key_start)
                key_timestamp_stop = metric_per_hour.pack(tuple_key_stop)
            # TODO data_Freq for days

            print('Start time tuple key:' + str(tuple_key_start))
            print('Stop time tuple key:' + str(tuple_key_stop))

            #  get the range
            for k, v in db[key_timestamp_start:key_timestamp_stop]:

                print(fdb.tuple.unpack(k), '=>', fdb.tuple.unpack(v))

                timestamp_keys = list(fdb.tuple.unpack(k))

                #  create the timestamp from the keys list
                if data_freq == 's':
                    timestamp_value = datetime.datetime(*timestamp_keys[3:9])
                elif data_freq == 'm':
                    timestamp_value = datetime.datetime(*timestamp_keys[4:9])
                elif data_freq == 'h':
                    timestamp_value = datetime.datetime(*timestamp_keys[4:8])

                timestamp_value = timestamp_value.timestamp()
                # convert the value tuple to list
                tuple_list = list(fdb.tuple.unpack(v))
                # append the timestamp string to the list
                tuple_list.append(str(int(timestamp_value)))
                # append value list to the datapoints list
                datapoints.insert(count, tuple_list)
                count += 1

        except fdb.FDBError as error:
            db.on_error(error).wait()
    else:
        print('The directory you are trying to read does not exist.')
    return data
