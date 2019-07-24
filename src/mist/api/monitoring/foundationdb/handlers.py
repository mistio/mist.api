"""Set of handlers to query from Foundationdb"""

import fdb
fdb.api_version(610)  # set api version for fdb

import fdb.tuple
import datetime

MACHINE_ID = '6e2faf7bba844833841fe1e015afc841'
METRICS = 'system.load1'


def init_db_and_read_metrics(machine, start, stop, step, metrics):
    db = fdb.open()
    data = {}
    print('Receive machined Id:' + machine.id)
    # Open the monitoring directory
    if fdb.directory.exists(db, 'monitoring'):
        monitoring = fdb.directory.open(db, ('monitoring',))
        data = get_data(db, monitoring, machine.id, start, stop)
    else:
        print('The directory you are trying to read does not exist.')

    return data


@fdb.transactional
def get_data(tr, monitoring, machine_id, start, stop):
    datapoints = [[]]

    data = {'machine_id': machine_id, 'metrics': METRICS,
            'datapoints': datapoints}

    # set start and stop time if not set

    #scenario 1 > receive start/stop as a timestamp and convert them to datettimes
    #scenario 2 > relative values for time(min, s, h, etc..)
    if not start: start = datetime.datetime.now() - datetime.timedelta(minutes=10)
    if not stop: stop = datetime.datetime.now()
    
    # round down start and stop time
    start = start.replace(second = 10, microsecond=0)
    stop = stop.replace(second = 10, microsecond=0)

    print('Start time for metrics:' + str(start))
    print('Stop time for metrics:' + str(stop))

    #  create a tuple of keys and pack them for the start and stop  timestamp 

    tuple_key_start = (machine_id, METRICS, start.year, start.month,
                       start.day, start.hour, start.minute, start.second)
    tuple_key_stop =  (machine_id, METRICS, stop.year, stop.month,
                       stop.day, stop.hour, stop.minute, stop.second)   
    
    print('Start time for metrics:' + str(tuple_key_start))
    print('Stop time for metrics:' + str(tuple_key_stop))

    key_timestamp_start = monitoring.pack(tuple_key_start)
    
    key_timestamp_stop = monitoring.pack(tuple_key_stop)
       
    print('Keys in this timestamp range:')
    for k, v in tr[key_timestamp_start: key_timestamp_stop]:
        print(fdb.tuple.unpack(k), '=>', fdb.tuple.unpack(v))
    
    count = 0
    #  get the range 
    for k, v in tr.get_range(key_timestamp_start, key_timestamp_stop):
        # get the timestamp range[3:9] inside the keys
        timestamp_keys = list(fdb.tuple.unpack(k))
        timestamp_value = datetime.datetime(timestamp_keys[3],  # year
                                            timestamp_keys[4],  # month
                                            timestamp_keys[5],  # day
                                            timestamp_keys[6],  # hour
                                            timestamp_keys[7],  # minute
                                            timestamp_keys[8]).timestamp()  # second
        # convert the value tuple to list
        tuple_list = list(fdb.tuple.unpack(v))
        # append the timestamp string to the list
        tuple_list.append(str(int(timestamp_value)))
        # append value list to the datapoints list
        datapoints.insert(count, tuple_list)
        count += 1
        print('Datapoints:' + str(datapoints))
        print('Created data dictionary:' + str(data))
    return data
