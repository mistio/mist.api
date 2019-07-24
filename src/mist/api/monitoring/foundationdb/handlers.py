"""Set of handlers to query from Foundationdb"""

import fdb
fdb.api_version(610)  # set api version for fdb

import fdb.tuple
import datetime
import random
import json


MACHINE_ID = '6e2faf7bba844833841fe1e015afc841'
METRICS = 'system.load1'


def init_db_and_read_metrics(machine, start, stop, step, metrics):
   db = fdb.open()
   data = {}
   print('Receive machined Id:' + machine.id)
   
   if fdb.directory.exists(db, 'monitoring'):
        monitoring = fdb.directory.open(db, ('monitoring',)) #Open the monitoring directory
        data = get_data(db, monitoring, machine.id, start, stop)
   else:
        print('The directory you are trying to read does not exist.')

   return data


@fdb.transactional
def get_data(tr, monitoring, machine_id, start, stop):
    datapoints = [[]]

    data = {'machine_id': machine_id, 'metrics': METRICS, 'datapoints': datapoints}
    # if not start: start = -10
    # if not stop: stop = datetime.datetime.now()

    count = 0
    for k, v in tr[monitoring.range()]:
        # get the timestamp range[3:9] inside the keys
        timestamp_keys = list(fdb.tuple.unpack(k))
        timestamp_value = datetime.datetime(timestamp_keys[3], timestamp_keys[4], timestamp_keys[5], 
                                            timestamp_keys[6], timestamp_keys[7], timestamp_keys[8]).timestamp()
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
