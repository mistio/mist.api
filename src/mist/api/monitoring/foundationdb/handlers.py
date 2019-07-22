"""Set of handlers to query from Foundationdb"""

import fdb
import fdb.tuple
import datetime
import random 
import json

MACHINE_ID = '6e2faf7bba844833841fe1e015afc841'
METRICS = 'system.load1'


def get_data(tr, machine_id):
    monitoring = fdb.directory.create_or_open(tr, ('machine_id', 'metrics', 'year', 'month', 'day', 'hour', 'minute', 'seconds'))

    datapoints_array = []
    data = {'machine_id' : MACHINE_ID , 'metrics' : METRICS , 'datapoints' : datapoints_array}
    
    for k, v in tr[monitoring.range()]:
        data_metric_value = fdb.tuple.unpack(v) #unpack data value
        for item in data_metric_value:
            datapoints_array.append(item) # append to datapoint
    
    print('Dt points:' + str(datapoints_array))     
    data['datapoints'] = datapoints_array # assign the datapoints to the dict corresponding key
        
    print('Created data dictionary:' + str(data))
    return data