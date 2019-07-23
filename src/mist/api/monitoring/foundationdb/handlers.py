"""Set of handlers to query from Foundationdb"""

import fdb
import fdb.tuple
import datetime
import random 
import json

fdb.api_version(610) #set api version for fdb
db = fdb.open()
monitoring = fdb.directory.open(db, ('monitoring',))

MACHINE_ID = '6e2faf7bba844833841fe1e015afc841'
METRICS = 'system.load1'


def init_and_get_data(machine, start, stop, step, metrics):
   print('Receive machined Id:' + machine.id)
   return get_data(db, machine.id, start, stop)

@fdb.transactional
def get_data(tr, machine_id, start, stop):
   #set_dummy_metrics(db)
   datapoints = [[]]

   data = {'machine_id' : machine_id , 'metrics' : METRICS , 'datapoints' : datapoints}
   #if not start > start = -10
   #if not stop > stop = now
   if start or stop: #handle start/stop time-series
      if start:
        datetime_start = datetime.datetime.fromtimestamp(int(start))
        print('Fetching metrics starting at:' + str(datetime_start))  
        start_key = fdb.tuple.pack((datetime_start.year, datetime_start.month, datetime_start.day,
                                    datetime_start.hour, datetime_start.minute, datetime_start.second ))
        for k, v in tr.get_range(start_key, b'\xFF'):
          print('Data from start param:' + str(fdb.tuple.unpack(k)))
   else:
         count = 0
         for k, v in tr[monitoring.range()]:
            #get the timestamp range[3:9] inside the keys
            #keys = fdb.tuple.unpack(k)
            timestamp_str = datetime.datetime(fdb.tuple.unpack(k)[3], fdb.tuple.unpack(k)[4],
                                            fdb.tuple.unpack(k)[5], fdb.tuple.unpack(k)[6],
                                            fdb.tuple.unpack(k)[7], fdb.tuple.unpack(k)[8]).timestamp()
            tuple_list = list(fdb.tuple.unpack(v)) # convert the value tuple to list
            tuple_list.append(str(int(timestamp_str))) # append the timestamp string to the list   
            datapoints.insert(count, tuple_list) # append value list to the datapoints list
            count += 1
         print('Datapoints:' + str(datapoints))
        
         print('Created data dictionary:' + str(data))
   return data

