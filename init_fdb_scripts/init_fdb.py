import fdb
import fdb.tuple
import datetime
import random 
import json

MACHINE_ID = '6e2faf7bba844833841fe1e015afc841'
METRICS = 'system.load1'

fdb.api_version(610)

db = fdb.open()
monitoring = fdb.directory.create(db, ('monitoring',))

@fdb.transactional
def init_db(tr):
    tr.clear_range(b'', b'\xFF') # clear all db data first
    set_dummy_metrics(tr)
    get_dummy_metrics(tr)
    
@fdb.transactional
def set_dummy_metrics(tr):
    now = datetime.datetime.now()

    for minute in range(now.minute - 10, now.minute): # for the last 10 minutes of the hour
       for i in range(1, 12):
            seconds = i * 5 # set metric for every 5 second intervals
            tuple_key = monitoring.pack((MACHINE_ID,METRICS, now.year, now.month, now.day, now.hour, minute, seconds ))
            tr[tuple_key] = fdb.tuple.pack((random.uniform(2.533, 4.325), )) # set a random metric value and the timestamp of the metric


@fdb.transactional
def get_dummy_metrics(tr):
    print('Fetching dummy data..')
    for k, v in tr[monitoring.range()]:
      print(fdb.tuple.unpack(k) , '=>', fdb.tuple.unpack(v))

            

if __name__ == '__main__':
   print('initializing fdb..')
   init_db(db)
   print('initialized.')