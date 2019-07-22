import fdb
import fdb.tuple
import datetime
import random 
import json

MACHINE_ID = '6e2faf7bba844833841fe1e015afc841'
METRICS = 'system.load1'

fdb.api_version(610)

db = fdb.open()


monitoring = fdb.directory.create_or_open(db, ('machine_id', 'metrics', 'year', 'month', 'day', 'hour', 'minute', 'seconds'))


#check key methods in docs --

@fdb.transactional
def init_db(tr):

    tr.clear_range(b'', b'\xFF') # clear all db data first
    set_dummy_metrics(tr)    
    get_dummy_metrics(tr)
    #get_metric_in_json(tr)
   
    
@fdb.transactional
def set_dummy_metrics(tr):
    now = datetime.datetime.now()

    for minute in range(0, 60): # for every minute of the hour
       for i in range(1, 12):
            seconds = i * 5 # set metric for every 5 second intervals
            tuple_key = monitoring.pack((MACHINE_ID,METRICS, now.year, now.month, now.day, now.hour, minute, seconds ))
            tr[tuple_key] = fdb.tuple.pack((random.uniform(2.533, 4.325),)) # set a random value using uniform function


@fdb.transactional
def get_dummy_metrics(tr):
    print('Fetching dummy data..')
    for k, v in tr[monitoring.range()]:
      print(str(fdb.tuple.unpack(k)[6]) + ' ' +  str(fdb.tuple.unpack(k)[7]) + ' '  + str(fdb.tuple.unpack(k)[8]) , '=>',  fdb.tuple.unpack(v)) 
            
@fdb.transactional
def get_metric_in_json(tr):
      datapoints_array = []
      data = {'machine_id' : MACHINE_ID , 'metrics' : METRICS , 'datapoints' : datapoints_array}
      for k, v in tr[monitoring.range()]:
            print('Adding value to array:' + str(fdb.tuple.unpack(v)[0]))
            data_metric_value = fdb.tuple.unpack(v)[0] #unpack data value
            datapoints_array.append(data_metric_value) # append to datapoint
      
      data['datapoints'] = datapoints_array # assign the datapoints to the dict corresponding key
      
      
      print('Created json data dictionary:' + str(json.dumps(data)))
            
     
      

if __name__ == '__main__':
   print('initializing fdb..')
   init_db(db)
   print('initialized.')