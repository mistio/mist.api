import fdb
fdb.api_version(610)

import fdb.tuple
import datetime
import random

MACHINE_ID = '6e2faf7bba844833841fe1e015afc841'
METRICS = 'system.load1'


def init_db():
    db = fdb.open()
    return db


@fdb.transactional
def set_dummy_metrics_last_hour(tr):
    now = datetime.datetime.now()

    print('Set dummy data, for the last hour:' + str(now.hour))
    
    for minute in range(0, now.minute):
        value = random.uniform(2.533, 4.325)  # set a random metric value per minute
        for i in range(1, 12):
            # set metric for every 5 second intervals
            seconds = i * 5
            tuple_key = monitoring.pack((MACHINE_ID, METRICS, now.year,
                                        now.month, now.day, now.hour,
                                        minute, seconds))
            tr[tuple_key] = fdb.tuple.pack((value,))
            


@fdb.transactional
def set_dummy_metrics_last_three_hours(tr):
    now = datetime.datetime.now()

    #ten_mins_ago = now - datetime.timedelta(minutes=10)
    three_hours_range = now - datetime.timedelta(hours=3)
    
    print('Set dummy data, since 3 hours ago:' + str(three_hours_range))
    print('Now hour:' + str(now.hour))
    print('Three hours ago:' + str(now.hour - 3))
    
    # for the last three hours
    for hour in range(now.hour - 3, now.hour):
        
        for minute in range(0, 60):
            tuple_key_minute = metrics_per_minute.pack((MACHINE_ID, METRICS, now.year,
                                            now.month, now.day, hour,
                                            minute))
            
            # set a random metric value and the timestamp of the metric
            value = random.uniform(2.533, 4.325)
            tr[tuple_key_minute] = fdb.tuple.pack((value,))
            
            
            for i in range(1, 12):
                # set metric for every 5 second intervals
                seconds = i * 5
                tuple_key_second = monitoring.pack((MACHINE_ID, METRICS, now.year,
                                            now.month, now.day, hour,
                                            minute, seconds))
                tr[tuple_key_second] = fdb.tuple.pack((value,))
            
@fdb.transactional
def get_dummy_metrics(tr):
    print('Fetching dummy data..')
    for k, v in tr[monitoring.range()]:
        print(fdb.tuple.unpack(k), '=>', fdb.tuple.unpack(v))
        

if __name__ == '__main__':
    print('initializing fdb..')
    db = init_db()
    monitoring = fdb.directory.create_or_open(db, ('monitoring',))
    
    metrics_per_minute = monitoring['metric_per_minute']
        
    #set_dummy_metrics_(db)
    #set_dummy_metrics_last_three_hours(db)
    #get_dummy_metrics_per_minute(db)
    set_dummy_metrics_last_hour(db)
    get_dummy_metrics(db)