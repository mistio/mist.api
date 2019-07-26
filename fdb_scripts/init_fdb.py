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
def set_dummy_metrics(tr):
    now = datetime.datetime.now()

    ten_mins_ago = now - datetime.timedelta(minutes=10)

    print('Set dummy data, since 10 mins ago:' + str(ten_mins_ago))
    # for the last the hour
    for minute in range(0, 59):
        for i in range(1, 12):
            # set metric for every 5 second intervals
            seconds = i * 5
            tuple_key = monitoring.pack((MACHINE_ID, METRICS, now.year,
                                        now.month, now.day, now.hour,
                                        minute, seconds))
            # set a random metric value and the timestamp of the metric
            tr[tuple_key] = fdb.tuple.pack((random.uniform(2.533, 4.325), ))


@fdb.transactional
def get_dummy_metrics(tr):
    print('Fetching dummy data..')
    for k, v in tr[monitoring.range()]:
        print(fdb.tuple.unpack(k), '=>', fdb.tuple.unpack(v))

@fdb.transactional
def get_metrics_for_every_minute(tr):
        print('Fetching dummy for every minute..')
        for k, v in tr[monitoring.range()]:
            if fdb.tuple.unpack(k)[8] == 0:
                print(fdb.tuple.unpack(k), '=>', fdb.tuple.unpack(v))


if __name__ == '__main__':
    print('initializing fdb..')
    db = init_db()
    monitoring = fdb.directory.create_or_open(db, ('monitoring',))
    set_dummy_metrics(db)
    get_dummy_metrics(db)
    #get_metrics_for_every_minute(db)
