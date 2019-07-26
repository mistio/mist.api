"""Set of handlers to query from Foundationdb"""

MACHINE_ID = '6e2faf7bba844833841fe1e015afc841'
METRICS = 'system.load1'


def get_data(machine, start, stop):
    import fdb
    fdb.api_version(610)  # set api version for fdb
    import fdb.tuple
    import datetime

    # open db connection and create transaction
    db = fdb.open()
    tr = db.create_transaction()
    
    print('Receive machined Id:' + machine.id)

    datapoints = [[]]

    data = {
        METRICS : {'name': METRICS, 'column': 'load1',
                   'measurement': 'system',
                   'datapoints': datapoints}
    } 
    
    # Open the monitoring directory if it exists
    if fdb.directory.exists(db, 'monitoring'):
        monitoring = fdb.directory.open(db, ('monitoring',))
        
        print('Start time for metrics:' + str(start))
        print('Stop time for metrics:' + str(stop))

        #  create a tuple of keys and packs them as the start and stop params
        tuple_key_start = (machine.id, METRICS, start.year, start.month,
                        start.day, start.hour, start.minute, start.second)
        tuple_key_stop = (machine.id, METRICS, stop.year, stop.month,
                        stop.day, stop.hour, stop.minute, stop.second)

        print('Start time tuple key:' + str(tuple_key_start))
        print('Stop time tuple key:' + str(tuple_key_stop))

        key_timestamp_start = monitoring.pack(tuple_key_start)

        key_timestamp_stop = monitoring.pack(tuple_key_stop)

        print('Keys in this timestamp range:')
        count = 0
        try:
            #  get the range
            for k, v in tr.get_range(key_timestamp_start, key_timestamp_stop):
                print(fdb.tuple.unpack(k), '=>', fdb.tuple.unpack(v))
                # get the timestamp range[3:9] inside the keys
                timestamp_keys = list(fdb.tuple.unpack(k))
                timestamp_value = datetime.datetime(timestamp_keys[3],  # year
                                                    timestamp_keys[4],  # month
                                                    timestamp_keys[5],  # day
                                                    timestamp_keys[6],  # hour
                                                    timestamp_keys[7],  # minute
                                                    timestamp_keys[8]).timestamp()
                # convert the value tuple to list
                tuple_list = list(fdb.tuple.unpack(v))
                # append the timestamp string to the list
                tuple_list.append(str(int(timestamp_value)))
                # append value list to the datapoints list
                datapoints.insert(count, tuple_list)
                count += 1
                
            tr.commit().wait()
        except fdb.FDBError as error:
            tr.on_error(error).wait()
        
    else:
        print('The directory you are trying to read does not exist.')
        
    return data
