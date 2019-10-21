from mist.api.monitoring.foundationdb.handlers import get_data
from mist.api.monitoring.helpers import parse_start_stop_params
from mist.api.machines.models import Machine


def fdb_get_stats(machine, start, stop, step, metrics):
    time_params_array = parse_start_stop_params(start, stop)

    return get_data(machine, time_params_array[0],
                    time_params_array[1], metrics)

def find_metrics(machine):
    import fdb
    fdb.api_version(610)  # set api version for fdb
    import fdb.tuple
    if not machine.monitoring.hasmonitoring:
        raise ForbiddenError("Machine doesn't have monitoring enabled.")
    metrics = {}
    db = fdb.open()
    print(machine.id)
    if fdb.directory.exists(db, 'monitoring'):
        monitoring = fdb.directory.open(db, 'monitoring')
        print("list test")
        print(monitoring.list(db))
        #metric = metric_per_hour.pack(machine.id)


        """metric = {key : {
            'id': 'cpu.cpu=cpu5.time_guest',
            'name': 'CPU time guest',
            'column': 'time_guest',
            'measurement': 'cpu',
            'max_value': None,
            'min_value': None,
            'priority': 0,
            'unit': ''
        }}"""
        
        #del db[monitoring["available_metrics"].range(())]


        #datatypes = ["float", "int", "string", "bool"]
        datatypes = ["float", "int"]

        for datatype in datatypes:
            for k, v in db[monitoring["available_metrics"][machine.id][datatype].range()]:
                data_tuple = monitoring["available_metrics"][machine.id][datatype].unpack(k)
                print(data_tuple)
                metric = {data_tuple[0]+"."+data_tuple[1] : {
                    'id': data_tuple[0]+"."+data_tuple[1],
                    'name': data_tuple[0]+"."+data_tuple[1],
                    'column': data_tuple[0]+"."+data_tuple[1],
                    'measurement': data_tuple[0]+"."+data_tuple[1],
                    'max_value': None,
                    'min_value': None,
                    'priority': 0,
                    'unit': ''
                }}
                metrics.update(metric)
            #print(metrics_machine.unpack(k), '=>', fdb.tuple.unpack(v))

    else:
        #raise ForbiddenError("Machine doesn't have the metrics directory.")
        print("rekt")

    return metrics
