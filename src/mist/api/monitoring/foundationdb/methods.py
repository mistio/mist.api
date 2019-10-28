import logging

from mist.api.monitoring.foundationdb.handlers import get_data
from mist.api.monitoring.helpers import parse_start_stop_params
from mist.api.machines.models import Machine

from mist.api.exceptions import NotFoundError, ServiceUnavailableError
from mist.api.exceptions import ForbiddenError


log = logging.getLogger(__name__)


def get_stats(machine, start, stop, step, metrics):
    time_params_array = parse_start_stop_params(start, stop)
        
    return get_data([machine.id], time_params_array[0],
                    time_params_array[1], metrics)[machine.id]

def get_load(machines, start, stop, step):
    time_params_array = parse_start_stop_params(start, stop)

    data = get_data(machines, time_params_array[0],
                    time_params_array[1], ["system.load1"])
    
    for machine in data.keys():
        data[machine] = data[machine]["system.load1"]
        data[machine]["name"] = machine
    
    return data


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

        for k, v in db[monitoring["available_metrics"][machine.id].range()]:
            data_tuple = monitoring["available_metrics"][machine.id].unpack(k)
            #print(data_tuple)
            metric = {data_tuple[1]+"."+data_tuple[2] : {
                'id': data_tuple[1]+"."+data_tuple[2],
                'name': data_tuple[1]+"."+data_tuple[2],
                'column': data_tuple[1]+"."+data_tuple[2],
                'measurement': data_tuple[1]+"."+data_tuple[2],
                'max_value': None,
                'min_value': None,
                'priority': 0,
                'unit': ''
            }}
            metrics.update(metric)
            #print(metrics_machine.unpack(k), '=>', fdb.tuple.unpack(v))

    else:
        raise ForbiddenError("Machine doesn't have the metrics directory.")
        
    return metrics
