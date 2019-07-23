from mist.api.monitoring.foundationdb.handlers import init_and_get_data

def fdb_get_stats(machine, start, stop, step, metrics):
    return init_and_get_data(machine, start, stop, step, metrics)
