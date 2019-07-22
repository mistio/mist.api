from mist.api.monitoring.foundationdb.handlers import get_data
from mist.api.monitoring.foundationdb.handlers import fdb

def fdb_get_stats(machine, start, stop, step, metrics):
    fdb.api_version(610) #set api version for fdb
    db = fdb.open()

    return get_data(db, machine)
