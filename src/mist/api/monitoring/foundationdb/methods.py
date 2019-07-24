from mist.api.monitoring.foundationdb.handlers import init_db_and_read_metrics


def fdb_get_stats(machine, start, stop, step, metrics):
    return init_db_and_read_metrics(machine, start, stop, step, metrics)
