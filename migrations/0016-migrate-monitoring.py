#!/usr/bin/env python

import argparse
from mist.api.config import GRAPHITE_TO_VICTORIAMETRICS_METRICS_MAP
from mist.api.config import VICTORIAMETRICS_TO_VICTORIAMETRICS_METRICS_MAP

from mist.api import config
from mist.api.rules.models import MachineMetricRule
from mist.api.models import Machine
from mist.api.monitoring.methods import update_metric


graphite_to_victoriametrics_map = {
    'cpu.0.idle': 'cpu_usage_idle{cpu="cpu0"}',
    'cpu.total.nonidle': '100-cpu_usage_idle{cpu="cpu-total"}',
    'cpu.total.steal': 'cpu_usage_steal{cpu="cpu-total"}',
    'cpu.total.user': 'cpu_usage_user{cpu="cpu-total"}',
    'cpu_extra.total.idle': 'cpu_usage_idle{cpu="cpu-total"}',
    'cpu_extra.total.system': 'cpu_usage_system{cpu="cpu-total"}',
    'cpu.total.usage_system': 'cpu_usage_system{cpu="cpu-total"}',
    'df.sda1.df_complex.used_percent': 'disk_used_percent{device="sda1"}',
    'df.vda1.df_complex.free': 'disk_free{device="vda1"}',
    'disk.total.disk_octets.read': 'sum(rate(diskio_read_bytes))',
    'disk.total.disk_octets.write': 'sum(rate(diskio_write_bytes))',
    'interface.total.if_octets.tx': 'sum(rate(net_bytes_sent))',
    'load.midterm': 'system_load5',
    'load.shortterm': 'system_load1',
    'memory.free': 'mem_free',
    'memory.free_percent': '(mem_free/mem_total)*100',
    'memory.nonfree_percent': '((mem_total-mem_free)/mem_total)*100',
    'memory_extra.available': 'mem_available',
    'memory.used_percent': '(mem_used/mem_total)*100',
    'system.n_cpus': 'system_n_cpus',
    'cpu.0.user': 'cpu_usage_user{cpu="cpu0"}',
    'df.sda1.df_complex.total': 'disk_total{device="sda1"}',
    'df.sda1.df_complex.used_percent': 'disk_used_percent{device="sda1"}',
    'disk.sda1.disk_octets.write': 'rate(diskio_write_bytes{name="sda1"})',
    'disk_extra.md0.iops_in_progress': 'diskio_iops_in_progress{name="md0"}',
    'interface.eth0.if_errors.rx': 'net_err_in{interface="eth0"}',
    'kernel.boot_time': 'kernel_boot_time',
    'kernel.interrupts': 'kernel_interrupts',
    'swap.free': 'swap_free',
}

graphite_to_victoriametrics_map.update(GRAPHITE_TO_VICTORIAMETRICS_METRICS_MAP)

influxdb_to_graphite_map = {
    "system.load1": "load.shortterm",
    "system.load5": "load.midterm",
    "system.n_cpus": "system.n_cpus",
    "cpu.cpu=cpu0.usage_user": "cpu.0.user",
    "cpu.cpu=cpu0.usage_idle": "cpu.0.idle"
}

influxdb_to_victoriametrics_map = {
    "system.load1": "system_load1",
    "system.load5": "system_load5",
    "system.n_cpus": "system_n_cpus",
    "cpu.cpu=cpu0.usage_user": 'cpu_usage_user{cpu="cpu0"}',
    "cpu.cpu=cpu0.usage_idle": 'cpu_usage_idle{cpu="cpu0"}'
}

victoriametrics_to_victoriametrics_map = {}

victoriametrics_to_victoriametrics_map.update(
    VICTORIAMETRICS_TO_VICTORIAMETRICS_METRICS_MAP)


def invert_map(map):
    return {v: k for k, v in map.items()}


metrics_map = {
    'influxdb-graphite': influxdb_to_graphite_map,
    'influxdb-victoriametrics': influxdb_to_victoriametrics_map,
    'graphite-influxdb': invert_map(influxdb_to_graphite_map),
    'graphite-victoriametrics': graphite_to_victoriametrics_map,
    'victoriametrics-graphite': invert_map(
        graphite_to_victoriametrics_map),
    'victoriametrics-influxdb': invert_map(
        influxdb_to_victoriametrics_map),
    'victoriametrics-victoriametrics': victoriametrics_to_victoriametrics_map
}


def parse_args():
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        '-f', '--force-migration', type=ascii,
        help="Force a specific migration e.g. graphite-victoriametrics"
    )
    return argparser.parse_args()


def migrate_machines(force_migration=None):
    default_timeseries_db = config.DEFAULT_MONITORING_METHOD.split("-")[1]
    failed = updated = 0
    machines = Machine.objects(
        missing_since=None, monitoring__hasmonitoring=True)

    total = len(machines)
    if not total:
        return

    for machine in machines:
        try:
            current_timeseries_db = machine.monitoring.method.split("-")[1]
            if force_migration:
                migration = force_migration
            else:
                migration = f"{current_timeseries_db}-{default_timeseries_db}"
            if metrics_map.get(migration):
                machine.monitoring.metrics = [metrics_map[migration].get(
                    metric, metric) for metric in machine.monitoring.metrics]
            for metric in machine.monitoring.metrics:
                update_metric(machine.owner, metric)
            machine.monitoring.method = config.DEFAULT_MONITORING_METHOD
            machine.save()
            updated += 1
        except Exception as e:
            failed += 1
            print(
                f"Failed to change monitoring method for"
                f" {machine.id} ({machine.name}) failed: {repr(e)}")

    print(f'{updated} machines updated succesfully')
    print(f'{failed} machines failed')


def migrate_rules(force_migration=None):
    default_timeseries_db = config.DEFAULT_MONITORING_METHOD.split("-")[1]
    if force_migration:
        possible_timeseries_migrations = [force_migration, ]
    else:
        possible_timeseries_migrations = [migration for migration in list(
            metrics_map.keys())
            if migration.endswith(f"-{default_timeseries_db}")]

    failed = updated = 0
    rules = MachineMetricRule.objects()
    total = len(rules)
    if not total:
        return

    for rule in rules:
        for query in rule.queries:
            for migration in possible_timeseries_migrations:
                if metrics_map[migration].get(query.target):
                    query.target = metrics_map[migration][query.target]
                    break
        try:
            rule.save()
            updated += 1
            print('OK')
        except Exception as e:
            failed += 1
            print('Failed to save rule %s (%s) failed: %r' % (
                rule.id, rule.name, e))

    print(f'{updated} rules updated succesfully')
    print(f'{failed} rules failed')


def migrate_monitoring(force_migration=None):
    migrate_rules(force_migration)
    migrate_machines(force_migration)


if __name__ == '__main__':
    args = parse_args()
    force_migration = None
    if args.force_migration:
        force_migration = args.force_migration.replace("'", "")
    if force_migration and \
            not metrics_map.get(force_migration):
        print(f"Not a supported migration: {force_migration}")
        exit()
    migrate_monitoring(force_migration=force_migration)
