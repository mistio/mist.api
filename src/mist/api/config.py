"""Basic configuration and mappings
   Here we define constants needed by mist.api
   Also, the configuration from settings.py is exposed through this module.
"""
import os
import ssl
import json
import logging
import datetime
import urllib
import urllib.parse

import libcloud.security
from libcloud.compute.types import NodeState
from libcloud.container.base import ClusterState
from libcloud.container.types import Provider as Container_Provider
from libcloud.compute.types import Provider


log = logging.getLogger(__name__)
libcloud.security.SSL_VERSION = ssl.PROTOCOL_TLSv1_2


def dirname(path, num=1):
    """Get absolute path of `num` directories above path"""
    path = os.path.abspath(path)
    for _ in range(num):
        path = os.path.dirname(path)
    return path


MIST_API_DIR = dirname(__file__, 4)
log.warn("MIST_API_DIR is %s" % MIST_API_DIR)


###############################################################################
###############################################################################

PORTAL_NAME = "Mist CE"
DESCRIPTION = "A secure cloud management platform for automation,\
 orchestration, cost and usage monitoring of public and private clouds,\
 hypervisors and container hosts. Provides multi-cloud RBAC. Enables\
 self service provisioning. Cost analytics and cloud spending optimization"
CORE_URI = "http://localhost"
LICENSE_KEY = ""
AMQP_URI = "rabbitmq:5672"
MEMCACHED_HOST = ["memcached:11211"]
BROKER_URL = "amqp://guest:guest@rabbitmq/"
INTERNAL_SOCKJS_HOST = "sockjs"
SSL_VERIFY = True
THEME = ""
EMAIL_LOGO = "landing/images/logo-email-440.png"

GC_SCHEDULERS = True
GC_SESSIONS = True
GC_NODATARULETRACKER = True
ELASTICSEARCH_CLEANUP = True
VERSION_CHECK = True
USAGE_SURVEY = False
ENABLE_METERING = True
BACKUP_INTERVAL = 24
LANDING_CDN_URI = ""
BLOG_CDN_URI = ""

METERING_PROMQL_LOOKBACK = "2h"
METERING_NOTIFICATIONS_WEBHOOK = ""
METERING_METRICS = {
    "machine": {
        "default": {
            'core_hours': {'type': 'counter', 'value': lambda machine,
                           dt: dt * (
                               float(machine.cores) if (
                                   machine.state == 'running' and
                                   machine.cores) else 0)},
            'ram_gb_hours': {'type': 'counter', 'value': lambda machine,
                             dt: dt * (
                                 machine.size.ram / 1000
                                 if (machine.state == 'running' and
                                     machine.size and
                                     machine.size.ram) else 0)},
            'total_cost': {'type': 'counter', 'value': lambda machine,
                           dt: dt * (
                               machine.cost.hourly
                               if (machine.state == 'running' and
                                   machine.cost.hourly) else 0)},
            'core_count': {'type': 'gauge', 'value': lambda machine:
                           machine.cores
                           if machine.cores else 0},
            'ram_gb': {'type': 'gauge', 'value': lambda machine: (
                machine.size.ram / 1000 if machine.state == 'running' and
                machine.size and machine.size.ram else 0)}
        }
    },
    "volume": {
        "default": {
            'disk_gb_hours': {'type': 'counter', 'value': lambda volume,
                              dt: dt * (volume.size)},
            'disk_gb': {'type': 'gauge', 'value': lambda volume: volume.size}
        }
    }
}

# backups
BACKUP = {
    'key': '',
    'secret': '',
    'bucket': 'mist-backup',
    'gpg': {
        'recipient': '',
        'public': '',
        'private': '',
    }
}

ELASTICSEARCH = {
    'elastic_host': 'elasticsearch',
    'elastic_port': '9200',
    'elastic_username': '',
    'elastic_password': '',
    'elastic_use_ssl': False,
    'elastic_verify_certs': False
}

# Sentry Settings
SENTRY_CONFIG = {
    'TRACES_SAMPLE_RATE': 0.2,
    'API_V1_URL': '',
    'API_V2_URL': '',
    'SOCK_JS_URL': '',
    'DRAMATIQ_URL': '',
    'ENVIRONMENT': '',
}

DATABASE_VERSION = 31

UI_TEMPLATE_URL = "http://ui"
LANDING_TEMPLATE_URL = "http://landing"

PY_LOG_LEVEL = logging.INFO
PY_LOG_FORMAT = '%(asctime)s %(levelname)s %(threadName)s %(module)s - %(funcName)s: %(message)s'  # noqa
PY_LOG_FORMAT_DATE = "%Y-%m-%d %H:%M:%S"
LOG_EXCEPTIONS = True

JS_BUILD = True
JS_LOG_LEVEL = 3

ENABLE_DEV_USERS = False

# policy to be applied on resources' owners
OWNER_POLICY = {}

# If true, on expiration schedule with action destroy,
# instead of destroying a machine,
# stop it, change ownership, untag the machine and
# create a new schedule that will destroy the machine
#  in <SAFE_EXPIRATION_DURATION> seconds
SAFE_EXPIRATION = False
SAFE_EXPIRATION_DURATION = 60 * 60 * 24 * 7

MONGO_URI = "mongodb:27017"
MONGO_DB = "mist2"

DOMAIN_VALIDATION_WHITELIST = []

DOCS_URI = 'https://docs.mist.io/'
SUPPORT_URI = 'https://docs.mist.io/contact'

INTERNAL_API_URL = 'http://api'
INTERNAL_API_V2_URL = 'http://api-v2:8080'
GOCKY_HOST = 'gocky'
GOCKY_PORT = 9096

# InfluxDB
INFLUX = {
    "host": "http://influxdb:8086", "db": "telegraf", "backup": "influxdb:8088"
}

TELEGRAF_TARGET = ""
TRAEFIK_API = "http://traefik:8080"

# Hashicorp Vault Default Vars
VAULT_TOKEN = ''
VAULT_ROLE_ID = ''
VAULT_SECRET_ID = ''
VAULT_ADDR = 'http://vault:8200'
# Mappings between organization names and secret engine paths
VAULT_SECRET_ENGINE_PATHS = {}
VAULT_KV_VERSION = 2  # 1 or 2
VAULT_CLOUDS_PATH = 'mist/clouds/'
VAULT_KEYS_PATH = 'mist/keys/'

# Default, built-in metrics.
INFLUXDB_BUILTIN_METRICS = {
    'cpu.cpu=cpu-total.usage_user': {
        'name': 'CPU',
        'unit': '%',
        'max_value': 100,
        'min_value': 0,
    },
    'system.load1': {
        'name': 'system.load1',
        'unit': '',
        'max_value': 64,
        'min_value': 0,
    },
    'mem.used_percent': {
        'name': 'RAM',
        'unit': '%',
        'max_value': 100,
        'min_value': 0,
    },
    'disk.bytes_read': {
        'name': 'Disks Read',
        'unit': 'B/s',
        'max_value': 750000000,  # 6Gbps (SATA3)
        'min_value': 0,
    },
    'disk.bytes_write': {
        'name': 'Disks Write',
        'unit': 'B/s',
        'max_value': 750000000,
        'min_value': 0,
    },
    'net.bytes_recv': {
        'name': 'Ifaces Rx',
        'unit': 'B/s',
        'max_value': 1250000000,  # 10Gbps (10G eth)
        'min_value': 0,
    },
    'net.bytes_sent': {
        'name': 'Ifaces Tx',
        'unit': 'B/s',
        'max_value': 1250000000,
        'min_value': 0,
    },
}

GRAPHITE_BUILTIN_METRICS = {
    'cpu.total.nonidle': {
        'name': 'CPU',
        'unit': '%',
        'max_value': 100,
        'min_value': 0,
    },
    'cpu_extra.total.user': {
        'name': 'CPU user',
        'unit': '%',
        'max_value': 100,
        'min_value': 0,
    },
    'cpu_extra.total.system': {
        'name': 'CPU system',
        'unit': '%',
        'max_value': 100,
        'min_value': 0,
    },
    'cpu_extra.total.idle': {
        'name': 'CPU idle',
        'unit': '%',
        'max_value': 100,
        'min_value': 0,
    },
    'load.shortterm': {
        'name': 'Load',
        'unit': '',
        'max_value': 64,
        'min_value': 0,
    },
    'memory.nonfree_percent': {
        'name': 'RAM',
        'unit': '%',
        'max_value': 100,
        'min_value': 0,
    },
    'memory_extra.available': {
        'name': 'RAM available',
        'unit': ''
    },
    'disk.total.disk_octets.read': {
        'name': 'Disks Read',
        'unit': 'B/s',
        'max_value': 750000000,  # 6Gbps (SATA3)
        'min_value': 0,
    },
    'disk.total.disk_octets.write': {
        'name': 'Disks Write',
        'unit': 'B/s',
        'max_value': 750000000,
        'min_value': 0,
    },
    'interface.total.if_octets.rx': {
        'name': 'Ifaces Rx',
        'unit': 'B/s',
        'max_value': 1250000000,  # 10Gbps (10G eth)
        'min_value': 0,
    },
    'interface.total.if_octets.tx': {
        'name': 'Ifaces Tx',
        'unit': 'B/s',
        'max_value': 1250000000,
        'min_value': 0,
    },
}

# Default Dashboards.
HOME_DASHBOARD_DEFAULT = {
    "meta": {},
    "dashboard": {
        "id": 1,
        "refresh": "10sec",
        "rows": [{
            "panels": [{
                "id": 0,
                "title": "Load on all monitored machines",
                "type": "graph",
                "span": 12,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "A",
                    "target": "load.shortterm"
                }],
                "x-axis": True,
                "y-axis": True
            }]
        }],
        "time": {
            "from": "now-10m",
            "to": "now"
        },
        "timepicker": {
            "now": True,
            "refresh_intervals": [],
            "time_options": [
                "10m",
                "1h",
                "6h",
                "24h",
                "7d",
                "30d"
            ]
        },
        "timezone": "browser"
    }
}

FDB_MACHINE_DASHBOARD_DEFAULT = {
    "meta": {},
    "dashboard": {
        "id": 1,
        "refresh": "10sec",
        "rows": [{
            "height": 300,
            "panels": [{
                "id": 0,
                "title": "Load",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "A",
                    "target": urllib.parse.quote(
                        "fetch(\"{id}.system.load(\d)+\"" +
                        ", start=\"{start}\", stop=\"{stop}\"" +
                        ", step=\"{step}\")")
                }],
                "x-axis": True,
                "y-axis": True
            }, {
                "id": 1,
                "title": "MEM",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "B",
                    "target": urllib.parse.quote(
                        "fetch(\"{id}.mem.(free|used|cached|buffered)$\"" +
                        ", start=\"{start}\", stop=\"{stop}\"" +
                        ", step=\"{step}\")")
                }, ],
                "yaxes": [{
                    "label": "B"
                }]
            }, {
                "id": 2,
                "title": "CPU total",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "C",
                    "target": urllib.parse.quote(
                        "fetch(\"{id}.cpu.total.usage.*(?<!idle)$\"" +
                        ", start=\"{start}\", stop=\"{stop}\"" +
                        ", step=\"{step}\")")
                }],
                "yaxes": [{
                    "label": "%"
                }]
            }, {
                "id": 3,
                "title": "CPU idle per core",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "Z",
                    "target": urllib.parse.quote(
                        "fetch(\"{id}.cpu.*usage_idle\"" +
                        ", start=\"{start}\", stop=\"{stop}\"" +
                        ", step=\"{step}\")")
                }],
                "yaxes": [{
                    "label": "%"
                }]
            }, {
                "id": 4,
                "title": "NET RX",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "G",
                    "target": urllib.parse.quote(
                        "deriv(fetch(\"{id}.net.*.bytes_recv\"" +
                        ", start=\"{start}\", stop=\"{stop}\"" +
                        ", step=\"{step}\"))")
                }],
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 5,
                "title": "NET TX",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "H",
                    "target": urllib.parse.quote(
                        "deriv(fetch(\"{id}.net.*.bytes_sent\"" +
                        ", start=\"{start}\", stop=\"{stop}\"" +
                        ", step=\"{step}\"))")
                }],
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 6,
                "title": "DISK READ",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "I",
                    "target": urllib.parse.quote(
                        "deriv(fetch(\"{id}.diskio.*.read_bytes\"" +
                        ", start=\"{start}\", stop=\"{stop}\"" +
                        ", step=\"{step}\"))")
                }],
                "x-axis": True,
                "y-axis": True,
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 7,
                "title": "DISK WRITE",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "J",
                    "target": urllib.parse.quote(
                        "deriv(fetch(\"{id}.diskio.*.write_bytes\"" +
                        ", start=\"{start}\", stop=\"{stop}\"" +
                        ", step=\"{step}\"))")
                }],
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 8,
                "title": "DF",
                "type": "graph",
                "span": 12,
                "height": 400,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "D",
                    "target": urllib.parse.quote(
                        "fetch(\"{id}.disk.*\.free\"" +
                        ", start=\"{start}\", stop=\"{stop}\"" +
                        ", step=\"{step}\")")
                }],
                "yaxes": [{
                    "label": "B"
                }]
            }],
        }],
        "time": {
            "from": "now-10m",
            "to": "now"
        },
        "timepicker": {
            "now": True,
            "refresh_intervals": [],
            "time_options": [
                "10m",
                "1h",
                "6h",
                "24h",
                "7d",
                "30d"
            ]
        },
        "timezone": "browser"
    }
}

VICTORIAMETRICS_MACHINE_DASHBOARD_DEFAULT = {
    "meta": {},
    "dashboard": {
        "id": 1,
        "refresh": "10sec",
        "rows": [{
            "height": 300,
            "panels": [{
                "id": 0,
                "title": "Load",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [
                    {
                        "refId": "A1",
                        "target": "system_load1",
                        "legendFormat": "system_load1"
                    },
                    {
                        "refId": "A2",
                        "target": "system_load5",
                        "legendFormat": "system_load5"
                    },
                    {
                        "refId": "A3",
                        "target": "system_load15",
                        "legendFormat": "system_load15"
                    }
                ],
                "x-axis": True,
                "y-axis": True
            }, {
                "id": 1,
                "title": "MEM",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [
                    {
                        "refId": "B1",
                        "target": "mem_free",
                        "legendFormat": "mem_free"
                    },
                    {
                        "refId": "B2",
                        "target": "mem_used",
                        "legendFormat": "mem_used"
                    },
                    {
                        "refId": "B3",
                        "target": "mem_cached",
                        "legendFormat": "mem_cached"
                    },
                    {
                        "refId": "B4",
                        "target": "mem_buffered",
                        "legendFormat": "mem_buffered"
                    }
                ],
                "yaxes": [{
                    "label": "B"
                }]
            }, {
                "id": 2,
                "title": "CPU total",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [
                    {
                        "refId": "C1",
                        "target": 'cpu_usage_guest{cpu="cpu-total"}',
                        "legendFormat": "cpu_usage_guest-{{cpu}}"
                    },
                    {
                        "refId": "C2",
                        "target": 'cpu_usage_iowait{cpu="cpu-total"}',
                        "legendFormat": "cpu_usage_iowait-{{cpu}}"
                    },
                    {
                        "refId": "C3",
                        "target": 'cpu_usage_user{cpu="cpu-total"}',
                        "legendFormat": "cpu_usage_user-{{cpu}}"
                    },
                    {
                        "refId": "C4",
                        "target": 'cpu_usage_nice{cpu="cpu-total"}',
                        "legendFormat": "cpu_usage_nice-{{cpu}}"
                    },
                    {
                        "refId": "C5",
                        "target": 'cpu_usage_softirq{cpu="cpu-total"}',
                        "legendFormat": "cpu_usage_softirq-{{cpu}}"
                    },
                    {
                        "refId": "C6",
                        "target": 'cpu_usage_idle{cpu="cpu-total"}',
                        "legendFormat": "cpu_usage_idle-{{cpu}}"
                    },
                    {
                        "refId": "C7",
                        "target": 'cpu_usage_irq{cpu="cpu-total"}',
                        "legendFormat": "cpu_usage_irq-{{cpu}}"
                    },
                    {
                        "refId": "C8",
                        "target": 'cpu_usage_system{cpu="cpu-total"}',
                        "legendFormat": "cpu_usage_system-{{cpu}}"
                    },
                    {
                        "refId": "C9",
                        "target": 'cpu_usage_steal{cpu="cpu-total"}',
                        "legendFormat": "cpu_usage_steal-{{cpu}}"
                    },
                    {
                        "refId": "C10",
                        "target": 'cpu_usage_guest_nice{cpu="cpu-total"}',
                        "legendFormat": "cpu_usage_guest_nice-{{cpu}}"
                    }
                ],
                "yaxes": [{
                    "label": "%"
                }]
            }, {
                "id": 3,
                "title": "CPU idle per core",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "Z",
                    "target": "cpu_usage_idle",
                    "legendFormat": "cpu_usage_idle-{{cpu}}"
                }],
                "yaxes": [{
                    "label": "%"
                }]
            }, {
                "id": 4,
                "title": "NET RX",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "G",
                    "target": "rate(net_bytes_recv)",
                    "legendFormat": "rate(net_bytes_recv)-{{interface}}"
                }],
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 5,
                "title": "NET TX",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "H",
                    "target": "rate(net_bytes_sent)",
                    "legendFormat": "rate(net_bytes_sent)-{{interface}}"
                }],
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 6,
                "title": "DISK READ",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "I",
                    "target": "rate(diskio_read_bytes)",
                    "legendFormat": "rate(diskio_read_bytes)-{{name}}"
                }],
                "x-axis": True,
                "y-axis": True,
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 7,
                "title": "DISK WRITE",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "J",
                    "target": "rate(diskio_write_bytes)",
                    "legendFormat": "rate(diskio_write_bytes)-{{name}}"
                }],
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 8,
                "title": "DF",
                "type": "graph",
                "span": 12,
                "height": 400,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "D",
                    "target": "disk_free",
                    "legendFormat": "disk_free-{{device}}-{{path}}"
                }],
                "yaxes": [{
                    "label": "B"
                }]
            }],
        }],
        "time": {
            "from": "now-10m",
            "to": "now"
        },
        "timepicker": {
            "now": True,
            "refresh_intervals": [],
            "time_options": [
                "10m",
                "1h",
                "6h",
                "24h",
                "7d",
                "30d"
            ]
        },
        "timezone": "browser"
    }
}

INFLUXDB_MACHINE_DASHBOARD_DEFAULT = {
    "meta": {},
    "dashboard": {
        "id": 1,
        "refresh": "10sec",
        "rows": [{
            "title": "Load, CPU, RAM, Uptime",
            "panels": [{
                "id": 0,
                "title": "Load",
                "description": "Load average",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "A",
                    "target": "system./load\d/"
                }],
                "x-axis": True,
                "y-axis": True
            }, {
                "id": 1,
                "title": "MEM",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "D",
                    "target": "mem./^(free|used|cached|buffered)$/"
                }],
                "yaxes": [{
                    "format": "B"
                }]
            }, {
                "id": 2,
                "title": "CPU total",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "C",
                    "target": "cpu.cpu=cpu-total./usage_\w*/"
                }],
                "yaxes": [{
                    "format": "%"
                }]
            }, {
                "id": 3,
                "title": "CPU idle per core",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "Z",
                    "target": "cpu.cpu=/cpu\d/.usage_idle"
                }],
                "yaxes": [{
                    "format": "%"
                }]
            }, {
                "id": 4,
                "title": "Uptime",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "Z",
                    "target": "system.uptime"
                }],
                "yaxes": [{
                    "format": "%"
                }]
            }]
        }, {
            "title": "Network & Filesystems",
            "collapsed": True,
            "panels": [{
                "id": 5,
                "title": "NET RX",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "G",
                    "target": "net.bytes_recv"
                }],
                "yaxes": [{
                    "format": "B/s"
                }]
            }, {
                "id": 6,
                "title": "NET TX",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "H",
                    "target": "net.bytes_sent"
                }],
                "yaxes": [{
                    "format": "B/s"
                }]
            }, {
                "id": 8,
                "title": "DF",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "D",
                    "target": "disk.free"
                }],
                "yaxes": [{
                    "format": "B"
                }]
            }]
        }, {
            "title": "Disks",
            "collapsed": True,
            "panels": [{
                "id": 9,
                "title": "DISK READ",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "I",
                    "target": "diskio.read_bytes"
                }],
                "x-axis": True,
                "y-axis": True
            }, {
                "id": 10,
                "title": "DISK WRITE",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "J",
                    "target": "diskio.write_bytes"
                }],
                "yaxes": [{
                    "format": "B/s"
                }]
            }],
        }, {
            "panels": []
        }],
        "time": {
            "from": "now-10m",
            "to": "now"
        },
        "timepicker": {
            "now": True,
            "refresh_intervals": [],
            "time_options": [
                "10m",
                "1h",
                "6h",
                "24h",
                "7d",
                "30d"
            ]
        },
        "timezone": "browser"
    }
}

GRAPHITE_MACHINE_DASHBOARD_DEFAULT = {
    "meta": {},
    "dashboard": {
        "id": 1,
        "refresh": "10sec",
        "rows": [{
            "height": 300,
            "panels": [{
                "id": 0,
                "title": "Load",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "A",
                    "target": "load.*"
                }],
                "x-axis": True,
                "y-axis": True
            }, {
                "id": 1,
                "title": "MEM",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "D",
                    "target": "memory.*"
                }],
                "yaxes": [{
                    "label": "B"
                }]
            }, {
                "id": 2,
                "title": "CPU total",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "C",
                    "target": "cpu.total.*"
                }],
                "yaxes": [{
                    "label": "%"
                }]
            }, {
                "id": 3,
                "title": "CPU idle per core",
                "type": "graph",
                "span": 6,
                "stack": True,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "Z",
                    "target": "cpu.*.idle"
                }],
                "yaxes": [{
                    "label": "%"
                }]
            }, {
                "id": 4,
                "title": "NET RX",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "G",
                    "target": "interface.*.if_octets.rx"
                }],
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 5,
                "title": "NET TX",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "H",
                    "target": "interface.*.if_octets.tx"
                }],
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 6,
                "title": "DISK READ",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "I",
                    "target": "disk.*.disk_octets.read"
                }],
                "x-axis": True,
                "y-axis": True,
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 7,
                "title": "DISK WRITE",
                "type": "graph",
                "span": 6,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "J",
                    "target": "disk.*.disk_octets.write"
                }],
                "yaxes": [{
                    "label": "B/s"
                }]
            }, {
                "id": 8,
                "title": "DF",
                "type": "graph",
                "span": 12,
                "height": 400,
                "stack": False,
                "datasource": "mist.monitor",
                "targets": [{
                    "refId": "D",
                    "target": "df.*.df_complex.free"
                }],
                "yaxes": [{
                    "label": "B"
                }]
            }],
        }],
        "time": {
            "from": "now-10m",
            "to": "now"
        },
        "timepicker": {
            "now": True,
            "refresh_intervals": [],
            "time_options": [
                "10m",
                "1h",
                "6h",
                "24h",
                "7d",
                "30d"
            ]
        },
        "timezone": "browser"
    }
}

WINDOWS_MACHINE_DASHBOARD_DEFAULT = {
    "meta": {},
    "dashboard": {
        "id": 1,
        "refresh": "10sec",
        "rows": [{
            "height": 300,
            "panels": [
                {
                    "id": 0,
                    "title": "MEM",
                    "type": "graph",
                    "span": 6,
                    "stack": True,
                    "datasource": "mist.monitor",
                    "targets": [
                        {
                            "refId": "A",
                            "target": "memory.used"
                        },
                        {
                            "refId": "B",
                            "target": "memory_extra.available"
                        }
                    ],
                    "yaxes": [{
                        "label": "B"
                    }]
                },
                {
                    "id": 1,
                    "title": "CPU total",
                    "type": "graph",
                    "span": 6,
                    "stack": True,
                    "datasource": "mist.monitor",
                    "targets": [
                        {
                            "refId": "C",
                            "target": "cpu_extra.total.user"
                        },
                        {
                            "refId": "D",
                            "target": "cpu_extra.total.system"
                        },
                        {
                            "refId": "E",
                            "target": "cpu_extra.total.idle"
                        }
                    ],
                    "yaxes": [{
                        "label": "%"
                    }]
                },
                {
                    "id": 2,
                    "title": "Disks",
                    "type": "graph",
                    "span": 6,
                    "stack": True,
                    "datasource": "mist.monitor",
                    "targets": [{
                        "refId": "F",
                        "target": "disk.*.used_percent"
                    }],
                    "yaxes": [{
                        "label": "%"
                    }]
                },
                {
                    "id": 4,
                    "title": "NET RX",
                    "type": "graph",
                    "span": 6,
                    "stack": False,
                    "datasource": "mist.monitor",
                    "targets": [{
                        "refId": "F",
                        "target": "net.*.bytes_recv"
                    }],
                    "yaxes": [{
                        "label": "octets"
                    }]
                },
                {
                    "id": 5,
                    "title": "NET TX",
                    "type": "graph",
                    "span": 6,
                    "stack": False,
                    "datasource": "mist.monitor",
                    "targets": [{
                        "refId": "G",
                        "target": "net.*.bytes_sent"
                    }],
                    "yaxes": [{
                        "label": "octets"
                    }]
                },
                {
                    "id": 6,
                    "title": "DISK READ",
                    "type": "graph",
                    "span": 6,
                    "stack": False,
                    "datasource": "mist.monitor",
                    "targets": [{
                        "refId": "H",
                        "target": "diskio.*.read_bytes"
                    }],
                    "x-axis": True,
                    "y-axis": True
                },
                {
                    "id": 7,
                    "title": "DISK WRITE",
                    "type": "graph",
                    "span": 6,
                    "stack": False,
                    "datasource": "mist.monitor",
                    "targets": [{
                        "refId": "J",
                        "target": "diskio.*.write_bytes"
                    }],
                    "yaxes": [{
                        "label": "octets"
                    }]
                }
            ],
        }],
        "time": {
            "from": "now-10m",
            "to": "now"
        },
        "timepicker": {
            "now": True,
            "refresh_intervals": [],
            "time_options": [
                "10m",
                "1h",
                "6h",
                "24h",
                "7d",
                "30d"
            ]
        },
        "timezone": "browser"
    }
}


MONITORING_METHODS = (
    'telegraf-influxdb',
    'telegraf-tsfdb',
    'telegraf-victoriametrics'
)
DEFAULT_MONITORING_METHOD = 'telegraf-influxdb'

GRAPHITE_URI = "http://graphite"

VICTORIAMETRICS_URI = "http://vmselect:8481/select/<org_id>/prometheus"
VICTORIAMETRICS_WRITE_URI = (f"http://vminsert:8480/insert/<org_id>/"
                             f"prometheus")

GRAPHITE_TO_VICTORIAMETRICS_METRICS_MAP = {}

VICTORIAMETRICS_TO_VICTORIAMETRICS_METRICS_MAP = {}

# Alert service's settings.
CILIA_TRIGGER_API = "http://api"
CILIA_SECRET_KEY = ""
CILIA_GRAPHITE_NODATA_TARGETS = (
    "load.shortterm", "load.midterm", "cpu.0.idle"
)
CILIA_INFLUXDB_NODATA_TARGETS = (
    "system.load1", "system.n_cpus", "cpu.cpu=cpu0.usage_user"
)
CILIA_FOUNDATIONDB_NODATA_TARGETS = (
    "system.load1", "system.n_cpus", "cpu.cpu=cpu0.usage_user"
)
CILIA_VICTORIAMETRICS_NODATA_TARGETS = (
    "system_load1", "system_n_cpus", 'cpu_usage_user{cpu="cpu0"}'
)

# Shard Manager settings. Can also be set through env variables.
SHARD_MANAGER_INTERVAL = 10
SHARD_MANAGER_MAX_SHARD_PERIOD = 60
SHARD_MANAGER_MAX_SHARD_CLAIMS = 500

# NoData alert suppression.
NO_DATA_ALERT_SUPPRESSION = False
NO_DATA_ALERT_BUFFER_PERIOD = 45
NO_DATA_RULES_RATIO = .2
NO_DATA_MACHINES_RATIO = .2

# number of api tokens user can have
ACTIVE_APITOKEN_NUM = 20
ALLOW_CONNECT_LOCALHOST = True
ALLOW_CONNECT_PRIVATE = True

# allow mist.io to connect to KVM hypervisor running on the same server
ALLOW_LIBVIRT_LOCALHOST = False

# Docker related
DOCKER_IP = "socat"
DOCKER_PORT = "2375"
DOCKER_TLS_KEY = ""
DOCKER_TLS_CERT = ""
DOCKER_TLS_CA = ""

MAILER_SETTINGS = {
    'mail.host': "mailmock",
    'mail.port': "8025",
    'mail.tls': False,
    'mail.starttls': False,
    'mail.username': "",
    'mail.password': "",
}

EMAIL_FROM = "Mist.io team <we@mist.io>"
EMAIL_ALERTS = "alert@mist.io"
EMAIL_REPORTS = "reports@mist.io"
EMAIL_INFO = "info@mist.io"
EMAIL_SALES = "sales@mist.io"
EMAIL_SUPPORT = "support@mist.io"
EMAIL_NOTIFICATIONS = "notifications@mist.io"
EMAIL_ALERTS_BCC = ""

GITHUB_BOT_TOKEN = ""

NO_VERIFY_HOSTS = []

MIXPANEL_ID = ""
FB_ID = ""
CHATWOOT_TOKEN = ""

FAILED_LOGIN_RATE_LIMIT = {
    'max_logins': 5,            # allow that many failed login attempts
    'max_logins_period': 60,    # in that many seconds
    'block_period': 60          # after that block for that many seconds
}

BANNED_EMAIL_PROVIDERS = [
    'qq.com',
    'mailinator.com',
    'bob.info',
    'veryreallemail.com',
    'spamherelots.com',
    'putthisinyourspamdatabase.com',
    'thisisnotmyrealemail.com',
    'binkmail.com',
    'spamhereplease.com',
    'sendspamhere.com',
    'chogmail.com',
    'spamthisplease.com',
    'frapmail.com',
    'obobbo.com',
    'devnullmail.com',
    'dispostable.com',
    'yopmail.com',
    'soodonims.com',
    'spambog.com',
    'spambog.de',
    'discardmail.com',
    'discardmail.de',
    'spambog.ru',
    'cust.in',
    '0815.ru',
    's0ny.net',
    'hochsitze.com',
    'hulapla.de',
    'misterpinball.de',
    'nomail2me.com',
    'dbunker.com',
    'bund.us',
    'teewars.org',
    'superstachel.de',
    'brennendesreich.de',
    'ano-mail.net',
    '10minutemail.com',
    'rppkn.com',
    'trashmail.net',
    'dacoolest.com',
    'junk1e.com',
    'throwawayemailaddress.com',
    'imgv.de',
    'spambastion.com',
    'dreameheap.com',
    'trollbot.org',
    'getairmail.com',
    'anonymizer.com',
    'dudmail.com',
    'scatmail.com',
    'trayna.com',
    'spamgourmet.com',
    'incognitomail.org',
    'mailexpire.com',
    'mailforspam.com',
    'sharklasers.com',
    'guerillamail.com',
    'guerrillamailblock.com',
    'guerrillamail.net',
    'guerrillamail.org',
    'guerrillamail.biz',
    'spam4.me',
    'grr.la',
    'guerrillamail.de',
    'trbvm.com',
    'byom.de'
]

###############################################################################
#  Different set in io and core
###############################################################################

SECRET = ""
SIGN_KEY = "dummy"

NOTIFICATION_EMAIL = {
    'all': "",
    'dev': "",
    'ops': "",
    'sales': "",
    'demo': "",
    'support': "",
}

# Sendgrid
SENDGRID_EMAIL_NOTIFICATIONS_KEY = ""

# Monitoring Related
GOOGLE_ANALYTICS_ID = ""

USE_EXTERNAL_AUTHENTICATION = False

LANDING_CATEGORIES = [{
    'href': '/',
    'name': 'home',
    'title': 'Home',
    'hiddenFromMenu': 1
}]

LANDING_FORMS = [
    'sign-in', 'sign-up', 'reset-password', 'forgot-password', 'set-password',
    'get-started', 'buy-license', 'request-pricing'
]

###############################################################################
# App constants
###############################################################################
STATES = {
    NodeState.RUNNING.value: 'running',
    NodeState.REBOOTING.value: 'rebooting',
    NodeState.TERMINATED.value: 'terminated',
    NodeState.PENDING.value: 'pending',
    # we assume unknown means stopped, especially for the EC2 case
    NodeState.UNKNOWN.value: 'unknown',
    NodeState.UPDATING.value: 'updating',
    NodeState.STOPPED.value: 'stopped',
    NodeState.ERROR.value: 'error',
    NodeState.PAUSED.value: 'paused',
    NodeState.SUSPENDED.value: 'suspended',
    NodeState.STARTING.value: 'starting',
    NodeState.STOPPING.value: 'stopping',
    NodeState.RECONFIGURING.value: 'reconfiguring',
    NodeState.MIGRATING.value: 'migrating',
    NodeState.NORMAL.value: 'normal',
    # The following are pod states returned by the Kubernetes API
    # https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-phase  # noqa
    NodeState.SUCCEEDED: 'succeeded',
    NodeState.FAILED: 'failed',
}

CLUSTER_STATES = [
    ClusterState.RUNNING.value,
    ClusterState.STARTING.value,
    ClusterState.STOPPING.value,
    ClusterState.TERMINATED.value,
    ClusterState.PENDING.value,
    ClusterState.UNKNOWN.value,
    ClusterState.ERROR.value,
    ClusterState.RECONFIGURING.value,
    ClusterState.UPDATING.value,
    # the following values are deprecated, we don't delete them to maintain
    # backwards compatibility
    'status_unspecified',
    'provisioning',
    'running',
    'reconciling',
    'stopping',
    'error',
    'degraded'
]

HELM_DOCKER_IMAGE = "alpine/helm:3.8.1"
HELM_DOCKER_IMAGE_WORKDIR = "/apps"

STAR_IMAGE_ON_MACHINE_CREATE = True

EC2_SECURITYGROUP = {
    'name': 'mistio',
    'description': 'Security group created by {portal_name}'
}

ECS_VPC = {
    'name': 'mistio',
    'description': 'Vpc created by {portal_name}'
}

ECS_SWITCH = {
    'name': 'mistio',
    'description': 'Switch created by {portal_name}'
}

ECS_SWITCH_CIDR_BLOCK_LENGTH = 27

# Linode datacenter ids/names mapping
LINODE_DATACENTERS = {
    2: 'Dallas, TX, USA',
    3: 'Fremont, CA, USA',
    4: 'Atlanta, GA, USA',
    6: 'Newark, NJ, USA',
    7: 'London, UK',
    8: 'Tokyo, JP',
    9: 'Singapore, SG',
    10: 'Frankfurt, DE'
}

# Alibaba volume types and permitted size ranges per type
# https://partners-intl.aliyun.com/help/doc-detail/25513.htm
ALIBABA_VOLUME_TYPES = {
    'cloud': (5, 2000),
    'cloud_efficiency': (20, 32768),
    'cloud_ssd': (20, 32768),
    'cloud_essd': (20, 32768),
}

VULTR_DDOS_PROTECTION_PRICE = 10
# Vultr automated backup per size
# Dedicated Cloud and Bare Metal sizes do not support backup
VULTR_BACKUP_PRICE_PER_SIZE = {
    'vc2-1c-1gb': 1,
    'vc2-1c-2gb': 2,
    'vc2-2c-4gb': 4,
    'vc2-4c-8gb': 8,
    'vc2-6c-16gb': 16,
    'vc2-8c-32gb': 32,
    'vc2-16c-64gb': 64,
    'vc2-24c-96gb': 128,
    'vhf-1c-1gb': 1.2,
    'vhf-1c-2gb': 2.4,
    'vhf-2c-2gb': 3.6,
    'vhf-2c-4gb': 4.8,
    'vhf-3c-8gb': 9.6,
    'vhf-4c-16gb': 19.2,
    'vhf-6c-24gb': 28.8,
    'vhf-8c-32gb': 38.4,
    'vhf-12c-48gb': 51.2,
}

ALIBABA_DEFAULT_VOLUME_TYPE = 'cloud'

PROVIDERS_WITH_CUSTOM_SIZES = ['vsphere', 'onapp', 'libvirt', 'lxd',
                               'kubevirt', 'cloudsigma']

PROVIDERS_WITH_TERMINATED_MACHINES_VISIBLE = ['ec2', 'libvirt', 'azure_arm']

PROVIDERS = {
    'amazon': {
        'name': 'Amazon Web Services',
        'aliases': ['aws', 'ec2'],
        'driver': 'ec2',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'container': {
                'kubernetes': True,
            },
            'provision': {
                'location': True,
                'cloudinit': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'dns': True,
            'storage': True,
            'networks': True,
            'objectstorage': True
        },
        'cost': {
            'kubernetes-control-plane': {
                'cph': 0.1,
                'cpm': 0,
            },
        },
    },
    'azure': {
        'name': 'Microsoft Azure',
        'aliases': ['arm', 'azure_arm'],
        'driver': 'azure_arm',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'location': True,
                'cloudinit': True,
                'key': {
                    'required': False,
                },
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': True,
                    'location-image-restriction': False,
                },
            },
            'storage': True,
            'networks': True
        }
    },
    'google': {
        'name': 'Google Cloud Platform',
        'aliases': ['gcp', 'gce', 'google cloud'],
        'driver': 'gce',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'container': {
                'kubernetes': True,
            },
            'provision': {
                'location': True,
                'cloudinit': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': True,
                    'location-image-restriction': False,
                },
            },
            'dns': True,
            'storage': True,
            'networks': True
        },
        'cost': {
            'kubernetes-control-plane': {
                'cph': 0.1,
                'cpm': 0,
            },
        },
    },
    'alibaba': {
        'name': 'Alibaba Cloud',
        'aliases': ['aliyun', 'aliyun ecs', 'ecs'],
        'driver': 'aliyun_ecs',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'location': True,
                'cloudinit': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': True,
                    'location-image-restriction': False,
                },
            },
            'storage': True,
            'networks': True
        },
    },
    'equinix': {
        'name': 'Equinix Metal',
        'aliases': ['packet', 'packet.net'],
        'driver': 'equinixmetal',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'location': True,
                'cloudinit': True,
                'restrictions': {
                    'size-image-restriction': True,
                    'location-size-restriction': True,
                    'location-image-restriction': False,
                },
            },
            'storage': False,
            'networks': True,
            'metal': True
        }
    },
    'ibm': {
        'name': 'IBM Cloud',
        'aliases': ['softlayer', 'ibm cloud'],
        'driver': 'softlayer',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'location': True,
                'cloudinit': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'metal': True
        }
    },
    'digitalocean': {
        'name': 'DigitalOcean',
        'aliases': [],
        'driver': 'digitalocean',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'location': True,
                'cloudinit': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': True,
                    'location-image-restriction': True,
                },
            },
            'storage': True,
        }
    },
    'linode': {
        'name': 'Linode',
        'aliases': [],
        'driver': 'linode',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'location': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'dns': True,
            'storage': True,
        }
    },
    'rackspace': {
        'name': 'Rackspace',
        'aliases': [],
        'driver': 'rackspace',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'location': False,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'dns': True,
            'storage': True,
        }
    },
    'maxihost': {
        'name': 'Maxihost',
        'aliases': [],
        'driver': 'maxihost',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'location': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'metal': True,
        }
    },
    'vultr': {
        'name': 'Vultr',
        'aliases': [],
        'driver': 'vultr',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'location': True,
                'cloudinit': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': True,
                    'location-image-restriction': False,
                },
            },
            'storage': True,
            'networks': True,
            'metal': True,
        }
    },
    'openstack': {
        'name': 'OpenStack',
        'aliases': [],
        'driver': 'openstack',
        'category': 'private cloud',
        'features': {
            'compute': True,
            'console': True,
            'provision': {
                'location': True,
                'cloudinit': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'storage': True,
            'objectstorage': True
        }
    },
    'vexxhost': {
        'name': 'Vexxhost',
        'aliases': [],
        'driver': 'openstack',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': True,
            'provision': {
                'location': False,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'storage': True,
            'objectstorage': True
        }
    },
    'onapp': {
        'name': 'OnApp',
        'aliases': [],
        'driver': 'onapp',
        'category': 'private cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'location': True,
                'custom_size': True,
                'key': {
                    'required': False,
                },
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'storage': False,
        }
    },
    'cloudsigma': {
        'name': 'CloudSigma',
        'aliases': [],
        'driver': 'cloudsigma',
        'category': 'public cloud',
        'features': {
            'compute': True,
            'console': False,
            'provision': {
                'cloudinit': True,
                'custom_size': True,
                'location': False,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'storage': True,
        }
    },
    'vsphere': {
        'name': 'vSphere',
        'aliases': ['vcenter', 'esxi'],
        'driver': 'vsphere',
        'category': 'private cloud',
        'features': {
            'compute': True,
            'console': True,
            'provision': {
                'location': True,
                'custom_size': True,
                'key': False,
                'custom_image': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'storage': False,
        }
    },
    'kvm': {
        'name': 'KVM',
        'aliases': ['libvirt'],
        'driver': 'libvirt',
        'category': 'hypervisor',
        'features': {
            'compute': True,
            'console': True,
            'provision': {
                'location': True,
                'cloudinit': True,
                'custom_size': True,
                'key': {
                    'required': False,
                },
                'custom_image': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'storage': False,
        }
    },
    'lxd': {
        'name': 'LXD',
        'aliases': ['lxc'],
        'driver': 'lxd',
        'category': 'container host',
        'features': {
            'compute': True,
            'container': {
                'container-service': True,
            },
            'provision': {
                'custom_size': True,
                'location': False,
                'key': False,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'storage': True,
        }
    },
    'docker': {
        'name': 'Docker',
        'aliases': [],
        'driver': 'docker',
        'category': 'container host',
        'features': {
            'compute': True,
            'console': False,
            'container': {
                'container-service': True,
            },
            'provision': {
                'location': False,
                'key': {
                    'required': False,
                },
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
                'custom_image': True,
            },
            'storage': False,
        }
    },
    'kubevirt': {
        'name': 'KubeVirt',
        'aliases': [],
        'driver': 'kubevirt',
        'category': 'container host',
        'features': {
            'compute': True,
            'console': False,
            'container': {
                'container-service': True,
            },
            'provision': {
                'location': True,
                'custom_size': True,
                'key': False,
                'custom_image': True,
                'restrictions': {
                    'size-image-restriction': False,
                    'location-size-restriction': False,
                    'location-image-restriction': False,
                },
            },
            'storage': True,
        }
    },
    'other': {
        'name': 'Other server',
        'aliases': ['ssh', 'bare_metal'],
        'driver': '',
        'category': 'other',
        'features': {
            'compute': True,
            'provision': False,
            'storage': False,
        }
    },
}

PROVIDERS['amazon']['regions'] = [
    {
        'location': 'Tokyo',
        'id': 'ap-northeast-1'
    },
    {
        'location': 'Seoul',
        'id': 'ap-northeast-2'
    },
    {
        'location': 'Osaka',
        'id': 'ap-northeast-3'
    },
    {
        'location': 'Singapore',
        'id': 'ap-southeast-1'
    },
    {
        'location': 'Sydney',
        'id': 'ap-southeast-2'
    },
    {
        'location': 'Frankfurt',
        'id': 'eu-central-1'
    },
    {
        'location': 'Ireland',
        'id': 'eu-west-1'
    },
    {
        'location': 'London',
        'id': 'eu-west-2'
    },
    {
        'location': 'Paris',
        'id': 'eu-west-3'
    },
    {
        'location': 'Stockholm',
        'id': 'eu-north-1'
    },
    {
        'location': 'Canada Central',
        'id': 'ca-central-1'
    },
    {
        'location': 'Sao Paulo',
        'id': 'sa-east-1'
    },
    {
        'location': 'N. Virginia',
        'id': 'us-east-1'
    },
    {
        'location': 'N. California',
        'id': 'us-west-1'
    },
    {
        'location': 'Oregon',
        'id': 'us-west-2'
    },
    {
        'location': 'Ohio',
        'id': 'us-east-2'
    },
    {
        'location': 'Mumbai',
        'id': 'ap-south-1'
    },
    {
        'location': 'Hong Kong',
        'id': 'ap-east-1'
    },
    {
        'location': 'Beijing',
        'id': 'cn-north-1'
    },
    {
        'location': 'Ningxia',
        'id': 'cn-northwest-1'
    },
    {
        'location': 'GovCloud (US)',
        'id': 'us-gov-west-1'
    },
    {
        'location': 'GovCloud (US-East)',
        'id': 'us-gov-east-1'
    },
]

PROVIDERS['alibaba']['regions'] = [
    {
        'location': 'China North 1 (Qingdao)',
        'id': 'cn-qingdao'
    },
    {
        'location': 'China North 2 (Beijing)',
        'id': 'cn-beijing'
    },
    {
        'location': 'China North 3 (Zhangjiakou)',
        'id': 'cn-zhangjiakou'
    },
    {
        'location': 'China North 5 (Huhehaote)',
        'id': 'cn-huhehaote'
    },
    {
        'location': 'China East 1 (Hangzhou)',
        'id': 'cn-hangzhou'
    },
    {
        'location': 'China East 2 (Shanghai)',
        'id': 'cn-shanghai'
    },
    {
        'location': 'China South 1 (Shenzhen)',
        'id': 'cn-shenzhen'
    },
    {
        'location': 'Hong Kong',
        'id': 'cn-hongkong'
    },
    {
        'location': 'EU Central 1 (Frankfurt)',
        'id': 'eu-central-1'
    },
    {
        'location': 'Middle East 1 (Dubai)',
        'id': 'me-east-1'
    },
    {
        'location': 'England (London)',
        'id': 'eu-west-1'
    },
    {
        'location': 'US West 1 (Silicon Valley)',
        'id': 'us-west-1'
    },
    {
        'location': 'US East 1 (Virginia)',
        'id': 'us-east-1'
    },
    {
        'location': 'South Asia 1 (Mumbai)',
        'id': 'ap-south-1'
    },
    {
        'location': 'Southeast Asia 5 (Jakarta)',
        'id': 'ap-southeast-5'
    },
    {
        'location': 'Southeast Asia 3 (Kuala Lumpur)',
        'id': 'ap-southeast-3'
    },
    {
        'location': 'Southeast Asia 2 (Sydney)',
        'id': 'ap-southeast-2'
    },
    {
        'location': 'Southeast Asia 1 (Singapore)',
        'id': 'ap-southeast-1'
    },
    {
        'location': 'Northeast Asia Pacific 1 (Tokyo)',
        'id': 'ap-northeast-1'
    },
]

PROVIDERS['rackspace']['regions'] = [
    {
        'location': 'Dallas',
        'id': 'dfw'
    },
    {
        'location': 'Chicago',
        'id': 'ord'
    },
    {
        'location': 'N. Virginia',
        'id': 'iad'
    },
    {
        'location': 'London',
        'id': 'lon'
    },
    {
        'location': 'Sydney',
        'id': 'syd'
    },
    {
        'location': 'Hong Kong',
        'id': 'hkg'
    },
    {
        'location': 'US-First Gen',
        'id': 'rackspace_first_gen:us'
    },
    {
        'location': 'UK-First Gen',
        'id': 'rackspace_first_gen:uk'
    },
]

# Deprecated in Mist v5
SUPPORTED_PROVIDERS = [
    # Other
    {
        'title': 'Other Server',
        'provider': 'other',
        'regions': []
    },
    # Azure
    {
        'title': 'Azure',
        'provider': Provider.AZURE,
        'regions': []
    },
    # AzureARM
    {
        'title': 'Azure ARM',
        'provider': Provider.AZURE_ARM,
        'regions': []
    },
    # EC2
    {
        'title': 'EC2',
        'provider': 'ec2',
        'regions': [
            {
                'location': 'Tokyo',
                'id': 'ap-northeast-1'
            },
            {
                'location': 'Seoul',
                'id': 'ap-northeast-2'
            },
            {
                'location': 'Osaka',
                'id': 'ap-northeast-3'
            },
            {
                'location': 'Singapore',
                'id': 'ap-southeast-1'
            },
            {
                'location': 'Sydney',
                'id': 'ap-southeast-2'
            },
            {
                'location': 'Frankfurt',
                'id': 'eu-central-1'
            },
            {
                'location': 'Ireland',
                'id': 'eu-west-1'
            },
            {
                'location': 'London',
                'id': 'eu-west-2'
            },
            {
                'location': 'Paris',
                'id': 'eu-west-3'
            },
            {
                'location': 'Stockholm',
                'id': 'eu-north-1'
            },
            {
                'location': 'Canada Central',
                'id': 'ca-central-1'
            },
            {
                'location': 'Sao Paulo',
                'id': 'sa-east-1'
            },
            {
                'location': 'N. Virginia',
                'id': 'us-east-1'
            },
            {
                'location': 'N. California',
                'id': 'us-west-1'
            },
            {
                'location': 'Oregon',
                'id': 'us-west-2'
            },
            {
                'location': 'Ohio',
                'id': 'us-east-2'
            },
            {
                'location': 'Mumbai',
                'id': 'ap-south-1'
            },
            {
                'location': 'Hong Kong',
                'id': 'ap-east-1'
            },
            {
                'location': 'Beijing',
                'id': 'cn-north-1'
            },
            {
                'location': 'Ningxia',
                'id': 'cn-northwest-1'
            },
            {
                'location': 'GovCloud (US)',
                'id': 'us-gov-west-1'
            },
            {
                'location': 'GovCloud (US-East)',
                'id': 'us-gov-east-1'
            },
        ]
    },
    # Alibaba Aliyun
    {
        'title': 'Alibaba',
        'provider': Provider.ALIYUN_ECS,
        'regions': [
            {
                'location': 'China North 1 (Qingdao)',
                'id': 'cn-qingdao'
            },
            {
                'location': 'China North 2 (Beijing)',
                'id': 'cn-beijing'
            },
            {
                'location': 'China North 3 (Zhangjiakou)',
                'id': 'cn-zhangjiakou'
            },
            {
                'location': 'China North 5 (Huhehaote)',
                'id': 'cn-huhehaote'
            },
            {
                'location': 'China East 1 (Hangzhou)',
                'id': 'cn-hangzhou'
            },
            {
                'location': 'China East 2 (Shanghai)',
                'id': 'cn-shanghai'
            },
            {
                'location': 'China South 1 (Shenzhen)',
                'id': 'cn-shenzhen'
            },
            {
                'location': 'Hong Kong',
                'id': 'cn-hongkong'
            },
            {
                'location': 'EU Central 1 (Frankfurt)',
                'id': 'eu-central-1'
            },
            {
                'location': 'Middle East 1 (Dubai)',
                'id': 'me-east-1'
            },
            {
                'location': 'England (London)',
                'id': 'eu-west-1'
            },
            {
                'location': 'US West 1 (Silicon Valley)',
                'id': 'us-west-1'
            },
            {
                'location': 'US East 1 (Virginia)',
                'id': 'us-east-1'
            },
            {
                'location': 'South Asia 1 (Mumbai)',
                'id': 'ap-south-1'
            },
            {
                'location': 'Southeast Asia 5 (Jakarta)',
                'id': 'ap-southeast-5'
            },
            {
                'location': 'Southeast Asia 3 (Kuala Lumpur)',
                'id': 'ap-southeast-3'
            },
            {
                'location': 'Southeast Asia 2 (Sydney)',
                'id': 'ap-southeast-2'
            },
            {
                'location': 'Southeast Asia 1 (Singapore)',
                'id': 'ap-southeast-1'
            },
            {
                'location': 'Northeast Asia Pacific 1 (Tokyo)',
                'id': 'ap-northeast-1'
            },
        ]
    },
    # GCE
    {
        'title': 'GCE',
        'provider': Provider.GCE,
        'regions': []
    },
    # DigitalOcean
    {
        'title': 'DigitalOcean',
        'provider': Provider.DIGITAL_OCEAN,
        'regions': []
    },
    # Linode
    {
        'title': 'Linode',
        'provider': Provider.LINODE,
        'regions': []
    },
    # OpenStack TODO: re-enable & test
    {
        'title': 'OpenStack',
        'provider': Provider.OPENSTACK,
        'regions': []
    },
    # Rackspace
    {
        'title': 'Rackspace',
        'provider': 'rackspace',
        'regions': [
            {
                'location': 'Dallas',
                'id': 'dfw'
            },
            {
                'location': 'Chicago',
                'id': 'ord'
            },
            {
                'location': 'N. Virginia',
                'id': 'iad'
            },
            {
                'location': 'London',
                'id': 'lon'
            },
            {
                'location': 'Sydney',
                'id': 'syd'
            },
            {
                'location': 'Hong Kong',
                'id': 'hkg'
            },
            {
                'location': 'US-First Gen',
                'id': 'rackspace_first_gen:us'
            },
            {
                'location': 'UK-First Gen',
                'id': 'rackspace_first_gen:uk'
            },
        ]
    },
    # Softlayer
    {
        'title': 'SoftLayer',
        'provider': Provider.SOFTLAYER,
        'regions': []
    },
    # Docker
    {
        'title': 'Docker',
        'provider': Container_Provider.DOCKER,
        'regions': []
    },

    # vCloud
    {
        'title': 'VMware vCloud',
        'provider': Provider.VCLOUD,
        'regions': []
    },
    # libvirt
    {
        'title': 'KVM (via libvirt)',
        'provider': Provider.LIBVIRT,
        'regions': []
    },
    # HostVirtual
    {
        'title': 'HostVirtual',
        'provider': Provider.HOSTVIRTUAL,
        'regions': []
    },
    # Vultr
    {
        'title': 'Vultr',
        'provider': Provider.VULTR,
        'regions': []
    },
    # vSphere
    {
        'title': 'VMWare vSphere',
        'provider': Provider.VSPHERE,
        'regions': []
    },
    # EquinixMetal
    {
        'title': 'EquinixMetal',
        'provider': Provider.EQUINIXMETAL,
        'regions': []
    },
    # Maxihost
    {
        'title': 'Maxihost',
        'provider': Provider.MAXIHOST,
        'regions': []
    },
    # KubeVirt
    {
        'title': 'Kubevirt',
        'provider': Provider.KUBEVIRT,
        'regions': []
    },
    # LXD
    {
        'title': 'LXD',
        'provider': 'lxd',
        'regions': []
    },
]

EC2_IMAGES_FILE = 'aws_default_images.json'
AZURE_IMAGES_FILE = 'azure_default_images.json'

# Base AMIs
EC2_IMAGES = {
    'eu-central-1': {
        'ami-e4c63e8b': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-009b16df9fcaac611': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-2eaeb342': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-09e8a19c9eda495b3': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-ba68bad5': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-b968bad6': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-02f9ea74050d6f812': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-c425e4ab': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-25a97a4a': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-060cde69': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-0932440befd74cdba': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
    },
    'eu-west-1': {
        'ami-02ace471': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-032e5b6af8a711f30': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-fa7cdd89': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-d1c0c4b7': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-01ccc867': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-096f43ef67d75e998': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-9186a1e2': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-00b5dfb1b867959fd': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-09447c6f': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-a8d2d7ce': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-0e5657f6d3c3ea350': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-022e8cc8f0d3c52fd': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
    },
    'eu-west-2': {
        'ami-9c363cf8': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-06178cf087598769c': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-63342007': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-f1d7c395': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-09b984029e6b0326b': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-005383956f2e5fb96': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-b6daced2': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-0ffd774e02309201f': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-a9eae0cd': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-9fc7cdfb': 'SUSE Linux Enterprise Server 11 SP4 (HVM), SSD Volume Type',  # noqa
        'ami-0d7db5fc4b5075b0d': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
    },
    'eu-west-3': {
        'ami-0ec28fc9814fce254': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-0f79604849d0fcaab': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-00f6fe7d6cbb56a78': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-021a167711a65e911': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0ba7c4110ca9bfe0b': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
    },
    'eu-north-1': {
        'ami-02a6bfdcf8224bd77': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-00d7bb1aabce7d22c': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-09b44b5f46219ee86': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0b10b3680c5d18124': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-08bc26bf92a90ba04': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type ',  # noqa
    },
    'eu-south-1': {
        'ami-00adf9322be77b621': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-08cef65729b7c8850': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-0e0812e2467b24796': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0ae9d70d4429d6724': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-04684e5a51afd7579': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
    },
    'ca-central-1': {
        'ami-9062d0f4': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-08523c5075ba75813': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-b3d965d7': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-beea56da': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-04b46a87fa4d13308': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0df58bd52157c6e83': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0bd66a6f': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-0df612970f825f04c': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-14368470': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-1562d071': 'SUSE Linux Enterprise Server 11 SP4 (HVM), SSD Volume Type',  # noqa
        'ami-0d8c9795f4f9f51c0': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
    },
    'us-east-1': {
        'ami-b63769a1': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-096fda3c22c1c990a': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-772aa961': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-80861296': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-02fe94dee086c0c37': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-03d315ad33b9d49c4': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-70065467': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-668f1e70': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-c58c1dd3': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-0915bcb5fa77e4892': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-fde4ebea': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-0fde50fcbcd46f2f7': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-8fb03898': 'ClearOS 7.2.0',
        'ami-0397f56a': 'ClearOS Community 6.4.0 ',
        'ami-ff9af896': 'ClearOS Professional 6.4.0'
    },
    'us-east-2': {
        'ami-0932686c': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-03d64741867e7bb94': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-0996d3051b72b5b2c': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-02aa7f3de34db391a': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-618fab04': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-8fab8fea': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-4191b524': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-09246ddb00c7c4fef': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-61a7fd04': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-4af2a92f': 'SUSE Linux Enterprise Server 11 SP4 (HVM), SSD Volume Type',  # noqa
        'ami-0f052119b3c7e61d1': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
    },
    'us-west-1': {
        'ami-09d9c5cdcfb8fc655': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-2cade64c': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-0ebef2838fb2605b7': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0d9b7049d327ec00d': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-2afbde4a': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-1da8f27d': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-e7a4cc87': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-066c82dabe6dd7f73': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-0f85a06f': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-7a85a01a': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-05c558c169cfe8d99': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-e09acc80': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
    },
    'us-west-2': {
        'ami-01e78c5619c5e68b4': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-6f68cf0f': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-0928f4202481dfdf6': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-025102f49d03bec05': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-efd0428f': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-7c22b41c': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-0174313b5af8423d7': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-baab0fda': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-09c5e030f74651050': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-c737a5a7': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-4836a428': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-e4a30084': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
    },
    'ap-northeast-1': {
        'ami-0dc185deadd3ac449': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-5de0433c': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-0e039c7d64008bd84': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-09dac16017637391f': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-afb09dc8': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-d85e7fbf': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-0cbc0209196a8063b': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-27fed749': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-09d28faae2e9e7138': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-30391657': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-923d12f5': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-e21c7285': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
    },
    'ap-northeast-2': {
        'ami-07270d166cdf39adc': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-44db152a': 'Red Hat Enterprise Linux 7.2 (HVM), SSD Volume Type',
        'ami-067abcae434ee508b': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0b50511490117e709': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-66e33108': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-15d5077b': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-006e2f9fa7597680a': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-9d15c7f3': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-097fc5cd098dd20d5': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-5060b73e': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
    },
    'sa-east-1': {
        'ami-079b1541b6dc958ca': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-7de77b11': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-0e765cee959bcbfce': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-06a550af32c7dda36': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-4090f22c': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-02777cd0ce58a1847': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-029a1e6e': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-0a0bc0fa94d632c94': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-36cfad5a': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-37cfad5b': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-e1cd558d': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-8df695e1': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
    },
    'ap-southeast-1': {
        'ami-0f86a70488991335e': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-2c95344f': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-09a6a7e49bd29554b': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0ae3e6717dc99c62b': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-8fcc75ec': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-0a19a669': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-1a5f9f79': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-0d06583a13678c938': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-ab5ce5c8': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-fc5ae39f': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-03e8d3c5c16f119bb': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-67b21d04': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
    },
    'ap-southeast-2': {
        'ami-044c46b1952ad5861': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-39ac915a': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-0d767dd04ac152743': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-080b87fdc6d5ca853': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-96666ff5': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-807876e3': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-0e413a9954960d83a': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-8ea3fbed': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-075a72b1992cb0687': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-af2128cc': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-162c2575': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-527b4031': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
    },
    'ap-south-1': {
        'ami-0a9d27a9f4f5c0efc': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
        'ami-cdbdd7a2': 'Red Hat Enterprise Linux 7.2 (HVM), SSD Volume Type',
        'ami-073c8c0760395aab8': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0e8710d48cc4ea8dd': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-c2ee9dad': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-83a8dbec': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-0eeb03e72075b9bcc': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-52c7b43d': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-8f8afde0': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-0b3acf3edf2397475': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
    },
    'ap-east-1': {
      'ami-04864d873127e4b0a': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
      'ami-0a3a9dd4bc68bae02': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
      'ami-0b4017973f2328b15': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
      'ami-015e90097eca079a6': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
      'ami-f4fab885': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',
    },
    'me-south-1': {
        'ami-0e3fd15abd8ba3d3c': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-095711532f1d50122': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-07bf297712e054a41': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0c288c79750011574': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0b41a37a62a4296fc': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
    },
    'af-south-1': {
        'ami-03dd45f91b6676f74': 'Amazon Linux 2 AMI (HVM), SSD Volume Type',
        'ami-0950dcf60f02f2731': 'SUSE Linux Enterprise Server 15 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-0f072aafc9dfcb24f': 'Ubuntu Server 20.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0fcf986c07ff1a0c2': 'Ubuntu Server 18.04 LTS (HVM), SSD Volume Type',  # noqa
        'ami-0f4b49fefef9be45a': 'Red Hat Enterprise Linux 8 (HVM), SSD Volume Type',  # noqa
    },
}

DOCKER_IMAGES = {
    'mist/debian-ssh': 'Debian Bullseye with SSH server',
}

AZURE_ARM_IMAGES = {
    'MicrosoftWindowsServer:WindowsServer:2012-Datacenter:9200.22776.20190604': 'MicrosoftWindowsServer WindowsServer 2012-Datacenter',  # noqa
    'MicrosoftWindowsServer:WindowsServer:2012-Datacenter-smalldisk:9200.22830.1908092125': 'MicrosoftWindowsServer WindowsServer 2012-Datacenter-smalldisk',  # noqa
    'MicrosoftWindowsServer:WindowsServer:2016-Datacenter-Server-Core-smalldisk:14393.3025.20190604': 'MicrosoftWindowsServer WindowsServer 2016-Datacenter-Server-Core-smalldisk',  # noqa
    'MicrosoftWindowsServer:WindowsServer:2016-Datacenter-with-Containers:2016.127.20190603': 'MicrosoftWindowsServer WindowsServer 2016-Datacenter-with-Containers',  # noqa
    'MicrosoftWindowsServer:WindowsServer:2019-Datacenter:2019.0.20190410': 'MicrosoftWindowsServer WindowsServer 2019-Datacenter',  # noqa
    'Canonical:UbuntuServer:16.04.0-LTS:16.04.201906280': 'Canonical UbuntuServer 16.04.0-LTS',  # noqa
    'Canonical:UbuntuServer:18.04-LTS:18.04.201908131': 'Canonical UbuntuServer 18.04-LTS',  # noqa
    'RedHat:RHEL:7.3:7.3.2017090723': 'RedHat RHEL 7.3 7.3.2017090723',
    'RedHat:RHEL:6.9:6.9.2017090105': 'RedHat RHEL 6.9 6.9.2017090105',
}

GCE_IMAGES = ['debian-cloud',
              'centos-cloud',
              'suse-cloud',
              'rhel-cloud',
              'coreos-cloud',
              'gce-nvme',
              'google-containers',
              'opensuse-cloud',
              'suse-cloud',
              'ubuntu-os-cloud',
              'windows-cloud']

AZURE_SECURITY_RULES = [
    {
        "name": "allowSSHInbound",
        "properties": {
            "protocol": "*",
            "sourceAddressPrefix": "*",
            "destinationAddressPrefix": "*",
            "access": "Allow",
            "destinationPortRange": "22",
            "sourcePortRange": "*",
            "priority": 200,
            "direction": "Inbound"
        }
    },
    {
        "name": "allowRDPInbound",
        "properties": {
            "protocol": "*",
            "sourceAddressPrefix": "*",
            "destinationAddressPrefix": "*",
            "access": "Allow",
            "destinationPortRange": "3389",
            "sourcePortRange": "*",
            "priority": 201,
            "direction": "Inbound"
        }
    },
    {
        "name": "allowMonitoringOutbound",
        "properties": {
            "protocol": "*",
            "sourceAddressPrefix": "*",
            "destinationAddressPrefix": "*",
            "access": "Allow",
            "destinationPortRange": "25826",
            "sourcePortRange": "*",
            "priority": 202,
            "direction": "Outbound"
        }
    }
]

RESET_PASSWORD_EXPIRATION_TIME = 60 * 60 * 24

WHITELIST_IP_EXPIRATION_TIME = 60 * 60 * 24

# Email templates

CONFIRMATION_EMAIL_SUBJECT = "[{portal_name}] Confirm your registration"

CONFIRMATION_EMAIL_BODY = """Hello {fname},

we received a registration request to {portal_name} from this email address.

To activate your account, please click on the following link:

{portal_uri}/confirm?key={activation_key}

{follow_us}This request originated from the IP address {ip_addr}.

If it wasn't you, simply ignore this message.

Best regards,
The {portal_name} team
"""

FOLLOW_US = "In the meantime, stay up-to-date by following us on"\
    "https://twitter.com/mist_io"


RESET_PASSWORD_EMAIL_SUBJECT = "[{portal_name}] Password reset request"

RESET_PASSWORD_EMAIL_BODY = """Hello {fname},

We have received a request to change your password.
Please click on the following link:

{portal_uri}/reset-password?key={activation_key}

This request originated from the IP address {ip_addr}.

If it wasn't you, simply ignore this message.
Your password has not been changed.


Best regards,
The {portal_name} team
"""

MACHINE_EXPIRE_NOTIFY_EMAIL_SUBJECT = \
    "[{portal_name}] Machine is about to expire"

MACHINE_EXPIRE_NOTIFY_EMAIL_BODY = """Hello {fname},

Your machine `{machine_name}` will expire on {expiration}

If you'd like to prevent that, please update the expiration date at {uri}
{custom_msg}
Best regards,
The {portal_name} team
"""

WHITELIST_IP_EMAIL_SUBJECT = "[{portal_name}] Account IP whitelist request"

WHITELIST_IP_EMAIL_BODY = """Hello {fname},

We have received a request to whitelist the IP you just tried to login with.
Please click on the following link to finish this action:

{portal_uri}/confirm-whitelist?key={confirmation_key}

This request originated from the IP address {ip_addr}.
If it wasn't you, simply ignore this message.
The above IP will not be whitelisted.


Best regards,
The {portal_name} team
"""


FAILED_LOGIN_ATTEMPTS_EMAIL_SUBJECT = \
    "[{portal_name}] Failed login attempts warning"

FAILED_LOGIN_ATTEMPTS_EMAIL_BODY = """
================= Failed login attempts warning =================

Too many failed login attempts for the same account and from the same IP
address occurred. Future login attempts for this user/ip will be
temporarily blocked to thwart a brute-force attack.

User: {email}
IP address: {ip_addr}
Number of failed attempts: {failed_attempts}
Time period of failed login attempts: {time_period}
Blocking period: {block_period}
"""

ORG_TEAM_STATUS_CHANGE_EMAIL_SUBJECT = \
    "[{portal_name}] Your status in an organization has changed"

ORG_NOTIFICATION_EMAIL_SUBJECT = "[{portal_name}] Subscribed to team"

USER_NOTIFY_ORG_TEAM_ADDITION = """Hello {fname}

You have been added to the team "{team}" of organization {org}.

Best regards,
The {portal_name} team
"""

USER_CONFIRM_ORG_INVITATION_EMAIL_BODY = """Hi {fname}

You have been invited by {invited_by} to join the "{org}" organization
as a member of the "{team}" team.

To confirm your invitation, please click on the following link:

{portal_uri}/confirm-invitation?invitoken={invitoken}

Once you are done with the confirmation process,
you will be able to login to your Mist.io user account
as a member of the team "{team}".

Best regards,
The {portal_name} team
"""

ORG_INVITATION_EMAIL_SUBJECT = "[{portal_name}] Confirm your invitation"

REGISTRATION_AND_ORG_INVITATION_EMAIL_BODY = """Hello {fname}

You have been invited by {invited_by} to join the "{org}" organization
as a member of the "{team}" team.

In order to accept the invitation, please click on the
following link:

{portal_uri}/confirm?key={activation_key}&invitoken={invitoken}

Best regards,
The {portal_name} team
"""

NOTIFY_REMOVED_FROM_TEAM = """Hello {fname}

You have been removed from team "{team}" of organization "{org}" by the
administrator "{admin}".

Best regards,
The {portal_name} team
"""

NOTIFY_REMOVED_FROM_ORG = """Hello {fname}

You are no longer a member of the organization "{org}".

Best regards,
The {portal_name} team
"""

NOTIFY_INVITATION_REVOKED_SUBJECT = \
    "[{portal_name}] Invitation for organization revoked"

NOTIFY_INVITATION_REVOKED = """Hello {fname}

Your invitation to the organization "{org}" has been revoked.

Best regards,
The {portal_name} team
"""

NO_DATA_ALERT_SUPPRESSION_SUBJECT = "[{portal_name}] Suppressed no-data rule"

NO_DATA_ALERT_SUPPRESSION_BODY = """
           ********** %(rule)s triggered and suppressed **********

%(nodata_rules_firing)d/%(total_number_of_nodata_rules)d of no-data rules
(%(rules_percentage)d%%) have been triggered.

%(mon_machines_firing)d/%(total_num_monitored_machines)d of monitored machines
(%(machines_percentage)d%%) have no monitoring data available.

Click the link below to delete and completely forget all suppressed alerts:
%(delete_alerts_link)s

Click the link below to unsuppress all suppressed alerts:
%(unsuppress_alerts_link)s

Note that the above action will actually send the alerts, if the corresponding
rules are re-triggered during the next evaluation cycle.
"""
CREATE_APITOKEN_SUBJECT = "[{portal_name}] New API Token has been issued"

CREATE_APITOKEN_BODY = """Hello {fname},

You requested a new API token which has been issued.
The request originated from the IP address {ip_addr}.

If it was not you we suggest that you:
1. Revoke the new token immediately at {portal_uri}/my-account/tokens
2. Change your password
3. Contact {support_email}

Best regards,
The {portal_name} team
"""

CTA = {
    "rbac": {
        "action": "UPGRADE YOUR MIST.IO",
        "uri": "https://mist.io/get-started",
        "description": "Role based access policies are available in the "
                       "Enterprise Edition and the Hosted Service."
    }
}

SHOW_FOOTER = False
REDIRECT_HOME_TO_SIGNIN = False
ALLOW_SIGNUP_EMAIL = True
ALLOW_SIGNUP_GOOGLE = False
ALLOW_SIGNUP_GITHUB = False
ALLOW_SIGNUP_MS365 = False
ALLOW_SIGNUP_CILOGON = False
ALLOW_SIGNIN_EMAIL = True
ALLOW_SIGNIN_GOOGLE = False
ALLOW_SIGNIN_GITHUB = False
ALLOW_SIGNIN_MS365 = False
ALLOW_SIGNIN_CILOGON = False
LDAP_SETTINGS = {}
DEFAULT_SIGNIN_METHOD = 'email'
STRIPE_PUBLIC_APIKEY = False
ENABLE_AB = False
ENABLE_R12N = False
ENABLE_MONITORING = True
ENABLE_SHELL_CAPTURE = False
MACHINE_PATCHES = True
DEFAULT_CLOUD_POLLING_INTERVAL = 30 * 60
PROCESS_POOL_WORKERS = 0
PLUGINS = []
PRE_ACTION_HOOKS = {}
POST_ACTION_HOOKS = {}
CURRENCY = {
    'sign': '$',
    'rate': '1'
}
ENABLE_VSPHERE_REST = False
VSPHERE_IMAGE_FOLDERS = []
VSPHERE_FETCH_ALL_EXTRA = True
UGLY_RBAC = ""

# DO NOT PUT ANYTHING BELOW HERE UNLESS YOU KNOW WHAT YOU ARE DOING

CONFIG_OVERRIDE_FILES = []

# Load defaults file if defined
DEFAULTS_FILE = os.getenv('DEFAULTS_FILE')
if DEFAULTS_FILE:
    CONFIG_OVERRIDE_FILES.append(os.path.abspath(DEFAULTS_FILE))

# Get settings from settings file.
SETTINGS_FILE = os.path.abspath(os.getenv('SETTINGS_FILE') or 'settings.py')
CONFIG_OVERRIDE_FILES.append(SETTINGS_FILE)

# Load all config override files. SETTINGS_FILE should be the last one to load
# This first pass will get us the list of configured plugins.
# We will load the plugin configs and then we'll reload the config overrides
for override_file in CONFIG_OVERRIDE_FILES:
    if os.path.exists(override_file):
        log.warn("Reading settings from %s" % override_file)
        CONF = {}
        exec(compile(open(override_file).read(), override_file, 'exec'), CONF)
        for key in CONF:
            if isinstance(locals().get(key), dict) and isinstance(CONF[key],
                                                                  dict):
                locals()[key].update(CONF[key])
            else:
                locals()[key] = CONF[key]
    else:
        log.error("Couldn't find settings file in %s" % override_file)

# Load all plugin config files. Plugins may define vars that can be overridden
# by environmental variables
PLUGIN_ENV_STRINGS = []
PLUGIN_ENV_INTS = []
PLUGIN_ENV_BOOLS = []
PLUGIN_ENV_ARRAYS = []

for plugin in PLUGINS:
    try:
        plugin_env = {}
        exec('from mist.%s.config import *' % plugin, plugin_env)
        for key in plugin_env:
            # Allow plugins to define vars that can be overridden by env
            if key in ['PLUGIN_ENV_STRINGS', 'PLUGIN_ENV_INTS',
                       'PLUGIN_ENV_BOOLS', 'PLUGIN_ENV_ARRAYS']:
                locals()[key] += plugin_env[key]
            elif isinstance(locals().get(key), dict) and \
                    isinstance(plugin_env[key], dict):
                locals()[key].update(plugin_env[key])
            else:
                locals()[key] = plugin_env[key]
        log.warn("Imported config of `%s` plugin" % plugin)
    except Exception as exc:
        log.error("Failed to import config of `%s` plugin: %r" % (
            plugin, exc))

# Get settings from environmental variables.
FROM_ENV_STRINGS = [
    'AMQP_URI', 'BROKER_URL', 'CORE_URI', 'MONGO_URI', 'MONGO_DB', 'DOCKER_IP',
    'DOCKER_PORT', 'DOCKER_TLS_KEY', 'DOCKER_TLS_CERT', 'DOCKER_TLS_CA',
    'UI_TEMPLATE_URL', 'LANDING_TEMPLATE_URL', 'THEME',
    'DEFAULT_MONITORING_METHOD', 'LICENSE_KEY', 'AWS_ACCESS_KEY',
    'AWS_SECRET_KEY', 'AWS_MONGO_BUCKET', 'VAULT_ADDR', 'VAULT_TOKEN'
] + PLUGIN_ENV_STRINGS
FROM_ENV_INTS = [
    'SHARD_MANAGER_MAX_SHARD_PERIOD', 'SHARD_MANAGER_MAX_SHARD_CLAIMS',
    'SHARD_MANAGER_INTERVAL',
] + PLUGIN_ENV_INTS
FROM_ENV_BOOLS = [
    'SSL_VERIFY', 'ALLOW_CONNECT_LOCALHOST', 'ALLOW_CONNECT_PRIVATE',
    'ALLOW_LIBVIRT_LOCALHOST', 'JS_BUILD', 'VERSION_CHECK', 'USAGE_SURVEY',
] + PLUGIN_ENV_BOOLS
FROM_ENV_ARRAYS = [
    'PLUGINS'
] + PLUGIN_ENV_ARRAYS
log.info("Reading settings from environmental variables.")
for key in FROM_ENV_STRINGS:
    if os.getenv(key):
        locals()[key] = os.getenv(key)
for key in FROM_ENV_INTS:
    if os.getenv(key):
        try:
            locals()[key] = int(os.getenv(key))
        except (KeyError, ValueError):
            log.error("Invalid value for %s: %s" % (key, os.getenv(key)))
for key in FROM_ENV_BOOLS:
    if os.getenv(key) is not None:
        locals()[key] = os.getenv(key) in ('1', 'true', 'True')
for key in FROM_ENV_ARRAYS:
    if os.getenv(key):
        locals()[key] = os.getenv(key).split(',')


# Load all config override files one last time after loading plugins.
# SETTINGS_FILE should be the last one to load
for override_file in CONFIG_OVERRIDE_FILES:
    if os.path.exists(override_file):
        log.info("Reading settings from %s" % override_file)
        CONF = {}
        exec(compile(open(override_file).read(), override_file, 'exec'), CONF)
        for key in CONF:
            if isinstance(locals().get(key), dict) and isinstance(CONF[key],
                                                                  dict):
                locals()[key].update(CONF[key])
            else:
                locals()[key] = CONF[key]
    else:
        log.error("Couldn't find settings file in %s" % override_file)

HAS_BILLING = 'billing' in PLUGINS
HAS_RBAC = 'rbac' in PLUGINS
HAS_INSIGHTS = 'insights' in PLUGINS
HAS_ORCHESTRATION = 'orchestration' in PLUGINS
HAS_CLOUDIFY_INSIGHTS = HAS_INSIGHTS and HAS_ORCHESTRATION \
    and HAS_RBAC and 'cloudify_insights' in PLUGINS
HAS_VPN = 'vpn' in PLUGINS
HAS_EXPERIMENTS = 'experiments' in PLUGINS
HAS_MANAGE = 'manage' in PLUGINS
HAS_AUTH = 'auth' in PLUGINS
HAS_PRICING = 'pricing' in PLUGINS

# enable backup feature if aws creds have been set
ENABLE_BACKUPS = bool(BACKUP['key']) and bool(BACKUP['secret'])

# Update TELEGRAF_TARGET.

if not TELEGRAF_TARGET:
    if urllib.parse.urlparse(CORE_URI).hostname in ('localhost', '127.0.0.1',
                                                    '172.17.0.1'):
        TELEGRAF_TARGET = "http://traefik"
    else:
        TELEGRAF_TARGET = CORE_URI + '/ingress'


_schedule = {}
if VERSION_CHECK:
    _schedule['version-check'] = {
        'task': 'mist.api.portal.tasks.check_new_versions',
        'schedule': datetime.timedelta(hours=24),
        # 'args': ('https://mist.io/api/v1/version-check', ),
    }
if USAGE_SURVEY:
    _schedule['usage-survey'] = {
        'task': 'mist.api.portal.tasks.usage_survey',
        'schedule': datetime.timedelta(hours=24),
        # 'args': ('https://mist.io/api/v1/usage-survey', ),
    }
if GC_SCHEDULERS:
    _schedule['gc-schedulers'] = {
        'task': 'mist.api.portal.tasks.gc_schedulers',
        'schedule': datetime.timedelta(hours=24),
    }
if GC_SESSIONS:
    _schedule['gc-sessions'] = {
        'task': 'mist.api.portal.tasks.gc_sessions',
        'schedule': datetime.timedelta(hours=24),
    }
if GC_NODATARULETRACKER:
    _schedule['gc-nodataruletracker'] = {
        'task': 'mist.api.notifications.tasks.gc_nodataruletracker',
        'schedule': datetime.timedelta(hours=24),
    }
if ELASTICSEARCH_CLEANUP:
    _schedule['elasticsearch-cleanup'] = {
        'task': 'mist.api.logs.tasks.elasticsearch_cleanup',
        'schedule': datetime.timedelta(days=30),
    }
if ENABLE_MONITORING:
    _schedule['reset-traefik'] = {
        'task': 'mist.api.monitoring.tasks.reset_traefik_config',
        'schedule': datetime.timedelta(seconds=90),
    }
    _schedule['set-activated-at'] = {
        'task': 'mist.api.monitoring.tasks.set_activated_at',
        'schedule': datetime.timedelta(seconds=10),
    }

if ENABLE_BACKUPS:
    _schedule['backups'] = {
        'task': 'mist.api.portal.tasks.create_backup',
        'schedule': datetime.timedelta(hours=BACKUP_INTERVAL),
    }


# Configure libcloud to not verify certain hosts.
if NO_VERIFY_HOSTS:
    if DOCKER_IP:
        NO_VERIFY_HOSTS.append(DOCKER_IP)
    libcloud.security.NO_VERIFY_MATCH_HOSTNAMES = NO_VERIFY_HOSTS

WHITELIST_CIDR = [
]

if LDAP_SETTINGS and LDAP_SETTINGS.get('SERVER'):
    if LDAP_SETTINGS.get('AD'):
        ALLOW_SIGNIN_AD = True
        ALLOW_SIGNIN_LDAP = False
    else:
        ALLOW_SIGNIN_AD = False
        ALLOW_SIGNIN_LDAP = True
else:
    ALLOW_SIGNIN_AD = False
    ALLOW_SIGNIN_LDAP = False

HOMEPAGE_INPUTS = {
    'portal_name': PORTAL_NAME,
    'portal_uri': CORE_URI,
    'theme': THEME,
    'cta': CTA,
    'description': DESCRIPTION,
    'features': {
        'monitoring': ENABLE_MONITORING,
        'rbac': HAS_RBAC,
        'orchestration': HAS_ORCHESTRATION,
        'insights': HAS_INSIGHTS,
        'billing': HAS_BILLING,
        'tunnels': HAS_VPN,
        'ab': ENABLE_AB,
        'r12ns': ENABLE_R12N,
        'signup_email': ALLOW_SIGNUP_EMAIL,
        'signup_google': ALLOW_SIGNUP_GOOGLE,
        'signup_github': ALLOW_SIGNUP_GITHUB,
        'signup_ms365': ALLOW_SIGNUP_MS365,
        'signup_cilogon': ALLOW_SIGNUP_CILOGON,
        'signin_email': ALLOW_SIGNIN_EMAIL,
        'signin_google': ALLOW_SIGNIN_GOOGLE,
        'signin_github': ALLOW_SIGNIN_GITHUB,
        'signin_ldap': ALLOW_SIGNIN_LDAP,
        'signin_ad': ALLOW_SIGNIN_AD,
        'signin_ms365': ALLOW_SIGNIN_MS365,
        'signin_cilogon': ALLOW_SIGNIN_CILOGON,
        'default_signin_method': DEFAULT_SIGNIN_METHOD.lower(),
        'signin_home': REDIRECT_HOME_TO_SIGNIN,
        'landing_footer': SHOW_FOOTER,
        'docs': DOCS_URI,
        'support': SUPPORT_URI,
        'currency': CURRENCY
    },
    'email': {
        'info': EMAIL_INFO,
        'support': EMAIL_SUPPORT,
        'sales': EMAIL_SALES
    },
    'fb_id': FB_ID,
    'chatwoot_token': CHATWOOT_TOKEN,
    'google_analytics_id': GOOGLE_ANALYTICS_ID,
    'mixpanel_id': MIXPANEL_ID,
    'categories': LANDING_CATEGORIES
}

if HAS_BILLING and STRIPE_PUBLIC_APIKEY:
    HOMEPAGE_INPUTS['stripe_public_apikey'] = STRIPE_PUBLIC_APIKEY

if not VAULT_ROLE_ID:
    try:
        with open('/approle/role_id', 'r') as file:
            VAULT_ROLE_ID = file.read().replace('\n', '')
        with open('/approle/secret_id', 'r') as file:
            VAULT_SECRET_ID = file.read().replace('\n', '')
    except FileNotFoundError:
        pass

# DO NOT PUT REGULAR SETTINGS BELOW, PUT THEM ABOVE THIS SECTION

# Read version info
VERSION = {}
try:
    with open('/mist-version.json', 'r') as fobj:
        VERSION = json.load(fobj)
except Exception:
    log.error("Couldn't load version info.")
