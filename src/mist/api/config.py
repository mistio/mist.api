"""Basic configuration and mappings
   Here we define constants needed by mist.api
   Also, the configuration from settings.py is exposed through this module.
"""
import os
import sys
import ssl
import json
import logging
import datetime
import urlparse

import libcloud.security
from libcloud.compute.types import Provider
from libcloud.container.types import Provider as Container_Provider

from libcloud.compute.types import NodeState


libcloud.security.SSL_VERSION = ssl.PROTOCOL_TLSv1_2


def dirname(path, num=1):
    """Get absolute path of `num` directories above path"""
    path = os.path.abspath(path)
    for _ in xrange(num):
        path = os.path.dirname(path)
    return path


MIST_API_DIR = dirname(__file__, 4)
print >> sys.stderr, "MIST_API_DIR is %s" % MIST_API_DIR


###############################################################################
# The following variables are common for both open.source and mist.core
###############################################################################

PORTAL_NAME = "Mist.io"
CORE_URI = "http://localhost"
AMQP_URI = "rabbitmq:5672"
MEMCACHED_HOST = ["memcached:11211"]
BROKER_URL = "amqp://guest:guest@rabbitmq/"
SSL_VERIFY = True
THEME = ""

GC_SCHEDULERS = True
VERSION_CHECK = True
USAGE_SURVEY = False

ELASTICSEARCH = {
    'elastic_host': 'elasticsearch',
    'elastic_port': '9200',
    'elastic_username': '',
    'elastic_password': '',
    'elastic_use_ssl': False,
    'elastic_verify_certs': False
}

UI_TEMPLATE_URL = "http://ui"
LANDING_TEMPLATE_URL = "http://landing"

PY_LOG_LEVEL = logging.INFO
PY_LOG_FORMAT = '%(asctime)s %(levelname)s %(threadName)s %(module)s - %(funcName)s: %(message)s'  # noqa
PY_LOG_FORMAT_DATE = "%Y-%m-%d %H:%M:%S"
LOG_EXCEPTIONS = True

JS_BUILD = False
CSS_BUILD = False
JS_LOG_LEVEL = 3

ENABLE_DEV_USERS = False

MONGO_URI = "mongodb:27017"
MONGO_DB = "mist2"

DOMAIN_VALIDATION_WHITELIST = []

# InfluxDB
INFLUX = {
    "host": "http://influxdb:8086", "db": "telegraf"
}

TELEGRAF_TARGET = ""
TRAEFIK_API = "http://traefik:8080"

# Default, built-in metrics.
INFLUXDB_BUILTIN_METRICS = {
    'cpu.cpu=cpu-total.usage_user': {
        'name': 'CPU',
        'unit': '%',
        'max_value': 100,
        'min_value': 0,
    },
    'system.load1': {
        'name': 'Load',
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

INFLUXDB_MACHINE_DASHBOARD_DEFAULT = {
    "meta": {},
    "dashboard": {
        "id": 1,
        "refresh": "10sec",
        "rows": [{
            "panels": [{
                "id": 0,
                "title": "Load",
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
                    "format": "octets"
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
                    "target": "net.bytes_sent"
                }],
                "yaxes": [{
                    "format": "octets"
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
                    "target": "diskio.read_bytes"
                }],
                "x-axis": True,
                "y-axis": True
            }, {
                "id": 7,
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
                    "format": "octets"
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

MONITORING_METHODS = (
    'collectd-graphite',
    'telegraf-influxdb',
    'telegraf-graphite',
)
DEFAULT_MONITORING_METHOD = 'telegraf-influxdb'

GRAPHITE_URI = "http://graphite"

# Alert service's authentication key
CILIA_TRIGGER = False
CILIA_SECRET_KEY = ""

# number of api tokens user can have
ACTIVE_APITOKEN_NUM = 20
ALLOW_CONNECT_LOCALHOST = True
ALLOW_CONNECT_PRIVATE = True

# allow mist.io to connect to KVM hypervisor running on the same server
ALLOW_LIBVIRT_LOCALHOST = False

# Docker related
DOCKER_IP = "172.17.0.1"
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
EMAIL_NOTIFICATIONS = "notifications@mist.io"
EMAIL_ALERTS_BCC = ""

GITHUB_BOT_TOKEN = ""

NO_VERIFY_HOSTS = []

MIXPANEL_ID = ""
FB_ID = ""
OLARK_ID = ""

FAILED_LOGIN_RATE_LIMIT = {
    'max_logins': 5,            # allow that many failed login attempts
    'max_logins_period': 60,    # in that many seconds
    'block_period': 60          # after that block for that many seconds
}

BANNED_EMAIL_PROVIDERS = [
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
COLLECTD_HOST = ""
COLLECTD_PORT = ""

GOOGLE_ANALYTICS_ID = ""

USE_EXTERNAL_AUTHENTICATION = False

# celery settings
CELERY_SETTINGS = {
    'BROKER_URL': BROKER_URL,
    'CELERY_TASK_SERIALIZER': 'json',
    'CELERYD_LOG_FORMAT': PY_LOG_FORMAT,
    'CELERYD_TASK_LOG_FORMAT': PY_LOG_FORMAT,
    'CELERYD_CONCURRENCY': 8,
    'CELERYD_MAX_TASKS_PER_CHILD': 32,
    'CELERYD_MAX_MEMORY_PER_CHILD': 204800,  # 20480 KiB - 200 MiB
    'CELERY_MONGODB_SCHEDULER_DB': 'mist2',
    'CELERY_MONGODB_SCHEDULER_COLLECTION': 'schedules',
    'CELERY_MONGODB_SCHEDULER_URL': MONGO_URI,
    'CELERY_ROUTES': {

        # Command queue
        'mist.api.tasks.ssh_command': {'queue': 'command'},

        # Machines queue
        'mist.api.tasks.list_machines': {'queue': 'machines'},
        'mist.api.poller.tasks.list_machines': {'queue': 'machines'},

        # Scripts queue (handled by gevent)
        'mist.api.tasks.group_run_script': {'queue': 'scripts'},
        'mist.api.tasks.run_script': {'queue': 'scripts'},
        'mist.api.tasks.group_machines_actions': {'queue': 'scripts'},
        'mist.api.tasks.machine_action': {'queue': 'scripts'},

        # SSH probe queue (handled by gevent)
        'mist.api.tasks.probe_ssh': {'queue': 'probe'},
        'mist.api.poller.tasks.ssh_probe': {'queue': 'probe'},

        # Ping probe queue (handled by gevent)
        'mist.api.tasks.ping': {'queue': 'ping'},
        'mist.api.poller.tasks.ping_probe': {'queue': 'ping'},

        # Rule evaluation queue (handled by gevent)
        'mist.api.rules.tasks.evaluate': {'queue': 'rules'},

        # Core tasks
        'mist.core.insights.tasks.list_deployments': {'queue': 'deployments'},
        'mist.rbac.tasks.update_mappings': {'queue': 'mappings'},
        'mist.rbac.tasks.remove_mappings': {'queue': 'mappings'},
    },
}

LANDING_CATEGORIES = [{
    'href': '/',
    'name': 'home',
    'template': 'home',
    'title': 'Home',
    'items': {
        "fold": {
            "copy": "",
            "subcopy":
                "Mist.io is a single dashboard to manage multi-cloud infrastructure",  # noqa
            "image": "images/mockup-imac-n4.png",
            "alt": "Mist.io cloud management dashboard",
            "cta": "Get Started"
        }
    }
}]

###############################################################################
# App constants
###############################################################################

STATES = {
    NodeState.RUNNING: 'running',
    NodeState.REBOOTING: 'rebooting',
    NodeState.TERMINATED: 'terminated',
    NodeState.PENDING: 'pending',
    # we assume unknown means stopped, especially for the EC2 case
    NodeState.UNKNOWN: 'unknown',
    NodeState.STOPPED: 'stopped',
    NodeState.ERROR: 'error',
    NodeState.PAUSED: 'paused',
    NodeState.SUSPENDED: 'suspended',
    NodeState.STARTING: 'starting',
    NodeState.STOPPING: 'stopping',
    NodeState.RECONFIGURING: 'reconfiguring'
}

EC2_SECURITYGROUP = {
    'name': 'mistio',
    'description': 'Security group created by mist.io'
}

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

SUPPORTED_PROVIDERS_V_2 = [
    # BareMetal
    {
        'title': 'Other Server',
        'provider': 'bare_metal',
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
        ]
    },
    # GCE
    {
        'title': 'GCE',
        'provider': Provider.GCE,
        'regions': []
    },

    # NephoScale
    {
        'title': 'NephoScale',
        'provider': Provider.NEPHOSCALE,
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
    # Packet.net
    {
        'title': 'Packet.net',
        'provider': Provider.PACKET,
        'regions': []
    }
]

# Base AMIs
EC2_IMAGES = {
    'eu-central-1': {
        'ami-e4c63e8b': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-060cde69': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-2eaeb342': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-ba68bad5': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-b968bad6': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-c425e4ab': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-25a97a4a': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-e37b8e8c': 'CoreOS-stable-1068.8.0 (PV)',
        'ami-7b7a8f14': 'CoreOS-stable-1068.8.0 (HVM',
    },
    'eu-west-1': {
        'ami-02ace471': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-a8d2d7ce': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-fa7cdd89': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-d1c0c4b7': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-01ccc867': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-9186a1e2': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-09447c6f': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-cbb5d5b8': 'CoreOS stable 1068.8.0 (HVM)',
        'ami-b6b8d8c5': 'CoreOS stable 1068.8.0 (PV)',
    },
    'eu-west-2': {
        'ami-9c363cf8': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-f1d7c395': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-63342007': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-b6daced2': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-a9eae0cd': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-9fc7cdfb': 'SUSE Linux Enterprise Server 11 SP4 (HVM), SSD Volume Type',  # noqa
    },
    'ca-central-1': {
        'ami-9062d0f4': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-b3d965d7': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-beea56da': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-0bd66a6f': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-14368470': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-1562d071': 'SUSE Linux Enterprise Server 11 SP4 (HVM), SSD Volume Type',  # noqa
    },
    'us-east-1': {
        'ami-b63769a1': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-80861296': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-70065467': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-668f1e70': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-c58c1dd3': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-fde4ebea': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-772aa961': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-098e011e': 'CoreOS stable 1068.8.0 (PV)',
        'ami-368c0321': 'CoreOS stable 1068.8.0 (HVM)',
        'ami-8fb03898': 'ClearOS 7.2.0',
        'ami-0397f56a': 'ClearOS Community 6.4.0 ',
        'ami-ff9af896': 'ClearOS Professional 6.4.0'
    },
    'us-east-2': {
        'ami-0932686c': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-618fab04': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-8fab8fea': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-4191b524': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-61a7fd04': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-4af2a92f': 'SUSE Linux Enterprise Server 11 SP4 (HVM), SSD Volume Type',  # noqa
    },
    'us-west-1': {
        'ami-2cade64c': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-2afbde4a': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-e7a4cc87': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-0f85a06f': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-7a85a01a': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-e09acc80': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-1da8f27d': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-ae2564ce': 'CoreOS stable 1068.8.0 (PV)',
        'ami-bc2465dc': 'CoreOS stable 1068.8.0 (HVM)',
    },
    'us-west-2': {
        'ami-6f68cf0f': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-efd0428f': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-baab0fda': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-c737a5a7': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-4836a428': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-e4a30084': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-7c22b41c': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-cfef22af': 'CoreOS stable 1068.8.0 (HVM)',
        'ami-ecec218c': 'CoreOS stable 1068.8.0 (PV)',
    },
    'ap-northeast-1': {
        'ami-5de0433c': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-afb09dc8': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-27fed749': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-30391657': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-923d12f5': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-e21c7285': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-d85e7fbf': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-d0e21bb1': 'CoreOS stable 1068.8.0 (PV)',
        'ami-fcd9209d': 'CoreOS stable 1068.8.0 (HVM)',
    },
    'ap-northeast-2': {
        'ami-44db152a': 'Red Hat Enterprise Linux 7.2 (HVM), SSD Volume Type',
        'ami-66e33108': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-9d15c7f3': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-5060b73e': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-15d5077b': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-91de14ff': 'CoreOS stable 1068.8.0 (HVM)',
        'ami-9edf15f0': 'CoreOS stable 1068.8.0 (PV)'
    },
    'sa-east-1': {
        'ami-7de77b11': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-4090f22c': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-029a1e6e': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-36cfad5a': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-37cfad5b': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-e1cd558d': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-8df695e1': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-0317836f': 'CoreOS stable 1068.8.0 (PV)',
        'ami-ef43d783': 'CoreOS stable 1068.8.0 (HVM)',
    },
    'ap-southeast-1': {
        'ami-2c95344f': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-8fcc75ec': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-1a5f9f79': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-ab5ce5c8': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-fc5ae39f': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-67b21d04': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-0a19a669': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-3203df51': 'CoreOS stable 1068.8.0 (PV)',
        'ami-9b00dcf8': 'CoreOS stable 1068.8.0 (HVM)',
    },
    'ap-southeast-2': {
        'ami-39ac915a': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-96666ff5': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-8ea3fbed': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',  # noqa
        'ami-af2128cc': 'Amazon Linux AMI 2017.03.0 (PV)',
        'ami-162c2575': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-527b4031': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-807876e3': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-e8e4ce8b': 'CoreOS stable 1068.8.0 (HVM)',
        'ami-ede4ce8e': 'CoreOS stable 1068.8.0 (PV)',
    },
    'ap-south-1': {
        'ami-cdbdd7a2': 'Red Hat Enterprise Linux 7.2 (HVM), SSD Volume Type',
        'ami-c2ee9dad': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-52c7b43d': 'Amazon Linux AMI 2017.03.0 (HVM), SSD Volume Type',
        'ami-8f8afde0': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',  # noqa
        'ami-83a8dbec': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
    }
}

DOCKER_IMAGES = {
    'mist/ubuntu-14.04': 'Ubuntu 14.04 - mist.io image',
    'mist/debian-wheezy': 'Debian Wheezy - mist.io image',
    'mist/opensuse-13.1': 'OpenSUSE 13.1 - mist.io image',
    'mist/fedora-20': 'Fedora 20 - mist.io image',
}

AZURE_ARM_IMAGES = {
    'MicrosoftWindowsServer:WindowsServer:2008-R2-SP1:2.127.20170918': 'MicrosoftWindowsServer WindowsServer 2008-R2-SP1 2.127.20170918',  # noqa
    'MicrosoftWindowsServer:WindowsServer:2012-R2-Datacenter:4.127.20170822': 'MicrosoftWindowsServer WindowsServer 2012-R2-Datacenter 4.127.20170822',  # noqa
    'MicrosoftWindowsServer:WindowsServer:2016-Datacenter:2016.127.20170918': 'MicrosoftWindowsServer WindowsServer 2016-Datacenter 2016.127.20170918',  # noqa
    'SUSE:openSUSE-Leap:42.3:2017.07.26': 'SUSE openSUSE-Leap 42.3 2017.07.26',
    'Canonical:UbuntuServer:16.04-LTS:16.04.201709190': 'Canonical UbuntuServer 16.04-LTS 16.04.201709190',  # noqa
    'Canonical:UbuntuServer:14.04.5-LTS:14.04.201708310': 'Canonical UbuntuServer 14.04.5-LTS 14.04.201708310',  # noqa
    'Canonical:UbuntuServer:17.04:17.04.201709220': 'Canonical UbuntuServer 17.04 17.04.201709220',  # noqa
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

RESET_PASSWORD_EXPIRATION_TIME = 60 * 60 * 24

WHITELIST_IP_EXPIRATION_TIME = 60 * 60 * 24

# Email templates

CONFIRMATION_EMAIL_SUBJECT = "[mist.io] Confirm your registration"

CONFIRMATION_EMAIL_BODY = """Hi %s,

we received a registration request to mist.io from this email address.

To activate your account, please click on the following link:

%s/confirm?key=%s

In the meantime, stay up-to-date by following us on https://twitter.com/mist_io

This request originated from the IP address %s. If it wasn't you, simply ignore
this message.

Best regards,
The mist.io team

--
%s
Govern the clouds
"""

RESET_PASSWORD_EMAIL_SUBJECT = "[mist.io] Password reset request"

RESET_PASSWORD_EMAIL_BODY = """Hi %s,

We have received a request to change your password.
Please click on the following link:

%s/reset-password?key=%s

This request originated from the IP address %s. If it wasn't you, simply ignore
this message. Your password has not been changed.


Best regards,
The mist.io team

--
%s
Govern the clouds
"""


WHITELIST_IP_EMAIL_SUBJECT = "[mist.io] Account IP whitelist request"

WHITELIST_IP_EMAIL_BODY = """Hi %s,

We have received a request to whitelist the IP you just tried to login with.
Please click on the following link to finish this action:

%s/confirm-whitelist?key=%s

This request originated from the IP address %s. If it wasn't you, simply ignore
this message. The above IP will not be whitelisted.


Best regards,
The mist.io team

--
%s
Govern the clouds
"""


FAILED_LOGIN_ATTEMPTS_EMAIL_SUBJECT = "[mist.io] Failed login attempts warning"

FAILED_LOGIN_ATTEMPTS_EMAIL_BODY = """
================= Failed login attempts warning =================

Too many failed login attempts for the same account and from the same IP
address occurred. Future login attempts for this user/ip will be
temporarily blocked to thwart a brute-force attack.

User: %s
IP address: %s
Number of failed attempts: %s
Time period of failed login attempts: %s
Blocking period: %s
"""

ORG_TEAM_STATUS_CHANGE_EMAIL_SUBJECT = ("Your status in an organization has"
                                        " changed")

ORG_NOTIFICATION_EMAIL_SUBJECT = "[mist.io] Subscribed to team"

USER_NOTIFY_ORG_TEAM_ADDITION = """Hi

You have been added to the team "%s" of organization %s.

Best regards,
The mist.io team

--
%s
"""

USER_CONFIRM_ORG_INVITATION_EMAIL_BODY = """Hi

You have been invited by %s to join the %s organization
as a member of the %s.

To confirm your invitation, please click on the following link:

%s/confirm-invitation?invitoken=%s

Once you are done with the confirmation process,
you will be able to login to your Mist.io user account
as a member of the team%s.

Best regards,
The mist.io team

--
%s
"""

ORG_INVITATION_EMAIL_SUBJECT = "[mist.io] Confirm your invitation"

REGISTRATION_AND_ORG_INVITATION_EMAIL_BODY = """Hi

You have been invited by %s to join the %s organization
as a member of the %s.

Before joining the team you must also activate your account in  mist.io and set
a password. To activate your account and join the team, please click on the
following link:

%s/confirm?key=%s&invitoken=%s

Once you are done with the registration process,
you will be able to login to your Mist.io user account
as a member of the team%s.

Best regards,
The mist.io team

--
%s
"""

NOTIFY_REMOVED_FROM_TEAM = """Hi

You have been removed from team %s of organization %s by the
administrator %s.

Best regards,
The mist.io team

--
%s
"""

NOTIFY_REMOVED_FROM_ORG = """Hi

You are no longer a member of the organization %s.

Best regards,
The mist.io team

--
%s
"""

NOTIFY_INVITATION_REVOKED_SUBJECT = "Invitation for organization revoked"

NOTIFY_INVITATION_REVOKED = """Hi

Your invitation to the organization %s has been revoked.

Best regards,
The mist.io team

--
%s
"""

SHOW_FOOTER = False
ALLOW_SIGNUP_EMAIL = True
ALLOW_SIGNUP_GOOGLE = False
ALLOW_SIGNUP_GITHUB = False
ALLOW_SIGNIN_EMAIL = True
ALLOW_SIGNIN_GOOGLE = False
ALLOW_SIGNIN_GITHUB = False
ENABLE_TUNNELS = False
ENABLE_ORCHESTRATION = False
ENABLE_INSIGHTS = False
STRIPE_PUBLIC_APIKEY = False
ENABLE_AB = False
ENABLE_MONITORING = True
MACHINE_PATCHES = True

PLUGINS = []

# DO NOT PUT ANYTHING BELOW HERE UNLESS YOU KNOW WHAT YOU ARE DOING

# Get settings from mist.core.
CORE_CONFIG_PATH = os.path.join(dirname(MIST_API_DIR, 2),
                                'src', 'mist', 'core', 'config.py')
if os.path.exists(CORE_CONFIG_PATH):
    print >> sys.stderr, "Will load core config from %s" % CORE_CONFIG_PATH
    execfile(CORE_CONFIG_PATH)
    HAS_CORE = True
else:
    print >> sys.stderr, "Couldn't find core config in %s" % CORE_CONFIG_PATH
    HAS_CORE = False


# Get settings from environmental variables.
FROM_ENV_STRINGS = [
    'AMQP_URI', 'BROKER_URL', 'CORE_URI', 'MONGO_URI', 'MONGO_DB', 'DOCKER_IP',
    'DOCKER_PORT', 'DOCKER_TLS_KEY', 'DOCKER_TLS_CERT', 'DOCKER_TLS_CA',
    'UI_TEMPLATE_URL', 'LANDING_TEMPLATE_URL', 'THEME'
]
FROM_ENV_INTS = [
]
FROM_ENV_BOOLS = [
    'SSL_VERIFY', 'ALLOW_CONNECT_LOCALHOST', 'ALLOW_CONNECT_PRIVATE',
    'ALLOW_LIBVIRT_LOCALHOST', 'JS_BUILD', 'VERSION_CHECK', 'USAGE_SURVEY',
]
FROM_ENV_ARRAYS = [
    'MEMCACHED_HOST',
]
print >> sys.stderr, "Reading settings from environmental variables."
for key in FROM_ENV_STRINGS:
    if os.getenv(key):
        locals()[key] = os.getenv(key)
for key in FROM_ENV_INTS:
    if os.getenv(key):
        try:
            locals()[key] = int(os.getenv(key))
        except (KeyError, ValueError):
            print >> sys.stderr, "Invalid value for %s: %s" % (key,
                                                               os.getenv(key))
for key in FROM_ENV_BOOLS:
    if os.getenv(key) is not None:
        locals()[key] = os.getenv(key) in ('1', 'true', 'True')
for key in FROM_ENV_ARRAYS:
    if os.getenv(key):
        locals()[key] = os.getenv(key).split(',')


CONFIG_OVERRIDE_FILES = []

# Load defaults file if defined
DEFAULTS_FILE = os.getenv('DEFAULTS_FILE')
if DEFAULTS_FILE:
    CONFIG_OVERRIDE_FILES.append(os.path.abspath(DEFAULTS_FILE))

# Get settings from settings file.
SETTINGS_FILE = os.path.abspath(os.getenv('SETTINGS_FILE') or 'settings.py')
CONFIG_OVERRIDE_FILES.append(SETTINGS_FILE)

# Load all config override files. SETTINGS_FILE should be the last one to load
for override_file in CONFIG_OVERRIDE_FILES:
    if os.path.exists(override_file):
        print >> sys.stderr, "Reading settings from %s" % override_file
        CONF = {}
        execfile(override_file, CONF)
        for key in CONF:
            if isinstance(locals().get(key), dict) and isinstance(CONF[key],
                                                                  dict):
                locals()[key].update(CONF[key])
            else:
                locals()[key] = CONF[key]
    else:
        print >> sys.stderr, ("Couldn't find settings file in %s" %
                              override_file)

HAS_BILLING = 'billing' in PLUGINS
HAS_RBAC = 'rbac' in PLUGINS


# Update TELEGRAF_TARGET.

if not TELEGRAF_TARGET:
    if urlparse.urlparse(CORE_URI).hostname in ('localhost', '127.0.0.1'):
        TELEGRAF_TARGET = "http://traefik"
    else:
        TELEGRAF_TARGET = CORE_URI + '/ingress'


# Update celery settings.
CELERY_SETTINGS.update({
    'BROKER_URL': BROKER_URL,
    'CELERY_MONGODB_SCHEDULER_URL': MONGO_URI,
    'CELERYD_LOG_FORMAT': PY_LOG_FORMAT,
    'CELERYD_TASK_LOG_FORMAT': PY_LOG_FORMAT,
})
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
        'task': 'mist.api.tasks.gc_schedulers',
        'schedule': datetime.timedelta(hours=24),
    }
if _schedule:
    CELERY_SETTINGS.update({'CELERYBEAT_SCHEDULE': _schedule})


# Configure libcloud to not verify certain hosts.
if NO_VERIFY_HOSTS:
    if DOCKER_IP:
        NO_VERIFY_HOSTS.append(DOCKER_IP)
    libcloud.security.NO_VERIFY_MATCH_HOSTNAMES = NO_VERIFY_HOSTS

WHITELIST_CIDR = [
]

HOMEPAGE_INPUTS = {
    'portal_name': PORTAL_NAME,
    'theme': THEME,
    'google_analytics_id': GOOGLE_ANALYTICS_ID,
    'mixpanel_id': MIXPANEL_ID,
    'fb_id': FB_ID,
    'olark_id': OLARK_ID,
    'categories': LANDING_CATEGORIES,
    'footer': SHOW_FOOTER,
    'allow_signup_email': ALLOW_SIGNUP_EMAIL,
    'allow_signup_google': ALLOW_SIGNUP_GOOGLE,
    'allow_signup_github': ALLOW_SIGNUP_GITHUB,
    'allow_signin_email': ALLOW_SIGNIN_EMAIL,
    'allow_signin_google': ALLOW_SIGNIN_GOOGLE,
    'allow_signin_github': ALLOW_SIGNIN_GITHUB,
    'enable_rbac': HAS_RBAC,
    'enable_tunnels': ENABLE_TUNNELS,
    'enable_orchestration': ENABLE_ORCHESTRATION,
    'enable_insights': ENABLE_INSIGHTS,
    'enable_billing': HAS_BILLING,
    'enable_ab': ENABLE_AB,
    'enable_monitoring': ENABLE_MONITORING,
}

if HAS_BILLING and STRIPE_PUBLIC_APIKEY:
    HOMEPAGE_INPUTS['stripe_public_apikey'] = STRIPE_PUBLIC_APIKEY

# DO NOT PUT REGULAR SETTINGS BELOW, PUT THEM ABOVE THIS SECTION


# Read version info
VERSION = {}
try:
    with open('/mist-version.json', 'r') as fobj:
        VERSION = json.load(fobj)
except Exception as exc:
    print >> sys.stderr, "Couldn't load version info."
