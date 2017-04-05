"""Basic configuration and mappings
   Here we define constants needed by mist.api
   Also, the configuration from settings.py is exposed through this module.
"""
import os
import sys
import ssl
import logging

import libcloud.security
from libcloud.compute.types import Provider
from libcloud.container.types import Provider as Container_Provider

from libcloud.compute.types import NodeState


libcloud.security.SSL_VERSION = ssl.PROTOCOL_TLSv1_2


###############################################################################
# The following variables are common for both open.source and mist.core
###############################################################################

CORE_URI = "https://mist.io"
AMQP_URI = "rabbitmq:5672"
MEMCACHED_HOST = ["memcached:11211"]
BROKER_URL = "amqp://guest:guest@rabbitmq/"
SSL_VERIFY = True

PY_LOG_LEVEL = logging.INFO
PY_LOG_FORMAT = '%(asctime)s %(levelname)s %(threadName)s %(module)s - %(funcName)s: %(message)s'
PY_LOG_FORMAT_DATE = "%Y-%m-%d %H:%M:%S"
LOG_EXCEPTIONS = True

JS_BUILD = False
CSS_BUILD = False
JS_LOG_LEVEL = 3

MONGO_URI = "mongodb:27017"
MONGO_DB = "mist2"

ACTIVATE_POLLER = True

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

GITHUB_BOT_TOKEN = ""

NO_VERIFY_HOSTS = []

MIXPANEL_ID = ""
FB_ID = ""
OLARK_ID = ""

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

EMAIL_FROM = ""

# Monitoring Related
COLLECTD_HOST = ""
COLLECTD_PORT = ""

GOOGLE_ANALYTICS_ID = ""

# celery settings
CELERY_SETTINGS = {
    'BROKER_URL': BROKER_URL,
    'CELERY_TASK_SERIALIZER': 'json',
    'CELERYD_LOG_FORMAT': PY_LOG_FORMAT,
    'CELERYD_TASK_LOG_FORMAT': PY_LOG_FORMAT,
    'CELERYD_CONCURRENCY': 4,
    'CELERYD_MAX_TASKS_PER_CHILD': 32,
    'CELERYD_MAX_MEMORY_PER_CHILD': 204800,  # 20480 KiB - 200 MiB
    'CELERY_MONGODB_SCHEDULER_DB': 'mist2',
    'CELERY_MONGODB_SCHEDULER_COLLECTION': 'schedules',
    'CELERY_MONGODB_SCHEDULER_URL': MONGO_URI,
}

LANDING_CATEGORIES = [
    {'href': '/', 'name': 'home', 'template': 'home', 'title': 'Home'}
]

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
        'provider' : Provider.LIBVIRT,
        'regions': []
    },
    # HostVirtual
    {
        'title': 'HostVirtual',
        'provider' : Provider.HOSTVIRTUAL,
        'regions': []
    },
    # Vultr
    {
        'title': 'Vultr',
        'provider' : Provider.VULTR,
        'regions': []
    },
     # vSphere
    {
        'title': 'VMWare vSphere',
        'provider' : Provider.VSPHERE,
        'regions': []
    },
    # Packet.net
    {
        'title': 'Packet.net',
        'provider' : Provider.PACKET,
        'regions': []
    }
]

# Base AMIs
EC2_IMAGES = {
    'eu-central-1': {
        'ami-af0fc0c0': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-3b0fc054': 'Amazon Linux AMI 2016.09.1 (PV)',
        'ami-5aee2235': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-78559817': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-e4c63e8b': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-c425e4ab': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',
        'ami-2eaeb342': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',
        'ami-e37b8e8c': 'CoreOS-stable-1068.8.0 (PV)',
        'ami-7b7a8f14': 'CoreOS-stable-1068.8.0 (HVM',
    },
    'eu-west-1': {
        'ami-70edb016': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-e0f2af86': 'Amazon Linux AMI 2016.09.1 (PV)',
        'ami-02ace471': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-d8f4deab': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-a192bad2': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-fa7cdd89': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',
        'ami-9186a1e2': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',
        'ami-cbb5d5b8': 'CoreOS stable 1068.8.0 (HVM)',
        'ami-b6b8d8c5': 'CoreOS stable 1068.8.0 (PV)',
    },
    'us-east-1': {
        'ami-0b33d91d': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-7a3dd76c': 'Amazon Linux AMI 2016.09.1 (PV)',
        'ami-b63769a1': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-fde4ebea': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',
        'ami-49c9295f': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-6edd3078': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-70065467': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',
        'ami-098e011e': 'CoreOS stable 1068.8.0 (PV)',
        'ami-368c0321': 'CoreOS stable 1068.8.0 (HVM)',
    },
    'us-east-2': {
        'ami-c55673a0': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-7a3dd76c': 'Amazon Linux AMI 2016.09.1 (PV)',
        'ami-0932686c': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-4af2a92f': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',
        'ami-41d48e24': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-fcc19b99': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-70065467': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',
    },
    'us-west-1': {
        'ami-165a0876': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-f25a0892': 'Amazon Linux AMI 2016.09.1 (PV)',
        'ami-3e21725e': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-539ac933': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-2cade64c': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-e09acc80': 'SUSE Linux Enterprise Server 12 SP 2 (HVM), SSD Volume Type',
        'ami-e7a4cc87': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',
        'ami-ae2564ce': 'CoreOS stable 1068.8.0 (PV)',
        'ami-bc2465dc': 'CoreOS stable 1068.8.0 (HVM)',
    },
    'us-west-2': {
        'ami-f173cc91': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-8a72cdea': 'Amazon Linux AMI 2016.09.1 (PV)',
        'ami-6f68cf0f': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-e4a30084': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',
        'ami-5e63d13e': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-7c803d1c': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-baab0fda': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',
        'ami-cfef22af': 'CoreOS stable 1068.8.0 (HVM)',
        'ami-ecec218c': 'CoreOS stable 1068.8.0 (PV)',
    },
    'ap-southeast-1': {
        'ami-dc9339bf': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-2c95344f': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-67b21d04': 'SUSE Linux Enterprise Server 12 SP 2 (HVM), SSD Volume Type',
        'ami-50e64d33': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-1a5f9f79': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',
        'ami-b1943fd2': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-2c963c4f': 'Amazon Linux AMI 2016.09.1 (PV)',
        'ami-3203df51': 'CoreOS stable 1068.8.0 (PV)',
        'ami-9b00dcf8': 'CoreOS stable 1068.8.0 (HVM)',
    },
    'ap-southeast-2': {
        'ami-6f47400c': 'Amazon Linux AMI 2016.09.1 (PV)',
        'ami-1c47407f': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-39ac915a': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-527b4031': 'SUSE Linux Enterprise Server 12 SP 2 (HVM), SSD Volume Type',
        'ami-8ea3fbed': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',
        'ami-799d981a': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-fe71759d': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-e8e4ce8b': 'CoreOS stable 1068.8.0 (HVM)',
        'ami-ede4ce8e': 'CoreOS stable 1068.8.0 (PV)',
    },
    'sa-east-1': {
        'ami-80086dec': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-7de77b11': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-e1cd558d': 'SUSE Linux Enterprise Server 12 SP 2 (HVM), SSD Volume Type',
        'ami-ff861c93': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-029a1e6e': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',
        'ami-7379e31f': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-2a096c46': 'Amazon Linux AMI 2016.09.1 (PV)',
        'ami-0317836f': 'CoreOS stable 1068.8.0 (PV)',
        'ami-ef43d783': 'CoreOS stable 1068.8.0 (HVM)',
    },
    'ap-northeast-1': {
        'ami-56d4ad31': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-bdd2abda': 'Amazon Linux AMI 2016.09.1 (PV)',
        'ami-5de0433c': 'Red Hat Enterprise Linux 7.3 (HVM), SSD Volume Type',
        'ami-eb49358c': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-6fccbe08': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-27fed749': 'SUSE Linux Enterprise Server 11 SP4 (PV), SSD Volume Type',
        'ami-e21c7285': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',
        'ami-d0e21bb1': 'CoreOS stable 1068.8.0 (PV)',
        'ami-fcd9209d': 'CoreOS stable 1068.8.0 (HVM)',
    },
    'ap-northeast-2': {
        'ami-dac312b4': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-44db152a': 'Red Hat Enterprise Linux 7.2 (HVM), SSD Volume Type',
        'ami-5060b73e': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',
        'ami-93d600fd': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
        'ami-7669be18': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-91de14ff': 'CoreOS stable 1068.8.0 (HVM)',
        'ami-9edf15f0': 'CoreOS stable 1068.8.0 (PV)'
    },
    'ap-south-1': {
        'ami-f9daac96': 'Amazon Linux AMI 2016.09.1 (HVM), SSD Volume Type',
        'ami-cdbdd7a2': 'Red Hat Enterprise Linux 7.2 (HVM), SSD Volume Type',
        'ami-8f8afde0': 'SUSE Linux Enterprise Server 12 SP2 (HVM), SSD Volume Type',
        'ami-19f78076': 'Ubuntu Server 14.04 LTS (HVM), SSD Volume Type',
        'ami-dd3442b2': 'Ubuntu Server 16.04 LTS (HVM), SSD Volume Type',
    },
}

DOCKER_IMAGES = {
    'mist/ubuntu-14.04': 'Ubuntu 14.04',
    'mist/debian-wheezy': 'Debian Wheezy',
    'mist/opensuse-13.1': 'OpenSUSE 13.1',
    'mist/fedora-20': 'Fedora 20',
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


# Get settings from mist.core.
def dirname(path, num=1):
    for i in xrange(num):
        path = os.path.dirname(path)
    return path


CORE_CONFIG_PATH = os.path.join(dirname(__file__, 6),
                                'mist', 'core', 'config.py')
if os.path.exists(CORE_CONFIG_PATH):
    print >> sys.stderr, "Will load core config from %s" % CORE_CONFIG_PATH
    execfile(CORE_CONFIG_PATH)
else:
    print >> sys.stderr, "Couldn't find core config in %S" % CORE_CONFIG_PATH


# Get settings from environmental variables.
FROM_ENV_STRINGS = [
    'AMQP_URI', 'BROKER_URL', 'CORE_URI', 'MONGO_URI', 'MONGO_DB', 'DOCKER_IP',
    'DOCKER_PORT', 'DOCKER_TLS_KEY', 'DOCKER_TLS_CERT', 'DOCKER_TLS_CA',
]
FROM_ENV_INTS = [
]
FROM_ENV_BOOLS = [
    'SSL_VERIFY', 'ALLOW_CONNECT_LOCALHOST', 'ALLOW_CONNECT_PRIVATE',
    'ALLOW_LIBVIRT_LOCALHOST',
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


# Get settings from settings file.
settings_file = os.path.abspath(os.getenv('SETTINGS_FILE') or 'settings.py')
if os.path.exists(settings_file):
    print >> sys.stderr, "Reading local settings from %s" % settings_file
    conf = {}
    execfile(settings_file, conf)
    for key in conf:
        if isinstance(locals().get(key), dict) and isinstance(conf[key], dict):
            locals()[key].update(conf[key])
        else:
            locals()[key] = conf[key]
else:
    print >> sys.stderr, "Couldn't find settings file in %s" % settings_file


# Update celery settings.
CELERY_SETTINGS.update({
    'BROKER_URL': BROKER_URL,
    'CELERY_MONGODB_SCHEDULER_URL': MONGO_URI,
    'CELERYD_LOG_FORMAT': PY_LOG_FORMAT,
    'CELERYD_TASK_LOG_FORMAT': PY_LOG_FORMAT,
})


# Configure libcloud to not verify certain hosts.
if NO_VERIFY_HOSTS:
    if DOCKER_IP:
        NO_VERIFY_HOSTS.append(DOCKER_IP)
    libcloud.security.NO_VERIFY_MATCH_HOSTNAMES = NO_VERIFY_HOSTS


HOMEPAGE_INPUTS = {
    'google_analytics_id': GOOGLE_ANALYTICS_ID,
    'mixpanel_id': MIXPANEL_ID,
    'fb_id': FB_ID,
    'olark_id': OLARK_ID,
    'categories': LANDING_CATEGORIES
}
