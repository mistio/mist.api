"""Basic configuration and mappings

Here we define constants needed by mist.io

Also, the configuration from settings.py is exposed through this module.

"""

import os
import logging


from libcloud.compute.types import Provider
from libcloud.container.types import Provider as Container_Provider

from libcloud.compute.types import NodeState


# Parse user defined settings from settings.py in the top level project dir
log = logging.getLogger(__name__)

# If SETTINGS_FILE ebv variable exists, it will point to a mounted
# file that hosts the configuration option of our Kubernetes
# configMap.
settings_file = os.getenv('SETTINGS_FILE') or 'settings.py'

settings = {}
try:
    execfile(settings_file, settings)
except IOError:
    log.warning("No settings.py file found.")
except Exception as exc:
    log.error("Error parsing settings py: %r", exc)
CORE_URI = settings.get("CORE_URI", os.environ.get("CORE_URI", "https://mist.io"))
AMQP_URI = settings.get("AMQP_URI", "localhost:5672")
MEMCACHED_HOST = settings.get("MEMCACHED_HOST", ["127.0.0.1:11211"])
BROKER_URL = settings.get("BROKER_URL", "amqp://guest:guest@127.0.0.1/")
SSL_VERIFY = settings.get("SSL_VERIFY", True)
JS_BUILD = settings.get("JS_BUILD", False)
CSS_BUILD = settings.get("CSS_BUILD", False)
LAST_BUILD = settings.get("LAST_BUILD", '')
JS_LOG_LEVEL = settings.get("JS_LOG_LEVEL", 3)
PY_LOG_LEVEL = settings.get("PY_LOG_LEVEL", logging.INFO)
PY_LOG_FORMAT = settings.get("PY_LOG_FORMAT", '%(asctime)s %(levelname)s %(threadName)s %(module)s - %(funcName)s: %(message)s')
PY_LOG_FORMAT_DATE = settings.get("PY_LOG_FORMAT_DATE", "%Y-%m-%d %H:%M:%S")
GOOGLE_ANALYTICS_ID = settings.get("GOOGLE_ANALYTICS_ID", "")
COMMAND_TIMEOUT = settings.get("COMMAND_TIMEOUT", 20)
ALLOW_CONNECT_LOCALHOST = settings.get('ALLOW_CONNECT_LOCALHOST', True)
ALLOW_CONNECT_PRIVATE = settings.get('ALLOW_CONNECT_PRIVATE', True)
# allow mist.io to connect to KVM hypervisor running on the same server
ALLOW_LIBVIRT_LOCALHOST = settings.get('ALLOW_LIBVIRT_LOCALHOST', False)
# mist.io interface to the OpenVPN server
VPN_SERVER_API_ADDRESS = settings.get('VPN_SERVER_API_ADDRESS', '')
ALLOWED_PRIVATE_NETWORKS = settings.get('ALLOWED_PRIVATE_NETWORKS', ['192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8'])
ALLOW_PUBLIC_VPN = settings.get('ALLOW_PUBLIC_VPN', True)

# celery settings
CELERY_SETTINGS = {
    'BROKER_URL': BROKER_URL,
    'CELERY_TASK_SERIALIZER': 'json',
    'CELERYD_LOG_FORMAT': PY_LOG_FORMAT,
    'CELERYD_TASK_LOG_FORMAT': PY_LOG_FORMAT,
    'CELERYD_CONCURRENCY': 32,
    'CELERYD_MAX_TASKS_PER_CHILD': 32,
}
CELERY_SETTINGS.update(settings.get('CELERY_SETTINGS', {}))

# App constants

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
