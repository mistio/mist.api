import re
import subprocess

import pingparsing


from mongoengine import DoesNotExist

from time import time

from libcloud.common.types import InvalidCredsError
from libcloud.utils.networking import is_private_subnet
from libcloud.dns.types import Provider as DnsProvider
from libcloud.dns.types import RecordType
from libcloud.dns.providers import get_driver as get_dns_driver

from mist.api.shell import Shell

from mist.api.exceptions import MistError
from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import CloudNotFoundError

from mist.api.helpers import amqp_publish_user

from mist.api.helpers import dirty_cow, parse_os_release

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine

from mist.api import config

import mist.api.clouds.models as cloud_models

import logging

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)


def connect_provider(cloud):
    """Establishes cloud connection using the credentials specified.

    Cloud is expected to be a cloud mongoengine model instance.

    """
    return cloud.ctl.compute.connect()


def ssh_command(owner, cloud_id, machine_id, host, command,
                key_id=None, username=None, password=None, port=22):
    """
    We initialize a Shell instant (for mist.api.shell).

    Autoconfigures shell and returns command's output as string.
    Raises MachineUnauthorizedError if it doesn't manage to connect.

    """
    # check if cloud exists
    Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)

    shell = Shell(host)
    key_id, ssh_user = shell.autoconfigure(owner, cloud_id, machine_id,
                                           key_id, username, password, port)
    retval, output = shell.command(command)
    shell.disconnect()
    return output


def list_locations(owner, cloud_id, cached=False):
    """List the locations of the specified cloud"""
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id)
    except Cloud.DoesNotExist:
        raise CloudNotFoundError()
    if cached:
        locations = cloud.ctl.compute.list_cached_locations()
    else:
        locations = cloud.ctl.compute.list_locations()
    return [location.as_dict() for location in locations]


def filter_list_locations(auth_context, cloud_id, locations=None, perm='read',
                          cached=False):
    """Filter the locations of the specific cloud based on RBAC policy"""
    if locations is None:
        locations = list_locations(auth_context.owner, cloud_id, cached)
    if not auth_context.is_owner():
        allowed_resources = auth_context.get_allowed_resources(perm)
        if cloud_id not in allowed_resources['clouds']:
            return {'cloud_id': cloud_id, 'locations': []}
        for i in range(len(locations) - 1, -1, -1):
            if locations[i]['id'] not in allowed_resources['locations']:
                locations.pop(i)
    return locations


def list_projects(owner, cloud_id):
    """List projects for each account.
    Currently supported for Packet.net. For other providers
    this returns an empty list
    """
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)

    if cloud.ctl.provider in ['packet']:
        conn = connect_provider(cloud)
        projects = conn.ex_list_projects()
        ret = [{'id': project.id,
                'name': project.name,
                'extra': project.extra
                }
               for project in projects]
    else:
        ret = []

    return ret


def list_resource_groups(owner, cloud_id):
    """List resource groups for each account.
    Currently supported for Azure Arm. For other providers
    this returns an empty list
    """
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)

    if cloud.ctl.provider in ['azure_arm']:
        conn = connect_provider(cloud)
        groups = conn.ex_list_resource_groups()
    else:
        groups = []

    ret = [{'id': group.id,
            'name': group.name,
            'extra': group.extra
            }
           for group in groups]
    return ret


def list_storage_pools(owner, cloud_id):
    """
    List storage pools for LXD containers.
    """

    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)

    if cloud.ctl.provider in ['lxd']:
        conn = connect_provider(cloud)
        storage_pools = conn.ex_list_storage_pools(detailed=False)
    else:
        storage_pools = []

    ret = [{'title': pool.name,
            'val': pool.name}
           for pool in storage_pools]
    return ret


def list_storage_accounts(owner, cloud_id):
    """List storage accounts for each account.
    Currently supported for Azure Arm. For other providers
    this returns an empty list
    """
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    if cloud.ctl.provider in ['azure_arm']:
        conn = connect_provider(cloud)
        accounts = conn.ex_list_storage_accounts()
    else:
        accounts = []

    storage_accounts = []
    resource_groups = conn.ex_list_resource_groups()
    for account in accounts:
        location_id = account.location

        # FIXME: circular import
        from mist.api.clouds.models import CloudLocation
        try:
            location = CloudLocation.objects.get(external_id=location_id,
                                                 cloud=cloud)
        except CloudLocation.DoesNotExist:
            pass
        r_group_name = account.id.split('resourceGroups/')[1].split('/')[0]
        r_group_id = ''
        for resource_group in resource_groups:
            if resource_group.name == r_group_name:
                r_group_id = resource_group.id
                break
        storage_account = {'id': account.id,
                           'name': account.name,
                           'location': location.id if location else None,
                           'extra': account.extra,
                           'resource_group': r_group_id}
        storage_accounts.append(storage_account)

    return storage_accounts


# TODO deprecate this!
# We should decouple probe_ssh_only from ping.
# Use them as two separate functions instead & through celery
def probe(owner, cloud_id, machine_id, host, key_id='', ssh_user=''):
    """Ping and SSH to machine and collect various metrics."""

    if not host:
        raise RequiredParameterMissingError('host')

    ping_res = ping(owner=owner, host=host)
    try:
        ret = probe_ssh_only(owner, cloud_id, machine_id, host,
                             key_id=key_id, ssh_user=ssh_user)
    except Exception as exc:
        log.error(exc)
        log.warning("SSH failed when probing, let's see what ping has to say.")
        ret = {}

    ret.update(ping_res)
    return ret


def probe_ssh_only(owner, cloud_id, machine_id, host, key_id='', ssh_user='',
                   shell=None):
    """Ping and SSH to machine and collect various metrics."""

    # run SSH commands
    command = (
        "echo \""
        "LC_NUMERIC=en_US.UTF-8 sudo -n uptime 2>&1|"
        "grep load|"
        "wc -l && "
        "echo -------- && "
        "LC_NUMERIC=en_US.UTF-8 uptime && "
        "echo -------- && "
        "if [ -f /proc/uptime ]; then cat /proc/uptime | cut -d' ' -f1; "
        "else expr `date '+%s'` - `sysctl kern.boottime | sed -En 's/[^0-9]*([0-9]+).*/\\1/p'`;"  # noqa
        "fi; "
        "echo -------- && "
        "if [ -f /proc/cpuinfo ]; then grep -c processor /proc/cpuinfo;"
        "else sysctl hw.ncpu | awk '{print $2}';"
        "fi;"
        "echo -------- && "
        "/sbin/ifconfig;"
        "echo -------- &&"
        "/bin/df -Pah;"
        "echo -------- &&"
        "uname -r ;"
        "echo -------- &&"
        "cat /etc/*release;"
        "echo --------"
        "\"|sh"  # In case there is a default shell other than bash/sh (ex csh)
    )

    if key_id:
        log.warn('probing with key %s' % key_id)

    if not shell:
        cmd_output = ssh_command(owner, cloud_id, machine_id,
                                 host, command, key_id=key_id)
    else:
        _, cmd_output = shell.command(command)
    cmd_output = [str(part).strip()
                  for part in cmd_output.replace('\r', '').split('--------')]
    log.warn(cmd_output)
    uptime_output = cmd_output[1]
    loadavg = re.split('load averages?: ', uptime_output)[1].split(', ')
    users = re.split(' users?', uptime_output)[0].split(', ')[-1].strip()
    uptime = cmd_output[2]
    cores = cmd_output[3]
    ips = re.findall(r'inet addr:(\S+)', cmd_output[4]) or \
        re.findall(r'inet (\S+)', cmd_output[4])
    m = re.findall(r'((?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})',
                   cmd_output[4])
    if '127.0.0.1' in ips:
        ips.remove('127.0.0.1')
    macs = {}
    for i in range(0, len(ips)):
        try:
            macs[ips[i]] = m[i]
        except IndexError:
            # in case of interfaces, such as VPN tunnels, with a dummy MAC addr
            continue
    pub_ips = find_public_ips(ips)
    priv_ips = [ip for ip in ips if ip not in pub_ips]

    kernel_version = cmd_output[6].replace("\n", "")
    os_release = cmd_output[7]
    os, os_version, distro = parse_os_release(os_release)

    return {
        'uptime': uptime,
        'loadavg': loadavg,
        'cores': cores,
        'users': users,
        'pub_ips': pub_ips,
        'priv_ips': priv_ips,
        'macs': macs,
        'df': cmd_output[5],
        'timestamp': time(),
        'kernel': kernel_version,
        'os': os,
        'os_version': os_version,
        'distro': distro,
        'dirty_cow': dirty_cow(os, os_version, kernel_version)
    }


def _ping_host(host, pkts=10):
    ping = subprocess.Popen(['ping', '-c', str(pkts), '-i', '0.4', '-W',
                             '1', '-q', host], stdout=subprocess.PIPE)
    ping_parser = pingparsing.PingParsing()
    output = ping.stdout.read()
    ping_parser.parse(output.decode().replace('pipe 8\n', ''))
    return ping_parser.as_dict()


def ping(owner, host, pkts=10):
    if config.HAS_VPN:
        from mist.vpn.methods import super_ping
        result = super_ping(owner=owner, host=host, pkts=pkts)
    else:
        result = _ping_host(host, pkts=pkts)

    # In both cases, the returned dict is formatted by pingparsing.

    # Rename keys.
    final = {}
    for key, newkey in (('packet_transmit', 'packets_tx'),
                        ('packet_receive', 'packets_rx'),
                        ('packet_duplicate_rate', 'packets_duplicate'),
                        ('packet_loss_rate', 'packets_loss'),
                        ('rtt_min', 'rtt_min'),
                        ('rtt_max', 'rtt_max'),
                        ('rtt_avg', 'rtt_avg'),
                        ('rtt_mdev', 'rtt_std')):
        if key in result:
            final[newkey] = result[key]
    return final


def find_public_ips(ips):
    public_ips = []
    for ip in ips:
        # is_private_subnet does not check for ipv6
        try:
            if not is_private_subnet(ip):
                public_ips.append(ip)
        except:
            pass
    return public_ips


def notify_admin(title, message="", team="all"):
    """ This will only work on a multi-user setup configured to send emails """
    from mist.api.helpers import send_email
    send_email(title, message,
               config.NOTIFICATION_EMAIL.get(team, config.NOTIFICATION_EMAIL))


def notify_user(owner, title, message="", email_notify=True, **kwargs):
    # Notify connected owner via amqp
    payload = {'title': title, 'message': message}
    payload.update(kwargs)
    if 'command' in kwargs:
        output = '%s\n' % kwargs['command']
        if 'output' in kwargs:
            output += '%s\n' % kwargs['output'].decode('utf-8', 'ignore')
        if 'retval' in kwargs:
            output += 'returned with exit code %s.\n' % kwargs['retval']
        payload['output'] = output
    amqp_publish_user(owner, routing_key='notify', data=payload)

    body = message + '\n' if message else ''
    if 'cloud_id' in kwargs:
        cloud_id = kwargs['cloud_id']
        body += "Cloud:\n"
        try:
            cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
            cloud_title = cloud.title
        except DoesNotExist:
            cloud_title = ''
            cloud = ''
        if cloud_title:
            body += "  Name: %s\n" % cloud_title
        body += "  Id: %s\n" % cloud_id
        if 'machine_id' in kwargs:
            machine_id = kwargs['machine_id']
            body += "Machine:\n"
            if kwargs.get('machine_name'):
                name = kwargs['machine_name']
            else:
                try:
                    name = Machine.objects.get(cloud=cloud,
                                               machine_id=machine_id).name
                except DoesNotExist:
                    name = ''
            if name:
                body += "  Name: %s\n" % name
            title += " for machine %s" % (name or machine_id)
            body += "  Id: %s\n" % machine_id
    if 'error' in kwargs:
        error = kwargs['error']
        body += "Result: %s\n" % ('Success' if not error else 'Error')
        if error and error is not True:
            body += "Error: %s" % error
    if 'command' in kwargs:
        body += "Command: %s\n" % kwargs['command']
    if 'retval' in kwargs:
        body += "Return value: %s\n" % kwargs['retval']
    if 'duration' in kwargs:
        body += "Duration: %.2f secs\n" % kwargs['duration']
    if 'output' in kwargs:
        body += "Output: %s\n" % kwargs['output']

    if email_notify:
        from mist.api.helpers import send_email
        email = owner.email if hasattr(owner, 'email') else owner.get_email()
        send_email("[%s] %s" % (config.PORTAL_NAME, title), body, email)


def create_dns_a_record(owner, domain_name, ip_addr):
    """Will try to create DNS A record for specified domain name and IP addr.

    All clouds for which there is DNS support will be tried to see if the
    relevant zone exists.

    """

    # split domain_name in dot separated parts
    parts = [part for part in domain_name.split('.') if part]
    # find all possible domains for this domain name, longest first
    all_domains = {}
    for i in range(1, len(parts) - 1):
        host = '.'.join(parts[:i])
        domain = '.'.join(parts[i:]) + '.'
        all_domains[domain] = host
    if not all_domains:
        raise MistError("Couldn't extract a valid domain from '%s'."
                        % domain_name)

    # iterate over all clouds that can also be used as DNS providers
    providers = {}
    clouds = Cloud.objects(owner=owner)
    for cloud in clouds:
        if isinstance(cloud, cloud_models.AmazonCloud):
            provider = DnsProvider.ROUTE53
            creds = cloud.apikey, cloud.apisecret
        # TODO: add support for more providers
        # elif cloud.provider == Provider.LINODE:
        #    pass
        # elif cloud.provider == Provider.RACKSPACE:
        #    pass
        else:
            # no DNS support for this provider, skip
            continue
        if (provider, creds) in providers:
            # we have already checked this provider with these creds, skip
            continue

        try:
            conn = get_dns_driver(provider)(*creds)
            zones = conn.list_zones()
        except InvalidCredsError:
            log.error("Invalid creds for DNS provider %s.", provider)
            continue
        except Exception as exc:
            log.error("Error listing zones for DNS provider %s: %r",
                      provider, exc)
            continue

        # for each possible domain, starting with the longest match
        best_zone = None
        for domain in all_domains:
            for zone in zones:
                if zone.domain == domain:
                    log.info("Found zone '%s' in provider '%s'.",
                             domain, provider)
                    best_zone = zone
                    break
            if best_zone:
                break

        # add provider/creds combination to checked list, in case multiple
        # clouds for same provider with same creds exist
        providers[(provider, creds)] = best_zone

    best = None
    for provider, creds in providers:
        zone = providers[(provider, creds)]
        if zone is None:
            continue
        if best is None or len(zone.domain) > len(best[2].domain):
            best = provider, creds, zone

    if not best:
        raise MistError("No DNS zone matches specified domain name.")

    provider, creds, zone = best
    name = all_domains[zone.domain]
    log.info("Will use name %s and zone %s in provider %s.",
             name, zone.domain, provider)

    msg = ("Creating A record with name %s for %s in zone %s in %s"
           % (name, ip_addr, zone.domain, provider))
    try:
        record = zone.create_record(name, RecordType.A, ip_addr)
    except Exception as exc:
        raise MistError(msg + " failed: %r" % repr(exc))
    log.info(msg + " succeeded.")
    return record
