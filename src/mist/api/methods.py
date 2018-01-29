import os
import re
import json
import shutil
import tempfile
import subprocess

import requests

import pingparsing


from mongoengine import ValidationError, NotUniqueError, DoesNotExist

from time import time

from libcloud.compute.types import Provider
from libcloud.common.types import InvalidCredsError
from libcloud.utils.networking import is_private_subnet
from libcloud.dns.types import Provider as DnsProvider
from libcloud.dns.types import RecordType
from libcloud.dns.providers import get_driver as get_dns_driver

import ansible.playbook
import ansible.utils.template
import ansible.callbacks
import ansible.utils
import ansible.constants

from mist.api.shell import Shell

from mist.api.helpers import get_auth_header

from mist.api.exceptions import *

from mist.api.helpers import trigger_session_update
from mist.api.helpers import amqp_publish_user
from mist.api.helpers import StdStreamCapture

from mist.api.helpers import dirty_cow, parse_os_release

import mist.api.tasks
import mist.api.inventory

from mist.api.clouds.models import Cloud
from mist.api.networks.models import NETWORKS, SUBNETS, Network, Subnet
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


def list_images(owner, cloud_id, term=None):
    """List images from each cloud"""
    return Cloud.objects.get(owner=owner, id=cloud_id,
                             deleted=None).ctl.compute.list_images(term)


def star_image(owner, cloud_id, image_id):
    """Toggle image star (star/unstar)"""
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)

    star = cloud.ctl.compute.image_is_starred(image_id)
    if star:
        if image_id in cloud.starred:
            cloud.starred.remove(image_id)
        if image_id not in cloud.unstarred:
            cloud.unstarred.append(image_id)
    else:
        if image_id not in cloud.starred:
            cloud.starred.append(image_id)
        if image_id in cloud.unstarred:
            cloud.unstarred.remove(image_id)
    cloud.save()
    task = mist.api.tasks.ListImages()
    task.clear_cache(owner.id, cloud_id)
    task.delay(owner.id, cloud_id)
    return not star


def list_sizes(owner, cloud_id):
    """List sizes (aka flavors) from each cloud"""
    return Cloud.objects.get(owner=owner, id=cloud_id,
                             deleted=None).ctl.compute.list_sizes()


def list_locations(owner, cloud_id):
    """List locations from each cloud"""
    return Cloud.objects.get(owner=owner, id=cloud_id,
                             deleted=None).ctl.compute.list_locations()


def list_subnets(cloud, network):
    """List subnets for a particular network on a given cloud.
    Currently EC2, Openstack and GCE clouds are supported. For other providers
    this returns an empty list.
    """
    if not hasattr(cloud.ctl, 'network'):
        return []
    subnets = cloud.ctl.network.list_subnets(network=network)
    return [subnet.as_dict() for subnet in subnets]


def list_projects(owner, cloud_id):
    """List projects for each account.
    Currently supported for Packet.net. For other providers
    this returns an empty list
    """
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    conn = connect_provider(cloud)

    ret = {}
    if conn.type in [Provider.PACKET]:
        projects = conn.ex_list_projects()
    else:
        projects = []

    ret = [{'id': project.id,
            'name': project.name,
            'extra': project.extra
            }
           for project in projects]
    return ret

    if conn.type == 'libvirt':
        # close connection with libvirt
        conn.disconnect()
    return ret


def list_resource_groups(owner, cloud_id):
    """List resource groups for each account.
    Currently supported for Azure Arm. For other providers
    this returns an empty list
    """
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    conn = connect_provider(cloud)

    ret = {}
    if conn.type in [Provider.AZURE_ARM]:
        groups = conn.ex_list_resource_groups()
    else:
        groups = []

    ret = [{'id': group.name,
            'name': group.name,
            'extra': group.extra
            }
           for group in groups]
    return ret

    if conn.type == 'libvirt':
        # close connection with libvirt
        conn.disconnect()
    return ret


def list_storage_accounts(owner, cloud_id):
    """List storage accounts for each account.
    Currently supported for Azure Arm. For other providers
    this returns an empty list
    """
    cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    conn = connect_provider(cloud)

    ret = {}
    if conn.type in [Provider.AZURE_ARM]:
        accounts = conn.ex_list_storage_accounts()
    else:
        accounts = []

    ret = [{'id': account.name,
            'name': account.name,
            'extra': account.extra
            }
           for account in accounts]
    return ret

    if conn.type == 'libvirt':
        # close connection with libvirt
        conn.disconnect()
    return ret

def create_subnet(owner, cloud, network, subnet_params):
    """
    Create a new subnet attached to the specified network ont he given cloud.
    Subnet_params is a dict containing all the necessary values that describe a subnet.
    """
    if not hasattr(cloud.ctl, 'network'):
        raise NotImplementedError()

    # Create a DB document for the new subnet and call libcloud
    #  to declare it on the cloud provider
    new_subnet = SUBNETS[cloud.ctl.provider].add(network=network,
                                                 **subnet_params)

    # Schedule a UI update
    trigger_session_update(owner, ['clouds'])

    return new_subnet


def delete_subnet(owner, subnet):
    """
    Delete a subnet.
    """
    subnet.ctl.delete()

    # Schedule a UI update
    trigger_session_update(owner, ['clouds'])


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
        "sudo -n uptime 2>&1|"
        "grep load|"
        "wc -l && "
        "echo -------- && "
        "uptime && "
        "echo -------- && "
        "if [ -f /proc/uptime ]; then cat /proc/uptime | cut -d' ' -f1; "
        "else expr `date '+%s'` - `sysctl kern.boottime | sed -En 's/[^0-9]*([0-9]+).*/\\1/p'`;"
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
        "\"|sh"  # In case there is a default shell other than bash/sh (e.g. csh)
    )

    if key_id:
        log.warn('probing with key %s' % key_id)

    if not shell:
        cmd_output = ssh_command(owner, cloud_id, machine_id,
                                 host, command, key_id=key_id)
    else:
        retval, cmd_output = shell.command(command)
    cmd_output = [str(part).strip()
                  for part in cmd_output.replace('\r', '').split('--------')]
    log.warn(cmd_output)
    uptime_output = cmd_output[1]
    loadavg = re.split('load averages?: ', uptime_output)[1].split(', ')
    users = re.split(' users?', uptime_output)[0].split(', ')[-1].strip()
    uptime = cmd_output[2]
    cores = cmd_output[3]
    ips = re.findall('inet addr:(\S+)', cmd_output[4])
    m = re.findall('((?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})', cmd_output[4])
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
    os, os_version = parse_os_release(os_release)

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
        'dirty_cow': dirty_cow(os, os_version, kernel_version)
    }


def _ping_host(host, pkts=10):
    ping = subprocess.Popen(['ping', '-c', str(pkts), '-i', '0.4', '-W',
                             '1', '-q', host], stdout=subprocess.PIPE)
    ping_parser = pingparsing.PingParsing()
    ping_parser.parse(ping.stdout.read())
    return ping_parser.as_dict()


def ping(owner, host, pkts=10):
    if config.HAS_CORE:
        from mist.core.vpn.methods import super_ping
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
        body += "Output: %s\n" % kwargs['output'].decode('utf-8', 'ignore')

    if email_notify:
        from mist.api.helpers import send_email
        email = owner.email if hasattr(owner, 'email') else owner.get_email()
        send_email("[mist.io] %s" % title, body.encode('utf-8', 'ignore'),
                   email)


def undeploy_python_plugin(owner, cloud_id, machine_id, plugin_id, host):

    # Sanity checks
    if not plugin_id:
        raise RequiredParameterMissingError('plugin_id')
    if not host:
        raise RequiredParameterMissingError('host')

    # Iniatilize SSH connection
    shell = Shell(host)
    key_id, ssh_user = shell.autoconfigure(owner, cloud_id, machine_id)

    # Prepare collectd.conf
    script = """
sudo=$(command -v sudo)
cd /opt/mistio-collectd/

echo "Removing Include line for plugin conf from plugins/mist-python/include.conf"
$sudo grep -v 'Import %(plugin_id)s$' plugins/mist-python/include.conf > /tmp/include.conf
$sudo mv /tmp/include.conf plugins/mist-python/include.conf

echo "Restarting collectd"
$sudo /opt/mistio-collectd/collectd.sh restart
""" % {'plugin_id': plugin_id}

    retval, stdout = shell.command(script)

    shell.disconnect()

    return {'metric_id': None, 'stdout': stdout}


def run_playbook(owner, cloud_id, machine_id, playbook_path, extra_vars=None,
                 force_handlers=False, debug=False):
    if not extra_vars:
        extra_vars = None
    ret_dict = {
        'success': False,
        'started_at': time(),
        'finished_at': 0,
        'stdout': '',
        'error_msg': '',
        'inventory': '',
        'stats': {},
    }
    inventory = mist.api.inventory.MistInventory(owner,
                                                [(cloud_id, machine_id)])
    if len(inventory.hosts) != 1:
        log.error("Expected 1 host, found %s", inventory.hosts)
        ret_dict['error_msg'] = "Expected 1 host, found %s" % inventory.hosts
        ret_dict['finished_at'] = time()
        return ret_dict
    ret_dict['host'] = inventory.hosts.values()[0]['ansible_ssh_host']
    machine_name = inventory.hosts.keys()[0]
    log_prefix = "Running playbook '%s' on machine '%s'" % (playbook_path,
                                                            machine_name)
    files = inventory.export(include_localhost=False)
    ret_dict['inventory'] = files['inventory']
    tmp_dir = tempfile.mkdtemp()
    old_dir = os.getcwd()
    os.chdir(tmp_dir)
    try:
        log.debug("%s: Saving inventory files", log_prefix)
        os.mkdir('id_rsa')
        for name, data in files.items():
            with open(name, 'w') as f:
                f.write(data)
        for name in os.listdir('id_rsa'):
            os.chmod('id_rsa/%s' % name, 0600)
        log.debug("%s: Inventory files ready", log_prefix)

        playbook_path = '%s/%s' % (old_dir, playbook_path)
        ansible_hosts_path = 'inventory'
        # extra_vars['host_key_checking'] = False

        ansible.utils.VERBOSITY = 4 if debug else 0
        ansible.constants.HOST_KEY_CHECKING = False
        ansible.constants.ANSIBLE_NOCOWS = True
        stats = ansible.callbacks.AggregateStats()
        playbook_cb = ansible.callbacks.PlaybookCallbacks(
            verbose=ansible.utils.VERBOSITY
        )
        runner_cb = ansible.callbacks.PlaybookRunnerCallbacks(
            stats, verbose=ansible.utils.VERBOSITY
        )
        log.error(old_dir)
        log.error(tmp_dir)
        log.error(extra_vars)
        log.error(playbook_path)
        capture = StdStreamCapture()
        try:
            playbook = ansible.playbook.PlayBook(
                playbook=playbook_path,
                host_list=ansible_hosts_path,
                callbacks=playbook_cb,
                runner_callbacks=runner_cb,
                stats=stats,
                extra_vars=extra_vars,
                force_handlers=force_handlers,
            )
            result = playbook.run()
        except Exception as exc:
            log.error("%s: Error %r", log_prefix, exc)
            ret_dict['error_msg'] = repr(exc)
        finally:
            ret_dict['finished_at'] = time()
            ret_dict['stdout'] = capture.close()
        if ret_dict['error_msg']:
            return ret_dict
        log.debug("%s: Ansible result = %s", log_prefix, result)
        mresult = result[machine_name]
        ret_dict['stats'] = mresult
        if mresult['failures'] or mresult['unreachable']:
            log.error("%s: Ansible run failed: %s", log_prefix, mresult)
            return ret_dict
        log.info("%s: Ansible run succeeded: %s", log_prefix, mresult)
        ret_dict['success'] = True
        return ret_dict
    finally:
        os.chdir(old_dir)
        if not debug:
            shutil.rmtree(tmp_dir)


def _notify_playbook_result(owner, res, cloud_id=None, machine_id=None,
                            extra_vars=None, label='Ansible playbook'):
    title = label + (' succeeded' if res['success'] else ' failed')
    kwargs = {
        'cloud_id': cloud_id,
        'machine_id': machine_id,
        'duration': res['finished_at'] - res['started_at'],
        'error': False if res['success'] else res['error_msg'] or True,
    }
    if not res['success']:
        kwargs['output'] = res['stdout']
    notify_user(owner, title, **kwargs)


def deploy_collectd(owner, cloud_id, machine_id, extra_vars):
    ret_dict = run_playbook(
        owner, cloud_id, machine_id,
        playbook_path='deploy_collectd/ansible/enable.yml',
        extra_vars=extra_vars,
        force_handlers=True,
        # debug=True,
    )
    _notify_playbook_result(owner, ret_dict, cloud_id, machine_id,
                            label='Collectd deployment')
    return ret_dict


def undeploy_collectd(owner, cloud_id, machine_id):
    ret_dict = run_playbook(
        owner, cloud_id, machine_id,
        playbook_path='deploy_collectd/ansible/disable.yml',
        force_handlers=True,
        # debug=True,
    )
    _notify_playbook_result(owner, ret_dict, cloud_id, machine_id,
                            label='Collectd undeployment')
    return ret_dict


def get_deploy_collectd_command_unix(uuid, password, monitor, port=25826):
    url = "https://github.com/mistio/deploy_collectd/raw/master/local_run.py"
    cmd = "wget -O mist_collectd.py %s && $(command -v sudo) python mist_collectd.py %s %s" % (url, uuid, password)
    if monitor != 'monitor1.mist.api':
        cmd += " -m %s" % monitor
    if str(port) != '25826':
        cmd += " -p %s" % port
    return cmd


def get_deploy_collectd_command_windows(uuid, password, monitor, port=25826):
    return 'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned ' \
           '-Scope CurrentUser -Force;(New-Object System.Net.WebClient).' \
           'DownloadFile(\'https://raw.githubusercontent.com/mistio/' \
           'deploy_collectm/master/collectm.remote.install.ps1\',' \
           ' \'.\collectm.remote.install.ps1\');.\collectm.remote.install.ps1 ' \
           '-SetupConfigFile -setupArgs \'-username "%s" -password "%s" ' \
           '-servers @("%s:%s")\'' % (uuid, password, monitor, port)


def get_deploy_collectd_command_coreos(uuid, password, monitor, port=25826):
    return "sudo docker run -d -v /sys/fs/cgroup:/sys/fs/cgroup -e COLLECTD_USERNAME=%s -e COLLECTD_PASSWORD=%s -e MONITOR_SERVER=%s -e COLLECTD_PORT=%s mist/collectd" % (
        uuid, password, monitor, port)


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

    # debug
    # log.debug("Will print all existing A records for zone '%s'.", zone.domain)
    # for record in zone.list_records():
    #    if record.type == 'A':
    #        log.info("%s -> %s", record.name, record.data)

    msg = ("Creating A record with name %s for %s in zone %s in %s"
           % (name, ip_addr, zone.domain, provider))
    try:
        record = zone.create_record(name, RecordType.A, ip_addr)
    except Exception as exc:
        raise MistError(msg + " failed: %r" % repr(exc))
    log.info(msg + " succeeded.")
    return record


# FIXME DEPRECATED
def rule_triggered(machine, rule_id, value, triggered, timestamp,
                   notification_level, incident_id):
    from mist.api.rules.models import NoDataRule
    from mist.api.rules.methods import run_chained_actions
    if config.HAS_CORE and rule_id == 'nodata':
        rule = NoDataRule.objects.get(owner_id=machine.owner.id, title='NoData')
        rule_id = rule.title
    run_chained_actions(rule_id, machine, value, triggered, timestamp,
                        notification_level, incident_id)
