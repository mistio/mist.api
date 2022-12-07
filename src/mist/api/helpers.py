"""Helper functions used in views and WSGI initialization

This file is imported in many places. Importing other mist modules into this
file causes circular import errors.

Try to not put anything in here that depends on other mist code, with the
exception of mist.api.config.

In general, this file should only contain generic helper functions that one
could easily use in some other unrelated project.

"""

import asyncio
from asgiref.sync import async_to_sync
from rstream import Consumer, amqp_decoder, AMQPMessage
from rstream.exceptions import StreamDoesNotExist
from functools import reduce
from mist.api import config
from mist.api.exceptions import WorkflowExecutionError, BadRequestError
from mist.api.exceptions import PolicyUnauthorizedError, ForbiddenError
from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import MistError, NotFoundError
from mist.api.auth.models import ApiToken, datetime_to_str
import mist.api.users.models
from libcloud.container.types import Provider as Container_Provider
from libcloud.container.providers import get_driver as get_container_driver
from libcloud.container.drivers.docker import DockerException
from libcloud.container.base import ContainerImage
from elasticsearch import Elasticsearch
from distutils.version import LooseVersion
from amqp.exceptions import NotFound as AmqpNotFound
import kombu.pools
import kombu
from Crypto.Random import get_random_bytes
from Crypto.Hash.HMAC import HMAC
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests
import netaddr
import iso8601
from pyramid.httpexceptions import HTTPError
from pyramid.view import view_config as pyramid_view_config
from mongoengine import DoesNotExist, NotRegistered
from email.utils import formatdate, make_msgid
from contextlib import contextmanager
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from base64 import urlsafe_b64encode
import dateparser
from datetime import timedelta
from time import time, strftime, sleep
import subprocess
import jsonpickle
import traceback
import tempfile
import datetime
import urllib.parse
import os
import re
import sys
import json
import shutil
import string
import random
import socket
import smtplib
import logging
import codecs
import secrets
import operator

# Python 2 and 3 support
from future.utils import string_types
from future.standard_library import install_aliases
install_aliases()


if config.HAS_RBAC:
    from mist.rbac.tokens import SuperToken


logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)


@contextmanager
def get_cloned_git_path(repo, branch="master"):
    """Create a temp dir to clone a git repo into.

    The HEAD of the specified branch is cloned into a temp dir.

    This method yields the path to the temporary directory. Once the `with`
    block has been exited, the entire tree under `tmpdir` is removed.

    """
    tmpdir = tempfile.mkdtemp()
    cmd = ["git", "clone", "--depth", "1", "--branch", branch, repo, tmpdir]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as err:
        raise Exception("Error cloning %s in %s: %r" % (repo, tmpdir, err))
    try:
        yield tmpdir
    finally:
        try:
            shutil.rmtree(tmpdir)
        except:
            pass


@contextmanager
def get_temp_file(content, dir=None):
    """Creates a temporary file on disk and saves 'content' in it.

    It is meant to be used like this:
    with get_temp_file(my_string) as file_path:
        do_stuff(file_path)

    Once the with block is exited, the file is always deleted, even if an
    exception has been raised.

    """
    (tmp_fd, tmp_path) = tempfile.mkstemp(dir=dir)
    f = os.fdopen(tmp_fd, 'w+b')
    f.write(bytes(content, 'utf-8'))
    f.close()
    try:
        yield tmp_path
    finally:
        try:
            os.remove(tmp_path)
        except:
            pass


def atomic_write_file(path, content):
    # Store first into a tmp file, and then move it (atomically) to target
    # position, to avoid target file getting corrupted in case of concurrent
    # writers. Tmp file is stored in target dir, to make sure it's in same
    # mount as target file, cause otherwise move won't work, a copy would be
    # required instead (which would beat the purpose of all this).
    with get_temp_file(content, dir=os.path.dirname(path)) as tmp_path:
        os.rename(tmp_path, path)


def is_email_valid(email):
    """E-mail address validator.

    Ensure the e-mail is a valid expression and the provider is not banned.

    """
    match = re.match(r'^[\w\.-]+@([a-zA-Z0-9-]+)(\.[a-zA-Z0-9-]+)+$', email)
    return (match and
            ''.join(match.groups()) not in config.BANNED_EMAIL_PROVIDERS)


def params_from_request(request):
    """Get the parameters dict from request.

    Searches if there is a json payload or http parameters and returns
    the dict.

    """
    try:
        params = request.json_body
    except:
        params = request.params
    return params or {}


def delete_none(dikt):
    for k, v in list(dikt.items()):
        if v is None:
            del dikt[k]
        elif isinstance(v, dict):
            delete_none(v)
        elif isinstance(v, list):
            for el in v:
                if isinstance(el, dict):
                    delete_none(el)
    return dikt


def get_auth_header(user):
    """The value created here is added as an "Authorization" header in HTTP
    requests towards the hosted mist core service.
    """
    return user.mist_api_token


def parse_os_release(os_release):
    """
    Extract os name and version from the output of `cat /etc/*release`
    """
    os = ''
    os_version = ''
    os_release = os_release.replace('"', '')
    distro = ''
    lines = os_release.split("\n")

    # ClearOS specific
    # Needs a general update. We should find the whole distro string and
    # extract more specific information like os = linux, os_family = red_hat
    # etc.
    for line in lines:
        if 'clearos' in line.lower():
            distro = line
            os = 'clearos'
            os_version = line.partition(" ")[-1]
            return os, os_version, distro

    # Find ID which corresponds to the OS's name
    re_id = r'^ID=(.*)'
    # Find VERSION_ID which is the specific version (e.g. 7 in Debian 7)
    re_version = r'^VERSION_ID=(.*)'

    for line in lines:
        match_id = re.match(re_id, line)
        if match_id:
            os = match_id.group(1)

        match_version = re.match(re_version, line)
        if match_version:
            os_version = match_version.group(1)

    return os, os_version, distro


def dirty_cow(os, os_version, kernel_version):
    """
    Compares the current version to the vulnerable ones and returns
    True if vulnerable, False if safe, None if not matched with
    anything.
    """
    min_patched_version = "3.2.0"

    vulnerables = {
        "ubuntu":
        {
            "16.10": "4.8.0-26.28",
            "16.04": "4.4.0-45.66",
            "14.04": "3.13.0-100.147",
            "12.04": "3.2.0-113.155"
        },
        "debian":
        {
            "7": "3.2.82-1",
            "8": "3.16.36-1+deb8u2"
        },
        "centos":
        {
            "6": "3.10.58-rt62.60.el6rt",
            "7": "3.10.0-327.36.1.rt56.237.el7"
        },
        "rhel":
        {
            "6": "3.10.58-rt62.60.el6rt",
            "6.8": "3.10.58-rt62.60.el6rt",
            "7": "3.10.0-327.36.1.rt56.237.el7",
            "7.2": "3.10.0-327.36.1.rt56.237.el7"
        },
    }

    # If version is lower that min_patched_version it is most probably
    # vulnerable
    if LooseVersion(kernel_version) < LooseVersion(min_patched_version):
        return True

    # If version is greater/equal to 4.9 it is patched
    if LooseVersion(kernel_version) >= LooseVersion('4.9.0'):
        return False

    os = os.lower()

    # In case of CoreOS, where we have no discrete VERSION_ID
    if os == 'coreos':
        if LooseVersion(kernel_version) <= LooseVersion('4.7.0'):
            return True
        else:
            return False

    if os not in list(vulnerables.keys()):
        return None

    if os_version not in list(vulnerables[os].keys()):
        return None

    vuln_version = vulnerables[os][os_version]
    if LooseVersion(kernel_version) <= LooseVersion(vuln_version):
        return True
    else:
        return False


def amqp_publish(exchange, routing_key, data,
                 ex_type='fanout', ex_declare=False,
                 durable=False, auto_delete=True):
    exchange = kombu.Exchange(exchange, type=ex_type, auto_delete=auto_delete,
                              durable=False)
    with kombu.pools.producers[kombu.Connection(config.BROKER_URL)].acquire(
            block=True, timeout=10) as producer:
        producer.publish(data, exchange=exchange, routing_key=routing_key,
                         declare=[exchange] if ex_declare else [],
                         serializer='json', retry=True)


def amqp_subscribe(exchange, callback, queue='',
                   ex_type='fanout', routing_keys=None, durable=False,
                   auto_delete=True):
    with kombu.pools.connections[kombu.Connection(config.BROKER_URL)].acquire(
            block=True, timeout=10) as connection:
        exchange = kombu.Exchange(exchange, type=ex_type, durable=durable,
                                  auto_delete=auto_delete)
        if not routing_keys:
            queue = kombu.Queue(queue, exchange, exclusive=True)
        else:
            queue = kombu.Queue(queue,
                                [kombu.binding(exchange, routing_key=key)
                                 for key in routing_keys],
                                exclusive=True)
        with connection.Consumer([queue], callbacks=[callback], no_ack=True):
            while True:
                connection.drain_events()


def _amqp_owner_exchange(owner):
    # The exchange/queue name consists of a non-empty sequence of these
    # characters: letters, digits, hyphen, underscore, period, or colon.
    if not isinstance(owner, mist.api.users.models.Owner):
        try:
            owner = mist.api.users.models.Owner.objects.get(id=owner)
        except Exception as exc:
            raise Exception('%r %r' % (exc, owner))
    return "owner_%s" % owner.id


def amqp_publish_user(owner, routing_key, data):
    with kombu.Connection(config.BROKER_URL) as connection:
        channel = connection.channel()
        try:
            kombu.Producer(channel).publish(
                data, exchange=kombu.Exchange(_amqp_owner_exchange(owner)),
                routing_key=routing_key, serializer='json', retry=True
            )
            started_at = time()
            while True:
                try:
                    connection.drain_events(timeout=0.5)
                except AmqpNotFound:
                    raise
                except:
                    pass
                if time() - started_at >= 0.5:
                    break
        except AmqpNotFound:
            return False
        else:
            return True
        finally:
            channel.close()


def amqp_subscribe_user(owner, queue, callback):
    amqp_subscribe(_amqp_owner_exchange(owner), callback, queue)


def amqp_owner_listening(owner, retries=3):
    exchange = kombu.Exchange(_amqp_owner_exchange(owner), type='fanout')
    with kombu.pools.connections[kombu.Connection(config.BROKER_URL)].acquire(
            block=True, timeout=10) as connection:
        try:
            exchange(connection).declare(passive=True)
        except AmqpNotFound:
            return False
        except TimeoutError:
            if retries:
                return amqp_owner_listening(owner,
                                            retries - 1)
            else:
                log.error(
                    'Timed out multiple times when connecting to RabbitMQ')
                return False
        else:
            return True


def trigger_session_update(owner, sections=['clouds', 'keys', 'monitoring',
                                            'scripts', 'templates', 'stacks',
                                            'schedules', 'user', 'org',
                                            'zones']):
    amqp_publish_user(owner, routing_key='update', data=sections)


def amqp_log(msg):
    return
    msg = "[%s] %s" % (strftime("%Y-%m-%d %H:%M:%S %Z"), msg)
    try:
        amqp_publish('mist_debug', '', msg)
    except:
        pass


def amqp_log_listen():
    def echo(body, msg):
        print(body)
        print(msg)

    amqp_subscribe('mist_debug', echo)


class StdStreamCapture(object):
    def __init__(self, stdout=True, stderr=True, func=None, pass_through=True):
        """Starts to capture sys.stdout/sys.stderr"""
        self.func = func
        self.pass_through = pass_through
        self.buff = []
        self.streams = {}
        if stdout:
            self.streams['stdout'] = sys.stdout
        if stderr:
            self.streams['stderr'] = sys.stderr

        class Stream(object):
            def __init__(self, name):
                self.name = name

            def write(_self, text):
                self._write(_self.name, text)

        for name in self.streams:
            setattr(sys, name, Stream(name))

    def _write(self, name, text):
        self.buff.append((name, text))
        if self.pass_through:
            self.streams[name].write(text)
        if self.func is not None:
            self.func(name, text)

    def _get_capture(self, names=('stdout', 'stderr')):
        buff = ""
        for name, text in self.buff:
            if name in names:
                buff += text
        return buff

    def get_stdout(self):
        return self._get_capture(['stdout'])

    def get_stderr(self):
        return self._get_capture(['stderr'])

    def get_mux(self):
        return self._get_capture()

    def close(self):
        for name in self.streams:
            setattr(sys, name, self.streams[name])
        return self.get_mux()


def sanitize_host(host):
    """Return the hostname or ip address out of a URL"""

    for prefix in ['https://', 'http://']:
        host = host.replace(prefix, '')

    host = host.split('/')[0]
    host = host.split(':')[0]

    return host


def extract_port(url):
    """Returns the port number out of a url"""
    for prefix in ['http://', 'https://']:
        if prefix in url:
            url = url.replace(prefix, '')
            break
    else:
        prefix = ''
    url = url.split('/')[0]
    url = url.split(':')
    if len(url) > 1:
        return int(url[1])
    elif prefix == 'https://':
        return 443
    else:
        return 80


def extract_params(url):
    """Extracts the trailing params beyond the port number out of a url"""
    for prefix in ['http://', 'https://']:
        url = url.replace(prefix, '')
    params = url.split('/')[1:]
    params = '/'.join(params)
    return params


def extract_prefix(url, prefixes=['http://', 'https://']):
    """Extracts the (http, https) prefix out of a given url"""
    try:
        return [prefix for prefix in prefixes if prefix in url][0]
    except IndexError:
        return ''


def check_host(host, allow_localhost=config.ALLOW_CONNECT_LOCALHOST,
               allow_inaddr_any=False):
    """Check if a given host is a valid DNS name or IPv4 address"""

    try:
        ipaddr = socket.gethostbyname(host)
    except UnicodeEncodeError:
        raise MistError('Please provide a valid DNS name')
    except socket.gaierror:
        raise MistError("Not a valid IP address or resolvable DNS name: '%s'."
                        % host)

    if host != ipaddr:
        msg = "Host '%s' resolves to '%s' which" % (host, ipaddr)
    else:
        msg = "Host '%s'" % host

    if not netaddr.valid_ipv4(ipaddr):
        raise MistError(msg + " is not a valid IPv4 address.")

    forbidden_subnets = {
        '100.64.0.0/10': ("used for communications between a service provider "
                          "and its subscribers when using a "
                          "Carrier-grade NAT"),
        '169.254.0.0/16': ("used for link-local addresses between two hosts "
                           "on a single link when no IP address is otherwise "
                           "specified"),
        '192.0.0.0/24': ("used for the IANA IPv4 Special Purpose Address "
                         "Registry"),
        '192.0.2.0/24': ("assigned as 'TEST-NET' for use solely in "
                         "documentation and example source code"),
        '192.88.99.0/24': "used by 6to4 anycast relays",
        '198.18.0.0/15': ("used for testing of inter-network communications "
                          "between two separate subnets"),
        '198.51.100.0/24': ("assigned as 'TEST-NET-2' for use solely in "
                            "documentation and example source code"),
        '203.0.113.0/24': ("assigned as 'TEST-NET-3' for use solely in "
                           "documentation and example source code"),
        '224.0.0.0/4': "reserved for multicast assignments",
        '240.0.0.0/4': "reserved for future use",
        '255.255.255.255/32': ("reserved for the 'limited broadcast' "
                               "destination address"),
    }

    if not allow_inaddr_any:
        forbidden_subnets['0.0.0.0/8'] = ("used for broadcast messages "
                                          "to the current network")

    if not allow_localhost:
        forbidden_subnets['127.0.0.0/8'] = ("used for loopback addresses "
                                            "to the local host")

    cidr = netaddr.smallest_matching_cidr(ipaddr,
                                          list(forbidden_subnets.keys()))
    if cidr:
        raise MistError("%s is not allowed. It belongs to '%s' "
                        "which is %s." % (msg, cidr,
                                          forbidden_subnets[str(cidr)]))


def transform_key_machine_associations(associations):
    try:
        transformed = [
            {
                'cloud_id': association.machine.cloud.id,
                'machine_id': association.machine.id,
                'last_used': association.last_used,
                'ssh_user': association.ssh_user,
                'sudo': association.sudo,
                'port': association.port,
                'association_id': association.id
            }
            for association in associations
        ]
    except (DoesNotExist, NotRegistered):
        # If there are broken references get rid of them
        transformed = []
        for association in associations:
            try:
                transformed.append({
                    'cloud_id': association.machine.cloud.id,
                    'machine_id': association.machine.id,
                    'last_used': association.last_used,
                    'ssh_user': association.ssh_user,
                    'sudo': association.sudo,
                    'port': association.port,
                    'association_id': association.id
                })
            except (DoesNotExist, NotRegistered):
                association.delete()
    return transformed


def get_datetime(timestamp):
    """Parse several representations of time into a datetime object"""
    if isinstance(timestamp, datetime.datetime):
        # Timestamp is already a datetime object.
        return timestamp
    elif isinstance(timestamp, (int, float)):
        try:
            # Handle Unix timestamps.
            return datetime.datetime.fromtimestamp(timestamp)
        except ValueError:
            pass
        try:
            # Handle Unix timestamps in milliseconds.
            return datetime.datetime.fromtimestamp(timestamp / 1000)
        except ValueError:
            pass
    elif isinstance(timestamp, string_types):
        try:
            timestamp = float(timestamp)
        except (ValueError, TypeError):
            pass
        else:
            # Timestamp is probably Unix timestamp given as string.
            return get_datetime(timestamp)
        try:
            # Try to parse as string date in common formats.
            return iso8601.parse_date(timestamp)
        except:
            pass
    # Fuck this shit.
    raise ValueError("Couldn't extract date object from %r" % timestamp)


def random_string(length=5, punc=False):
    """
    Generate a random string. Default length is set to 5 characters.
    When punc=True, the string will also contain punctuation apart
    from letters and digits
    """
    _chars = string.ascii_letters + string.digits
    _chars += string.punctuation if punc else ''
    return ''.join(random.choice(_chars) for _ in range(length))


def rename_kwargs(kwargs, old_key, new_key):
    """Given a `kwargs` dict rename `old_key` to `new_key`"""
    if old_key in kwargs:
        if new_key not in kwargs:
            log.warning("Got param '%s' when expecting '%s', transforming.",
                        old_key, new_key)
            kwargs[new_key] = kwargs.pop(old_key)
        else:
            log.warning("Got both param '%s' and '%s', will not transform.",
                        old_key, new_key)


def snake_to_camel(s):
    return reduce(lambda y, z: y + z.capitalize(), s.split('_'))


def ip_from_request(request):
    """Extract IP address from HTTP Request headers."""
    return (request.environ.get('HTTP_X_REAL_IP') or
            request.environ.get('HTTP_X_FORWARDED_FOR') or
            request.environ.get('REMOTE_ADDR') or
            '0.0.0.0').split(',')[0].strip()


def send_email(subject, body, recipients, sender=None, bcc=None, attempts=3,
               html_body=None):
    """Send email.

    subject: email's subject
    body: email's body
    recipients: an email address as a string or an iterable of email addresses
    sender: the email address of the sender. default value taken from config

    """

    if not sender:
        sender = config.EMAIL_FROM
    if isinstance(recipients, string_types):
        recipients = [recipients]

    if html_body:
        msg = MIMEMultipart('alternative')
    else:
        msg = MIMEText(body, 'plain')

    msg["Subject"] = subject
    msg["From"] = sender
    msg["Date"] = formatdate()
    msg["To"] = ", ".join(recipients)
    msg["Message-ID"] = make_msgid()

    if bcc:
        msg["Bcc"] = bcc
        recipients.append(bcc)

    if html_body:
        part1 = MIMEText(body, "plain", "utf-8")
        part2 = MIMEText(html_body, "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)

    mail_settings = config.MAILER_SETTINGS
    host = mail_settings.get('mail.host')
    port = mail_settings.get('mail.port', '5555')
    username = mail_settings.get('mail.username')
    password = mail_settings.get('mail.password')
    tls = mail_settings.get('mail.tls')
    starttls = mail_settings.get('mail.starttls')
    ret_val = False
    # try 3 times to circumvent network issues
    for attempt in range(attempts):
        try:
            if tls and not starttls:
                server = smtplib.SMTP_SSL(host, port)
            else:
                server = smtplib.SMTP(host, port)
            if tls and starttls:
                server.starttls()
            if username:
                server.login(username, password)

            server.sendmail(sender, recipients, msg.as_string())
            ret_val = True
        except smtplib.SMTPException as exc:
            if attempt == attempts - 1:
                log.error(
                    "Could not send email to %s after %d retries! Error: %r",
                    recipients, attempts, exc)
            else:
                log.warn("Could not send email! Error: %r", exc)
                log.warn("Retrying in 5 seconds...")
                sleep(5)
        finally:
            try:
                server.quit()
            except Exception as exc:
                log.error("Failed to terminate SMTP Session with exception %r",
                          exc)
            if ret_val:
                return ret_val
    return ret_val


rtype_to_classpath = {
    'cloud': 'mist.api.clouds.models.Cloud',
    'clouds': 'mist.api.clouds.models.Cloud',
    'cluster': 'mist.api.containers.models.Cluster',
    'clusters': 'mist.api.containers.models.Cluster',
    'bucket': 'mist.api.objectstorage.models.Bucket',
    'buckets': 'mist.api.objectstorage.models.Bucket',
    'machine': 'mist.api.machines.models.Machine',
    'machines': 'mist.api.machines.models.Machine',
    'zone': 'mist.api.dns.models.Zone',
    'record': 'mist.api.dns.models.Record',
    'script': 'mist.api.scripts.models.Script',
    'key': 'mist.api.keys.models.Key',
    'schedule': 'mist.api.schedules.models.Schedule',
    'network': 'mist.api.networks.models.Network',
    'networks': 'mist.api.networks.models.Network',
    'subnet': 'mist.api.networks.models.Subnet',
    'volume': 'mist.api.volumes.models.Volume',
    'volumes': 'mist.api.volumes.models.Volume',
    'location': 'mist.api.clouds.models.CloudLocation',
    'image': 'mist.api.images.models.CloudImage',
    'rule': 'mist.api.rules.models.Rule',
    'size': 'mist.api.clouds.models.CloudSize',
    'team': 'mist.api.users.models.Team',
    'users': 'mist.api.users.models.User',
    'user': 'mist.api.users.models.User',
    'orgs': 'mist.api.users.models.Organization',
    'org': 'mist.api.users.models.Organization',
    'secret': 'mist.api.secrets.models.VaultSecret',
}

if config.HAS_VPN:
    rtype_to_classpath.update(
        {'tunnel': 'mist.vpn.models.Tunnel'}
    )

if config.HAS_ORCHESTRATION:
    rtype_to_classpath.update(
        {'template': 'mist.orchestration.models.Template',
         'stack': 'mist.orchestration.models.Stack'}
    )


def get_resource_model(rtype):
    model_path = rtype_to_classpath[rtype]
    mod, member = model_path.rsplit('.', 1)
    __import__(mod)
    return getattr(sys.modules[mod], member)


def get_object_with_id(owner, rid, rtype, *args, **kwargs):
    query = {}
    if rtype in ['machine', 'network', 'image', 'location']:
        if 'cloud_id' not in kwargs:
            raise RequiredParameterMissingError('No cloud id provided')
        else:
            query.update({'cloud': kwargs['cloud_id']})
    if rtype == 'machine':
        query.update({'machine_id': rid})
    else:
        query.update({'id': rid, 'deleted': None})

    if rtype not in ['machine', 'image']:
        query.update({'owner': owner})

    try:
        resource_obj = get_resource_model(rtype).objects.get(**query)
    except DoesNotExist:
        raise NotFoundError('Resource with this id could not be located')

    return resource_obj


def ts_to_str(timestamp):
    """Return a timestamp as a nicely formatted datetime string."""
    try:
        date = datetime.datetime.fromtimestamp(timestamp)
        date_string = date.strftime("%d/%m/%Y %H:%M %Z")
        return date_string
    except:
        return None


def iso_to_seconds(iso):
    """Attempt to transform a time representation into seconds."""
    return get_datetime(iso).strftime('%s')


def encrypt(plaintext, key=config.SECRET, key_salt='', no_iv=False,
            segment_size=8):
    """Encrypt shit the right way"""

    # sanitize inputs
    key = SHA256.new((key + key_salt).encode()).digest()
    if len(key) not in AES.key_size:
        raise Exception()
    if isinstance(plaintext, string_types):
        plaintext = plaintext.encode('utf-8')
    # pad plaintext using PKCS7 padding scheme
    padlen = AES.block_size - len(plaintext) % AES.block_size
    plaintext += (chr(padlen) * padlen).encode('utf-8')

    # generate random initialization vector using CSPRNG
    if no_iv:
        iv = ('\0' * AES.block_size).encode()
    else:
        iv = get_random_bytes(AES.block_size)
    # encrypt using AES in CFB mode
    ciphertext = AES.new(key, AES.MODE_CFB, iv,
                         segment_size=segment_size).encrypt(plaintext)
    # prepend iv to ciphertext
    if not no_iv:
        ciphertext = iv + ciphertext
    # return ciphertext in hex encoding
    return ciphertext.hex()


def decrypt(ciphertext, key=config.SECRET, key_salt='', no_iv=False):
    """Decrypt shit the right way"""

    # sanitize inputs
    key = SHA256.new((key + key_salt).encode()).digest()
    if len(key) not in AES.key_size:
        raise Exception()
    if len(ciphertext) % AES.block_size:
        raise Exception()
    try:
        ciphertext = codecs.decode(ciphertext, 'hex')
    except TypeError:
        log.warning("Ciphertext wasn't given as a hexadecimal string.")

    # split initialization vector and ciphertext
    if no_iv:
        iv = '\0' * AES.block_size
    else:
        iv = ciphertext[:AES.block_size]
        ciphertext = ciphertext[AES.block_size:]

    # decrypt ciphertext using AES in CFB mode
    plaintext = AES.new(key, AES.MODE_CFB, iv).decrypt(ciphertext).decode()

    # validate padding using PKCS7 padding scheme
    padlen = ord(plaintext[-1])
    if padlen < 1 or padlen > AES.block_size:
        raise Exception()
    if plaintext[-padlen:] != chr(padlen) * padlen:
        raise Exception()
    plaintext = plaintext[:-padlen]

    return plaintext


def logging_view_decorator(func):
    """Decorator that logs a view function's request and response."""
    def logging_view(context, request):
        """Call view function and log API request and its response.

        If an exception is raised inside a view, then the exception handler
        view will be activated and the request along with its error response
        will be handled there.

        """
        # hack to preserve view function's name if an exception is raised
        # and handled by exception handler (otherwise we got exception_handler
        # as view_name)
        if not hasattr(request, 'real_view_name'):
            request.real_view_name = func.__name__

        # check if exception occurred
        try:
            response = func(context, request)
        except HTTPError as e:
            if request.path_info.startswith('/social_auth/complete'):
                log.info("There was a bad error during SSO connection: %s, "
                         "and request was %s" % (repr(e), request.__dict__))
            raise
        # check if exception occurred
        exc_flag = (config.LOG_EXCEPTIONS and
                    isinstance(context, Exception) and
                    not isinstance(context, MistError))

        if request.method in ('GET', 'HEAD') and not exc_flag:
            # only continue to log non GET/HEAD requests
            # that didn't raise exceptions)
            return response
        elif request.real_view_name in ('rule_triggered', 'not_found',
                                        'enable_insights', 'register'):
            # don't log these views no matter what
            return response
        # log request #
        log_dict = {
            'event_type': 'request',
            'action': request.real_view_name,
            'request_path': request.path_info,
            'request_method': request.method,
            'request_ip': ip_from_request(request),
            'user_agent': request.user_agent,
            'response_code': response.status_code,
            'error': response.status_code >= 400,
        }

        # log original exception
        if isinstance(context, MistError):
            if context.orig_exc:
                log_dict['_exc'] = repr(context.orig_exc)
                log_dict['_exc_type'] = type(context.orig_exc)
                if context.orig_traceback:
                    log_dict['_traceback'] = context.orig_traceback
        elif isinstance(context, Exception):
            log_dict['_exc'] = repr(context)
            log_dict['_exc_type'] = type(context)
            log_dict['_traceback'] = traceback.format_exc()

        # log session
        session = request.environ['session']
        if session:
            log_dict['session_id'] = str(session.id)
            try:
                if session.fingerprint:
                    log_dict['fingerprint'] = session.fingerprint
                if session.experiment:
                    log_dict['experiment'] = session.experiment
                if session.choice:
                    log_dict['choice'] = session.choice
            except AttributeError:  # in case of ApiToken
                pass

        # log user
        user = session.get_user(effective=False)
        if user is not None:
            log_dict['user_id'] = user.id
            sudoer = session.get_user()
            if sudoer != user:
                log_dict['sudoer_id'] = sudoer.id
            auth_context = mist.api.auth.methods.auth_context_from_request(
                request)
            if auth_context.org:
                log_dict['owner_id'] = auth_context.org.id
            else:
                log_dict['owner_id'] = ''
        else:
            log_dict['user_id'] = None
            log_dict['owner_id'] = None

        if isinstance(session, ApiToken):
            if 'dummy' not in session.name:
                log_dict['api_token_id'] = str(session.id)
                log_dict['api_token_name'] = session.name
                log_dict['api_token'] = session.token[:4] + '***CENSORED***'
                log_dict['token_expires'] = datetime_to_str(session.expires())

        # Log special Token.
        if config.HAS_RBAC and isinstance(session, SuperToken):
            log_dict['setuid'] = True
            log_dict['api_token_id'] = str(session.id)
            log_dict['api_token_name'] = session.name

        # log matchdict and params
        params = dict(params_from_request(request))
        for key in ['email', 'cloud', 'machine', 'rule', 'script_id',
                    'tunnel_id', 'story_id', 'stack_id', 'template_id',
                    'zone', 'record', 'network', 'subnet', 'volume', 'key',
                    'buckets', 'secret']:
            if key != 'email' and key in request.matchdict:
                if not key.endswith('_id'):
                    log_dict[key + '_id'] = request.matchdict[key]
                else:
                    log_dict[key] = request.matchdict[key]
                continue
            if key != 'email':
                key += '_id'
            if key in params:
                log_dict[key] = params.pop(key)
            if snake_to_camel(key) in params:
                log_dict[key] = params.pop(snake_to_camel(key))

        cloud_id = request.environ.get('cloud_id')
        if cloud_id and not log_dict.get('cloud_id'):
            log_dict['cloud_id'] = cloud_id

        machine_id = request.environ.get('machine_id')
        if machine_id and not log_dict.get('machine_id'):
            log_dict['external_id'] = request.environ.get('machine_id')

        machine_id = (
            request.matchdict.get(
                'machine', request.matchdict.get('machine_id', None)
            ) or params.get('machine', params.get('machine_id', None)) or (
                request.environ.get(
                    'machine', request.environ.get('machine_id', None)
                )
            )
        )
        if machine_id and not log_dict.get('machine'):
            log_dict['machine'] = machine_id

        # Attempt to hide passwords, API keys, certificates, etc.
        for key in ('priv', 'password', 'new_password', 'apikey', 'apisecret',
                    'cert_file', 'key_file', 'token'):  # FIXME
            if params.get(key):
                params[key] = '***CENSORED***'

        # Hide sensitive cloud credentials.
        if log_dict['action'] == 'add_cloud':
            provider = params.get('provider')
            censor = {'ec2': 'api_secret',
                      'rackspace': 'api_key',
                      'softlayer': 'api_key',
                      'onapp': 'api_key',
                      'digitalocean': 'token',
                      'gce': 'private_key',
                      'azure': 'certificate',
                      'linode': 'api_key',
                      'docker': 'auth_password',
                      'maxihost': 'token',
                      'openstack': 'password',
                      'vexxhost': 'password', }.get(provider)
            if censor and censor in params:
                params[censor] = '***CENSORED***'

        # Hide password from Git URL, if exists.
        if log_dict.get('action', '') == 'add_template':
            if params.get('location_type') == 'github':
                git_url = params.get('template_github', '')
                git_password = urllib.parse.urlparse(git_url).password
                if git_password:
                    params['template_github'] = git_url.replace(git_password,
                                                                '*password*')

        log_dict['request_params'] = params

        # log response body
        try:
            bdict = json.loads(response.body)
            for key in ('job_id', 'job',):
                if key in bdict and key not in log_dict:
                    log_dict[key] = bdict[key]
            if 'cloud' in bdict and 'cloud' not in log_dict:
                log_dict['cloud'] = bdict['cloud']
            if 'machine' in bdict and 'machine_id' not in log_dict:
                log_dict['machine'] = bdict['machine']
            if 'machine' in bdict and 'machine' not in log_dict:
                log_dict['machine'] = bdict['machine']
            # Match resource type based on the action performed.
            for rtype in ['cloud', 'machine', 'key', 'script', 'tunnel',
                          'stack', 'template', 'schedule', 'volume',
                          'zone', 'network', 'buckets', 'secret']:
                if rtype in log_dict['action']:
                    if 'id' in bdict and '%s_id' % rtype not in log_dict:
                        log_dict['%s_id' % rtype] = bdict['id']
                        break
            if log_dict['action'] == 'update_rule':
                if 'id' in bdict and 'rule_id' not in log_dict:
                    log_dict['rule_id'] = bdict['id']
            for key in ('priv', ):
                if key in bdict:
                    bdict[key] = '***CENSORED***'
            if 'token' in bdict:
                bdict['token'] = bdict['token'][:4] + '***CENSORED***'
            log_dict['response_body'] = json.dumps(bdict)
        except:
            log_dict['response_body'] = response.body

        # override logged action for specific views
        if log_dict['action'] == 'machine_actions':
            action = log_dict['request_params'].pop('action', None)
            if action:
                log_dict['action'] = '%s_machine' % action
        elif log_dict['action'] == 'toggle_cloud':
            state = log_dict['request_params'].pop('new_state', None)
            if state == '1':
                log_dict['action'] = 'enable_cloud'
            elif state == '0':
                log_dict['action'] = 'disable_cloud'
        elif log_dict['action'] == 'update_monitoring':
            if log_dict['request_params'].pop('action', None) == 'enable':
                log_dict['action'] = 'enable_monitoring'
            else:
                log_dict['action'] = 'disable_monitoring'
        elif log_dict['action'] == 'volume_action':
            if log_dict['request_params'].pop('action', None) == 'attach':
                log_dict['action'] = 'attach_volume'
            else:
                log_dict['action'] = 'detach_volume'

        # we save log_dict in mongo logging collection
        from mist.api.logs.methods import log_event as log_event_to_es
        log_event_to_es(**log_dict)

        # if a bad exception didn't occur then return, else log it to file
        if not exc_flag:
            return response

        # Publish traceback in rabbitmq, for heka to parse and forward to
        # elastic
        log.info("Bad exception occurred, logging to rabbitmq")
        es_dict = log_dict.copy()
        es_dict.pop('_exc_type')
        es_dict['time'] = time()
        es_dict['traceback'] = es_dict.pop('_traceback')
        es_dict['exception'] = es_dict.pop('_exc')
        es_dict['type'] = 'exception'
        routing_key = "%s.%s" % (es_dict['owner_id'], es_dict['action'])
        pickler = jsonpickle.pickler.Pickler()
        amqp_publish('exceptions', routing_key, pickler.flatten(es_dict),
                     ex_type='topic', ex_declare=True,
                     auto_delete=False)

        # log bad exception to file
        log.info("Bad exception occurred, logging to file")
        lines = []
        lines.append("Exception: %s" % log_dict.pop('_exc'))
        lines.append("Exception type: %s" % log_dict.pop('_exc_type'))
        lines.append("Time: %s" % strftime("%Y-%m-%d %H:%M %Z"))
        lines += (
            ["%s: %s" % (key, value) for key, value in list(log_dict.items())
             if value and key != '_traceback']
        )
        for key in ('owner', 'user', 'sudoer'):
            _id = log_dict.get('%s_id' % key)
            if _id:
                try:
                    value = mist.api.users.models.Owner.objects.get(id=_id)
                    lines.append("%s: %s" % (key, value))
                except mist.api.users.models.Owner.DoesNotExist:
                    pass
                except Exception as exc:
                    log.error("Error finding user in logged exc: %r", exc)
        lines.append("-" * 10)
        lines.append(log_dict['_traceback'])
        lines.append("=" * 10)
        msg = "\n".join(lines) + "\n"
        directory = "var/log/exceptions"
        if not os.path.exists(directory):
            os.makedirs(directory)
        filename = "%s/%s" % (directory, int(time()))
        with open(filename, 'w+') as f:
            f.write(msg)
            # traceback.print_exc(file=f)

        return response

    return logging_view


def view_config(*args, **kwargs):
    """Override pyramid's view_config to log API requests and responses."""

    return pyramid_view_config(*args, decorator=logging_view_decorator,
                               **kwargs)


def es_client(asynchronous=False):
    """Returns an initialized Elasticsearch client."""
    if not asynchronous:
        return Elasticsearch(
            config.ELASTICSEARCH['elastic_host'],
            port=config.ELASTICSEARCH['elastic_port'],
            http_auth=(config.ELASTICSEARCH['elastic_username'],
                       config.ELASTICSEARCH['elastic_password']),
            use_ssl=config.ELASTICSEARCH['elastic_use_ssl'],
            verify_certs=config.ELASTICSEARCH['elastic_verify_certs'],
        )
    else:
        method = 'https' if config.ELASTICSEARCH['elastic_use_ssl'] else 'http'
        from elasticsearch import AsyncElasticsearch
        return AsyncElasticsearch(
            config.ELASTICSEARCH['elastic_host'],
            port=config.ELASTICSEARCH['elastic_port'], method=method,
        )


def get_file(url, filename, update=True):
    """Get file from url and store it to directory relative to src/mist/api

    If update is True, then a download will be attempted even if the file
    already exists.

    This function only raises an exception if the file doesn't exist and cannot
    be fetched.
    """

    path = os.path.join(config.MIST_API_DIR, 'src', 'mist', 'api',
                        filename)
    exists = os.path.exists(path)
    if not exists or update:
        try:
            resp = requests.get(url)
        except Exception as exc:
            err = "Error fetching file '%s' from '%s': %r" % (
                filename, url, exc
            )
            if not exists:
                log.critical(err)
                raise
            log.error(err)
        else:
            data = resp.text.replace('<!--! do not remove -->', '')
            if resp.status_code != 200:
                err = "Bad response fetching file '%s' from '%s': %r" % (
                    filename, url, data
                )
                if not exists:
                    log.critical(err)
                    raise Exception(err)
                log.error(err)
            else:
                atomic_write_file(path, data)
    return path


def mac_sign(kwargs, expires=None, key='', mac_len=0, mac_format='hex'):
    if not kwargs:
        raise ValueError('No message provided to be signed')
    key = key or config.SIGN_KEY
    if not key:
        raise ValueError('No key configured for signing the HMAC')
    if expires:
        kwargs['_expires'] = int(time() + expires)
    parts = ["%s=%s" % (k, kwargs[k]) for k in sorted(kwargs.keys())]
    msg = "&".join(parts)
    hmac = HMAC(key.encode(), msg=msg.encode(), digestmod=SHA256Hash())
    if mac_format == 'b64':
        tag = urlsafe_b64encode(hmac.digest()).rstrip('=')
    elif mac_format == 'bin':
        tag = hmac.digest()
    else:
        tag = hmac.hexdigest()
    if mac_len:
        tag = tag[:mac_len]
    kwargs['_mac'] = tag


def mac_verify(kwargs, key='', mac_len=0, mac_format='hex'):
    if not kwargs:
        raise ValueError('No message provided to be verified')
    key = key or config.SIGN_KEY
    if not key:
        raise ValueError('No key configured for HMAC verification')
    expiration = kwargs.get('_expires', 0)
    mac = kwargs.pop('_mac', '')
    mac_sign(kwargs=kwargs, key=key, mac_len=mac_len, mac_format=mac_format)
    fresh_mac = kwargs.get('_mac', '')
    if not fresh_mac or fresh_mac != mac:
        raise ValueError('Bad HMAC')
    if expiration and int(expiration) < time():
        raise ValueError('HMAC expired')
    for kw in ('_expires', '_mac'):
        if kw in kwargs:
            del kwargs[kw]


def is_resource_missing(obj):
    """Return True if either resource or its parent is missing or has been
    deleted. Note that `obj` is meant to be a subclass of me.Document."""
    try:
        if getattr(obj, 'deleted', None):
            return True
        if getattr(obj, 'missing_since', None):
            return True
        if getattr(obj, 'cloud', None) and obj.cloud.deleted:
            return True
        if getattr(obj, 'zone', None) and obj.zone.missing_since:
            return True
        if getattr(obj, 'network', None) and obj.network.missing_since:
            return True
    except Exception as exc:
        try:
            log.error('Error trying to decide if %s is missing: %r', obj, exc)
        except Exception as exc:
            # This extra try/except statement could help catch DBRef errors,
            # which most likely mean that the resource is indeed missing, as
            # its related object has already been deleted.
            log.error('Error trying to display the canonical repr: %r', exc)
    return False


def subscribe_log_events_raw(callback=None, routing_keys=('#')):
    raise NotImplementedError()  # change email to owner.id etc

    def preparse_event_dec(func):
        def wrapped(msg):
            try:
                # bring extra key-value pairs to top level
                for k, v in list(json.loads(msg.body.pop('extra')).items()):
                    msg.body[k] = v
            except:
                pass
            return func(msg)
        return wrapped

    def echo(msg):
        event = msg.body
        # print msg.delivery_info.get('routing_key'),
        try:
            if 'email' in event and 'type' in event and 'action' in event:
                print(event.pop('email'), event.pop('type'),
                      event.pop('action'))
            err = event.pop('error', False)
            if err:
                print('  error:', err)
            time = event.pop('time')
            if time:
                print('  date:', datetime.datetime.fromtimestamp(time))
            for key, val in list(event.items()):
                print('  %s: %s' % (key, val))
        except:
            print(event)

    if callback is None:
        callback = echo
    callback = preparse_event_dec(callback)
    log.info('Subscribing to log events with routing keys %s', routing_keys)
    mist.api.helpers.amqp_subscribe('events', callback, ex_type='topic',
                                    routing_keys=routing_keys)


def subscribe_log_events(callback=None, email='*', event_type='*', action='*',
                         error='*'):
    raise NotImplementedError()  # change email to owner.id etc
    keys = [str(var).lower().replace('.', '^')
            for var in (email, event_type, action, error)]
    routing_key = '.'.join(keys)
    subscribe_log_events_raw(callback, [routing_key])


# SEC
def filter_resource_ids(auth_context, cloud_id, resource_type, resource_ids):

    if not isinstance(resource_ids, set):
        resource_ids = set(resource_ids)

    if auth_context.is_owner():
        return resource_ids

    # NOTE: We can trust the RBAC Mappings in order to fetch the latest list of
    # machines for the current user, since mongo has been updated by either the
    # Poller or the above `list_machines`.

    try:
        auth_context.check_perm('cloud', 'read', cloud_id)
    except PolicyUnauthorizedError:
        return set()

    allowed_ids = set(auth_context.get_allowed_resources(rtype=resource_type))
    return resource_ids & allowed_ids


def convert_to_timedelta(time_val):
    """
    Receives a time_val param. time_val should be either an integer,
    or a relative delta in the following format:
    '_s', '_m', '_h', '_d', _w, '_mo', for seconds, minutes, hours, days,
    weeks and months respectively. Returns a timedelta object if right param is
    given, else None
    """
    try:
        seconds = int(time_val)
        return timedelta(seconds=seconds)
    except ValueError:
        try:
            num = time_val[:-1]
            if time_val.endswith('s'):
                return timedelta(seconds=int(num))
            elif time_val.endswith('m'):
                return timedelta(minutes=int(num))
            elif time_val.endswith('h'):
                return timedelta(hours=int(num))
            elif time_val.endswith('d'):
                return timedelta(days=int(num))
            elif time_val.endswith('w'):
                return timedelta(days=int(num) * 7)
            elif time_val.endswith('mo'):
                num = int(time_val[:-2])
                return timedelta(days=30 * num)
        except ValueError:
            raise ValueError('Input is expected to be in the format _s, _m,'
                             '_h, _d, _w or _mo where _ is an int or the whole'
                             ' input may be an int representing seconds')
    return None


def convert_to_datetime(time_val):
    """
    Input should  be a string in the format xT where
     x is an int and T is one of s, m, h, d, w, mo
     which stand for
     seconds, minutes, hours, days, weeks, months.
     Eg. '3mo' or '5d' or '342s'

     Return value is datetime.datetime object
    """
    try:
        num = time_val[:-1]
        letter = time_val[-1]
        if letter == 's':
            return dateparser.parse(f'in {int(num)} seconds')
        if letter == 'm':
            return dateparser.parse(f'in {int(num)} minutes')
        if letter == 'h':
            return dateparser.parse(f'in {int(num)} hours')
        if letter == 'd':
            return dateparser.parse(f'in {int(num)} days')
        if letter == 'w':
            return dateparser.parse(f'in {int(num)} weeks')
        if letter == 'o':
            num = time_val[:-2]
            return dateparser.parse(f'in {int(num)} months')
    except ValueError:
        raise ValueError('Input is expected to be in the format '
                         '{number}{time letter} where time letter is one of '
                         's, m, h, d, w, mo. Valid values could be '
                         '5mo or 300s or 2d etc...')


def node_to_dict(node):
    if isinstance(node, str):
        return node
    elif isinstance(node, datetime.datetime):
        return node.isoformat()
    elif not getattr(node, "__dict__"):
        return str(node)
    ret = node.__dict__.copy()
    if ret.get('driver'):
        ret.pop('driver')
    if ret.get('size'):
        ret['size'] = node_to_dict(ret['size'])
    if ret.get('image'):
        ret['image'] = node_to_dict(ret['image'])
    if ret.get('state'):
        ret['state'] = str(ret['state'])
    if 'extra' in ret:
        ret['extra'] = json.loads(json.dumps(
            ret['extra'], default=node_to_dict))
    return ret


def prepare_dereferenced_dict(standard_fields, deref_map, obj, deref, only):
    only_fields = [f for f in only.split(',') if f]
    deref = deref.replace(' ', '')
    if not deref or deref == 'none':
        deref_map = {k: 'id' for k in deref_map.keys()}
    elif deref != 'auto':
        deref_split = [f for f in deref.split(',') if f]
        for f in deref_split:
            if ':' in f:
                k, v = f.split(':')
                deref_map[k] = v
            else:
                deref_map[k] = 'name' if k != 'cloud' else 'title'

    if only_fields:
        deref_map = {
            k: v for k, v in deref_map.items() if k in only_fields}

    ret = {}

    for field in standard_fields:
        if field in only_fields or not only_fields:
            ret[field] = getattr(obj, field)

    for k, v in deref_map.items():
        # If we have a list, dereference its contents
        if isinstance(getattr(obj, k), list):
            if k in ('allowed_images', 'available_sizes', 'available_images'):
                ret[k] = {getattr(item, 'id', ''): getattr(item, v, '')
                          for item in getattr(obj, k)}
            else:
                ret[k] = [getattr(item, v, '') for item in getattr(obj, k)]
        else:
            ref = getattr(obj, k)
            ret[k] = getattr(ref, v, '')
    return ret


def compute_tags(auth_context, tags, request_tags):
    """Merge security tags with user requested tags."""

    tags = tags or {}
    request_tags = request_tags or {}

    security_tags = auth_context.get_security_tags()
    try:
        for mt in request_tags:
            if mt in security_tags:
                raise ForbiddenError(
                    'You may not assign tags included in a Team access policy:'
                    ' `%s`' % mt)
        tags.update(request_tags)
    except ValueError:
        raise BadRequestError('Invalid tags format.'
                              'Expecting a  dictionary of tags')

    return tags


def check_expiration_constraint(expiration, exp_constraint):
    if exp_constraint:
        try:
            from mist.rbac.methods import check_expiration
        except ImportError:
            return

        # FIXME remove this workaround and parse
        # datetime correctly in check_expiration

        # convert notify datetime string to seconds from now
        # as check_expiration expects it in seconds
        notify = expiration.get('notify')
        if notify:
            dt = datetime.datetime.strptime(notify, '%Y-%m-%d %H:%M:%S')
            time_delta = dt - datetime.datetime.now()
            temp_notify = int(time_delta.total_seconds())
            expiration['notify'] = temp_notify

        try:
            check_expiration(expiration, exp_constraint)
        except PolicyUnauthorizedError:
            # TODO if no expiration is passed
            # create a default expiration based on exp_constraint
            raise

        expiration['notify'] = notify


def check_cost_constraint(auth_context, cost_constraint):
    if cost_constraint:
        try:
            from mist.rbac.methods import check_cost
            check_cost(auth_context.org, cost_constraint)
        except ImportError:
            pass


def check_size_constraint(cloud_id, size_constraint, sizes):
    """Filter sizes list based on RBAC permissions"""

    try:
        from mist.rbac.methods import check_size
    except ImportError:
        return sizes

    if not size_constraint:
        return sizes

    permitted_sizes = []
    for size in sizes:
        try:
            check_size(cloud_id, size_constraint, size)
        except PolicyUnauthorizedError:
            continue
        permitted_sizes.append(size)

    return permitted_sizes


def bucket_to_dict(node, bucket_id):
    if isinstance(node, str):
        return node
    elif isinstance(node, datetime.datetime):
        return node.isoformat()
    elif not getattr(node, "__dict__"):
        return str(node)
    ret = node.__dict__
    if ret.get('driver'):
        ret.pop('driver')
    if ret.get('container'):
        ret['container'] = {
            'name': ret['container'].name,
            'id': bucket_id
        }
    if ret.get('state'):
        ret['state'] = str(ret['state'])
    if 'extra' in ret:
        ret['extra'] = json.loads(json.dumps(
            ret['extra'], default=bucket_to_dict))
    return ret


def docker_connect():
    try:
        if config.DOCKER_TLS_KEY and config.DOCKER_TLS_CERT:
            # tls auth, needs to pass the key and cert as files
            key_temp_file = tempfile.NamedTemporaryFile(delete=False)
            key_temp_file.write(config.DOCKER_TLS_KEY.encode())
            key_temp_file.close()
            cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            cert_temp_file.write(config.DOCKER_TLS_CERT.encode())
            cert_temp_file.close()
            if config.DOCKER_TLS_CA:
                # docker started with tlsverify
                ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
                ca_cert_temp_file.write(config.DOCKER_TLS_CA.encode())
                ca_cert_temp_file.close()
            driver = get_container_driver(Container_Provider.DOCKER)
            conn = driver(host=config.DOCKER_IP,
                          port=config.DOCKER_PORT,
                          key_file=key_temp_file.name,
                          cert_file=cert_temp_file.name,
                          ca_cert=ca_cert_temp_file.name)
        else:
            driver = get_container_driver(Container_Provider.DOCKER)
            conn = driver(host=config.DOCKER_IP, port=config.DOCKER_PORT)
    except Exception as err:
        raise WorkflowExecutionError(str(err))

    return conn


def docker_run(name, image_id, env=None, command=None,
               entrypoint=None):
    conn = docker_connect()
    image = ContainerImage(id=image_id, name=image_id,
                           extra={}, driver=conn, path=None,
                           version=None)
    try:
        container = conn.deploy_container(name, image,
                                          environment=env,
                                          command=command,
                                          tty=True,
                                          entrypoint=entrypoint,)
    except DockerException:
        conn.install_image(image_id)
        container = conn.deploy_container(name, image,
                                          environment=env,
                                          command=command,
                                          tty=True,
                                          entrypoint=entrypoint,)
    return container


def search_parser(search):
    """
    Parse search string passed to `list_resources` into a list of strings.

    Supports key:value, key=value, key:(value with spaces), key:"exact value",
    AND/OR operators and a single 'stray' string that will be set to
    id or name.

    A value containing spaces should be enclosed in
    parentheses or double quotes for exact match.

    Note: implicit id or name cannot be the last value
    unless it's the only value in search.
    """

    pattern = (r'([a-zA-Z0-9_]+)(:|=|<=|>=|!=|<|>)'  # capture key and mathematical operator  # noqa
               r'(\(.+?\)|".+?"|\S+)'  # capture value or value with spaces enclosed in "", ()  # noqa
               r'|(OR|AND|[^:=<>!]+?'  # capture OR/AND/'stray' string  # noqa
               r'(?= [a-zA-Z0-9_]+?[:=<>!]| AND | OR |$)'  # until one of key+mathematical operator, OR , AND is encountered  # noqa
               r'|^[^:=<>!]+$)')  # capture simple 'stray' string

    matched = re.findall(pattern, search)

    items = [''.join(val.strip(' ()') for val in tup if val)
             for tup in matched]
    return items


def startsandendswith(main_str, char):
    return main_str.startswith(char) and main_str.endswith(char)


def generate_secure_password(min_chars=12, max_chars=21):
    """Generate a twelve to twenty characters password with at least
    one lowercase character, at least one uppercase character
    and at least three digits.

    """
    alphabet = string.ascii_letters + string.digits
    length = secrets.choice(range(min_chars, max_chars))
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
                sum(c.isdigit() for c in password) >= 3):
            break

    return password


def validate_password(password):
    """A simple password validator
    """
    length = len(password) > 7
    lower_case = any(c.islower() for c in password)
    upper_case = any(c.isupper() for c in password)
    digit = any(c.isdigit() for c in password)

    return length and lower_case and upper_case and digit


def get_docker_image_sha(name):
    """Get docker image sha hash without pulling the image

    Parameters:
        name(str): The image name e.g "mist/mistio:latest". The  image tag
                   is required.

    Returns:
        A string containing the image sha256 hash or None if the image hash
        is not found.
    """
    # See the following references:
    # https://stackoverflow.com/questions/41808763/how-to-determine-the-docker-image-id-for-a-tag-via-docker-hub-api/41830007#41830007  # noqa
    # https://docs.docker.com/registry/spec/auth/jwt/

    repo_name, tag = name.split(':')

    # Official images e.g "python"  name is library/python
    if '/' not in repo_name:
        repo_name = f'library/{repo_name}'

    auth_url = f'https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo_name}:pull'  # noqa
    response = requests.get(auth_url)
    token = response.json()['token']

    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.docker.distribution.manifest.v2+json',  # noqa
    }
    response = requests.get(
        f'https://index.docker.io/v2/{repo_name}/manifests/{tag}',
        headers=headers)

    return response.headers.get('docker-content-digest')


def pull_docker_image(cloud_id, image_name):
    """Pull the docker image specified.

    Parameters:
        cloud_Id(str): The docker cloud to pull the image for.

        image_name(str): The image name e.g "mist/mistio:latest". If the image
                         tag is not specified, all available images will be
                         pulled

    Returns:
        A ContainerImage object
    """
    from mist.api.clouds.models import DockerCloud
    from mist.api.poller.models import ListImagesPollingSchedule

    cloud = DockerCloud.objects.get(id=cloud_id)

    image = cloud.ctl.compute.connection.install_image(image_name)

    log.info(
        'Accelerating default image polling interval for cloud: %s', cloud_id)

    schedule = ListImagesPollingSchedule.objects.get(cloud=cloud)
    schedule.add_interval(20, ttl=60)
    schedule.save()

    return image


def apply_promql_query_rbac(auth_context, tags, search, query):
    try:
        from mist.rbac.methods import apply_promql_rbac
        return apply_promql_rbac(auth_context, tags, search, query)
    except ImportError:
        return query


def get_victoriametrics_uri(org):
    return config.VICTORIAMETRICS_URI.replace(
        "<org_id>", str(int(org.id[:8], 16)))


def get_victoriametrics_write_uri(org):
    return config.VICTORIAMETRICS_WRITE_URI.replace(
        "<org_id>", str(int(org.id[:8], 16)))


def requests_retry_session(retries=3,
                           backoff_factor=0.3,
                           status_forcelist=(500, 502, 504),
                           session=None,
                           ):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        method_whitelist=frozenset(['GET', 'POST'])
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def get_version_string():
    """Convert VERSION dictionary to a string for tracking releases in Sentry

    """
    return (f"{config.VERSION['repo']}:{config.VERSION['name']}@"
            f"{config.VERSION['sha']}, modified:{config.VERSION['modified']}")


def select_plan(valid_plans, optimize, auth_context):
    """Helper function for api-v2 create machine endpoint.

    Pick the most appropriate plan from valid_plans based on
    the optimize parameter.

    Currently the following optimize values are supported:
        cost
        performance
    """
    if optimize == 'cost':
        return min(valid_plans, key=operator.itemgetter('cost'))

    if optimize == 'performance':
        from mist.api.tag.models import Tag
        for plan in valid_plans:
            tag = Tag.objects(resource_id=plan['cloud']['id'],
                              resource_type='cloud',
                              owner=auth_context.owner,
                              key='performance',
                              ).first()
            if tag and tag.value:
                try:
                    plan['performance'] = float(tag.value)
                except ValueError:
                    # custom metric case
                    from mist.api.auth.models import SessionToken
                    from mist.api.portal.models import Portal
                    if isinstance(auth_context.token, SessionToken):
                        headers = {
                            'Authorization': 'internal %s %s' % (
                                Portal.get_singleton().internal_api_key,
                                auth_context.token.token)}
                    else:
                        headers = {
                            'Authorization': auth_context.token.token,
                        }
                    params = f'query={tag.value}[10m]&time=0s'
                    url = f'{config.INTERNAL_API_V2_URL}/api/v2/datapoints'
                    response = requests.get(url,
                                            headers=headers,
                                            params=params)
                    try:
                        response.raise_for_status()
                    except requests.HTTPError as exc:
                        log.error(
                            ('Failed to fetch system load for cloud: %s '
                             'with exception: %s'),
                            plan['cloud']['id'], repr(exc))
                        plan['performance'] = float('inf')
                        continue

                    body = response.json()
                    try:
                        plan['performance'] = float(
                            body['data']['data']['result'][0]['values'][-1][1])
                    except (KeyError, IndexError):
                        log.error(
                            'Failed to parse system load metric for cloud: %s',
                            plan['cloud']['id'])
                        plan['performance'] = float('inf')
            else:
                plan['performance'] = float('inf')

        plan = min(valid_plans, key=operator.itemgetter('performance'))
        plan.pop('performance')
        return plan


def get_boto_driver(service, key, secret, region):
    import boto3
    return boto3.client(service,
                        aws_access_key_id=key,
                        aws_secret_access_key=secret,
                        region_name=region,
                        )


def get_aws_tags(resource_type: str,
                 cluster_name: str,
                 resource_group_tagging: bool = False):
    """Return the tags that should be applied to a CloudFormation stack
    that manages the given cluster or cluster nodegroup.
    These tags will determine if the given cluster/nodegroup is managed
    by a CloudFormation stack created by Mist.
    """
    tags = {
        'mist.io/cluster-name': cluster_name,
        'mist.io/managed': '1',
        'mist.io/type': resource_type,

    }
    aws_tags = []
    # Convert tags to the way AWS API expects them
    # The Resource Groups Tagging API accepts multiple Tag values for a
    # key.
    for key, value in tags.items():
        if resource_group_tagging:
            aws_tags.append({
                'Key': key,
                'Values': [value],
            })
        else:
            aws_tags.append({
                'Key': key,
                'Value': value,
            })
    return aws_tags


def create_helm_command(repo_url, release_name, chart_name, host, port, token,
                        ca_cert_path=f"{config.HELM_DOCKER_IMAGE_WORKDIR}/ca_cert",  # noqa
                        namespace=None,
                        values_file_path=None,
                        timeout="10m",
                        version=None,
                        ):
    """Create the helm command that will be passed as CMD/ENTRYPOINT
    to the container that will install the helm chart.
    """
    if not (host.startswith("https://") or host.startswith("http://")):
        host = f"https://{host}"

    helm_install_command = (f'helm install {release_name} {chart_name} --repo {repo_url} --atomic'  # noqa
                            f' --kube-apiserver "{host}:{port}" --kube-token "{token}"'  # noqa
                            f' --kube-ca-file {ca_cert_path}')

    if namespace:
        helm_install_command += f" --create-namespace --namespace {namespace}"
    if values_file_path:
        helm_install_command += f" -f {values_file_path}"
    if timeout:
        helm_install_command += f" --timeout {timeout}"
    if version:
        helm_install_command += f' --version "{version}"'

    # The docker image used defines container entrypoint
    return helm_install_command


def extract_selector_type(**kwargs):
    error_count = 0
    for selector in kwargs.get('selectors', []):
        if selector['type'] not in ['machines', 'volumes',
                                    'networks', 'clusters',
                                    'tags']:
            error_count += 1
        if 'ids' in selector and selector['ids'] is not None:
            selector_type = selector['type'].rstrip('s')
            break
        if 'include' in selector and selector['include'] is not None:
            selector_type = 'machine'
            break
    if error_count == len(kwargs.get('selectors', [])):
        raise BadRequestError('selector_type')
    return selector_type


class RabbitMQStreamConsumer:
    def __init__(self, job_id):
        self.stream_name = job_id
        self.buffer = ""
        self.exit_code = 1

    def on_message(self, msg: AMQPMessage):
        message = next(msg.data).decode('utf-8')
        if message.startswith('retval:'):
            self.exit_code = int(message.replace('retval:', '', 1))
            import asyncio
            asyncio.create_task(self.consumer.close())
        else:
            self.buffer = self.buffer + message

    @async_to_sync
    async def consume(self):
        self.consumer = Consumer(
            host=os.getenv("RABBITMQ_HOST", 'rabbitmq'),
            port=5552,
            vhost='/',
            username=os.getenv("RABBITMQ_USERNAME", 'guest'),
            password=os.getenv("RABBITMQ_PASSWORD", 'guest'),
        )

        loop = asyncio.get_event_loop()
        await self.consumer.start()
        sleep_time = 0
        SLEEP_TIMEOUT = 30
        SLEEP_INTERVAL = 3
        while sleep_time < SLEEP_TIMEOUT:

            try:
                await self.consumer.subscribe(
                    self.stream_name, self.on_message, decoder=amqp_decoder)
                break
            except StreamDoesNotExist:
                sleep(SLEEP_INTERVAL)
                sleep_time += SLEEP_INTERVAL

        await self.consumer.run()
        return self.exit_code, self.buffer
