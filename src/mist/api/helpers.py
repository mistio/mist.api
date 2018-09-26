"""Helper functions used in views and WSGI initialization

This file is imported in many places. Importing other mist modules into this
file causes circular import errors.

Try to not put anything in here that depends on other mist code, with the
exception of mist.api.config.

In general, this file should only contain generic helper functions that one
could easily use in some other unrelated project.

"""

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
import urlparse
import datetime
import tempfile
import traceback
import jsonpickle
import subprocess

from time import time, strftime, sleep

from base64 import urlsafe_b64encode

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from contextlib import contextmanager
from email.utils import formatdate, make_msgid
from mongoengine import DoesNotExist

from pyramid.view import view_config as pyramid_view_config
from pyramid.httpexceptions import HTTPError

import iso8601
import netaddr
import requests

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Hash.HMAC import HMAC
from Crypto.Random import get_random_bytes

import kombu
import kombu.pools
from amqp.exceptions import NotFound as AmqpNotFound

from distutils.version import LooseVersion

from elasticsearch import Elasticsearch
from elasticsearch_tornado import EsClient

import mist.api.users.models
from mist.api.auth.models import ApiToken, datetime_to_str

from mist.api.exceptions import MistError, NotFoundError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api import config

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
    f.write(content)
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

    if os not in vulnerables.keys():
        return None

    if os_version not in vulnerables[os].keys():
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
    try:
        amqp_publish(_amqp_owner_exchange(owner), routing_key, data)
    except AmqpNotFound:
        return False
    except Exception:
        return False
    return True


def amqp_subscribe_user(owner, queue, callback):
    amqp_subscribe(_amqp_owner_exchange(owner), callback, queue)


def amqp_owner_listening(owner):
    exchange = kombu.Exchange(_amqp_owner_exchange(owner), type='fanout')
    with kombu.pools.connections[kombu.Connection(config.BROKER_URL)].acquire(
            block=True, timeout=10) as connection:
        with connection.channel() as channel:
            try:
                exchange(connection.channel).declare(passive=True)
            except AmqpNotFound:
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


def check_host(host, allow_localhost=config.ALLOW_CONNECT_LOCALHOST):
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
        '0.0.0.0/8': "used for broadcast messages to the current network",
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

    if not allow_localhost:
        forbidden_subnets['127.0.0.0/8'] = ("used for loopback addresses "
                                            "to the local host")

    cidr = netaddr.smallest_matching_cidr(ipaddr, forbidden_subnets.keys())
    if cidr:
        raise MistError("%s is not allowed. It belongs to '%s' "
                        "which is %s." % (msg, cidr,
                                          forbidden_subnets[str(cidr)]))


def transform_key_machine_associations(machines, key):
    key_associations = []
    for machine in machines:
        for key_assoc in machine.key_associations:
            if key_assoc.keypair == key:
                key_associations.append([machine.cloud.id,
                                        machine.machine_id,
                                        key_assoc.last_used,
                                        key_assoc.ssh_user,
                                        key_assoc.sudo,
                                        key_assoc.port])
    return key_associations


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
    elif isinstance(timestamp, basestring):
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
    _chars = string.letters + string.digits
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
    return (request.get('HTTP_X_REAL_IP') or
            request.get('HTTP_X_FORWARDED_FOR') or
            request.get('REMOTE_ADDR') or
            '0.0.0.0')


def send_email(subject, body, recipients, sender=None, bcc=None, attempts=3,
               html_body=None):
    """Send email.

    subject: email's subject
    body: email's body
    recipients: an email address as a string or an iterable of email addresses
    sender: the email address of the sender. default value taken from config

    """
    if isinstance(subject, str):
        subject = subject.decode('utf-8', 'ignore')

    if not sender:
        sender = config.EMAIL_FROM
    if isinstance(recipients, basestring):
        recipients = [recipients]

    if isinstance(body, str):
        body = body.decode('utf8')

    if html_body:
        msg = MIMEMultipart('alternative')
    else:
        msg = MIMEText(body.encode('utf-8', 'ignore'), 'plain')

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
            server.quit()
            return True
        except smtplib.SMTPException as exc:
            if attempt == attempts - 1:
                log.error("Could not send email after %d retries! Error: %r",
                          attempts, exc)
                return False
            else:
                log.warn("Could not send email! Error: %r", exc)
                log.warn("Retrying in 5 seconds...")
                sleep(5)


rtype_to_classpath = {
    'cloud': 'mist.api.clouds.models.Cloud',
    'clouds': 'mist.api.clouds.models.Cloud',
    'machine': 'mist.api.machines.models.Machine',
    'machines': 'mist.api.machines.models.Machine',
    'zone': 'mist.api.dns.models.Zone',
    'record': 'mist.api.dns.models.Record',
    'script': 'mist.api.scripts.models.Script',
    'key': 'mist.api.keys.models.Key',
    'schedule': 'mist.api.schedules.models.Schedule',
    'network': 'mist.api.networks.models.Network',
    'subnet': 'mist.api.networks.models.Subnet',
    'volume': 'mist.api.volumes.models.Volume'
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
    """Return a timestamp as a nicely formated datetime string."""
    try:
        date = datetime.datetime.fromtimestamp(timestamp)
        date_string = date.strftime("%d/%m/%Y %H:%M %Z")
        return date_string
    except:
        return None


def iso_to_seconds(iso):
    """Attempt to transform a time representation into seconds."""
    return get_datetime(iso).strftime('%s')


def encrypt(plaintext, key=config.SECRET, key_salt='', no_iv=False):
    """Encrypt shit the right way"""

    # sanitize inputs
    key = SHA256.new(key + key_salt).digest()
    if len(key) not in AES.key_size:
        raise Exception()
    if isinstance(plaintext, unicode):
        plaintext = plaintext.encode('utf-8')

    # pad plaintext using PKCS7 padding scheme
    padlen = AES.block_size - len(plaintext) % AES.block_size
    plaintext += chr(padlen) * padlen

    # generate random initialization vector using CSPRNG
    iv = '\0' * AES.block_size if no_iv else get_random_bytes(AES.block_size)

    # encrypt using AES in CFB mode
    ciphertext = AES.new(key, AES.MODE_CFB, iv).encrypt(plaintext)

    # prepend iv to ciphertext
    if not no_iv:
        ciphertext = iv + ciphertext

    # return ciphertext in hex encoding
    return ciphertext.encode('hex')


def decrypt(ciphertext, key=config.SECRET, key_salt='', no_iv=False):
    """Decrypt shit the right way"""

    # sanitize inputs
    key = SHA256.new(key + key_salt).digest()
    if len(key) not in AES.key_size:
        raise Exception()
    if len(ciphertext) % AES.block_size:
        raise Exception()
    try:
        ciphertext = ciphertext.decode('hex')
    except TypeError:
        log.warning("Ciphertext wasn't given as a hexadecimal string.")

    # split initialization vector and ciphertext
    if no_iv:
        iv = '\0' * AES.block_size
    else:
        iv = ciphertext[:AES.block_size]
        ciphertext = ciphertext[AES.block_size:]

    # decrypt ciphertext using AES in CFB mode
    plaintext = AES.new(key, AES.MODE_CFB, iv).decrypt(ciphertext)

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
            request.real_view_name = func.func_name

        # check if exception occurred
        try:
            response = func(context, request)
        except HTTPError as e:
            if request.path_info.startswith('/social_auth/complete'):
                log.info("There was a bad error during SSO connection: %s, "
                         "and request was %s" % (repr(e), request.__dict__))
            raise
        # check if exception occured
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
            log_dict['owner_id'] = auth_context.owner.id
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
                    'zone', 'record', 'network', 'subnet', 'volume']:
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
            log_dict['machine_id'] = request.environ.get('machine_id')

        machine_uuid = (request.matchdict.get('machine_uuid') or
                        params.get('machine_uuid') or
                        request.environ.get('machine_uuid'))
        if machine_uuid and not log_dict.get('machine_uuid'):
            log_dict['machine_uuid'] = machine_uuid

        # Attempt to hide passwords, API keys, certificates, etc.
        for key in ('priv', 'password', 'new_password', 'apikey', 'apisecret',
                    'cert_file', 'key_file'):
            if params.get(key):
                params[key] = '***CENSORED***'

        # Hide sensitive cloud credentials.
        if log_dict['action'] == 'add_cloud':
            provider = params.get('provider')
            censor = {'vcloud': 'password',
                      'ec2': 'api_secret',
                      'rackspace': 'api_key',
                      'nephoscale': 'password',
                      'softlayer': 'api_key',
                      'onapp': 'api_key',
                      'digitalocean': 'token',
                      'gce': 'private_key',
                      'azure': 'certificate',
                      'linode': 'api_key',
                      'docker': 'auth_password',
                      'hp': 'password',
                      'openstack': 'password'}.get(provider)
            if censor and censor in params:
                params[censor] = '***CENSORED***'

        # Hide password from Git URL, if exists.
        if log_dict.get('action', '') == 'add_template':
            if params.get('location_type') == 'github':
                git_url = params.get('template_github', '')
                git_password = urlparse.urlparse(git_url).password
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
            if 'cloud' in bdict and 'cloud_id' not in log_dict:
                log_dict['cloud_id'] = bdict['cloud']
            if 'machine' in bdict and 'machine_id' not in log_dict:
                log_dict['machine_id'] = bdict['machine']
            if 'machine_uuid' in bdict and 'machine_id' not in log_dict:
                log_dict['machine_id'] = bdict['machine']
            # Match resource type based on the action performed.
            for rtype in ['cloud', 'machine', 'key', 'script', 'tunnel',
                          'stack', 'template', 'schedule', 'volume']:
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
        log.info("Bad exception occured, logging to rabbitmq")
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
        log.info("Bad exception occured, logging to file")
        lines = []
        lines.append("Exception: %s" % log_dict.pop('_exc'))
        lines.append("Exception type: %s" % log_dict.pop('_exc_type'))
        lines.append("Time: %s" % strftime("%Y-%m-%d %H:%M %Z"))
        lines += (
            ["%s: %s" % (key, value) for key, value in log_dict.items()
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


class AsyncElasticsearch(EsClient):
    """Tornado-compatible Elasticsearch client."""

    def mk_req(self, url, **kwargs):
        """Update kwargs with authentication credentials."""
        kwargs.update({
            'auth_username': config.ELASTICSEARCH['elastic_username'],
            'auth_password': config.ELASTICSEARCH['elastic_password'],
            'validate_cert': config.ELASTICSEARCH['elastic_verify_certs'],
            'ca_certs': None,

        })
        for param in ('connect_timeout', 'request_timeout'):
            if param not in kwargs:
                kwargs[param] = 30.0  # Increase default timeout by 10 sec.
        return super(AsyncElasticsearch, self).mk_req(url, **kwargs)


def es_client(async=False):
    """Returns an initialized Elasticsearch client."""
    if not async:
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
            data = resp.text
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


def mac_sign(kwargs=None, expires=None, key='', mac_len=0, mac_format='hex'):
    key = key or config.SIGN_KEY
    if not key:
        raise Exception('No key configured for signing the HMAC')
    if not kwargs:
        raise Exception('No message provided to be signed')
    if expires:
        kwargs['_expires'] = int(time() + expires)
    parts = ["%s=%s" % (k, kwargs[k]) for k in sorted(kwargs.keys())]
    msg = "&".join(parts)
    hmac = HMAC(str(key), msg=str(msg), digestmod=SHA256Hash())
    if mac_format == 'b64':
        tag = urlsafe_b64encode(hmac.digest()).rstrip('=')
    elif mac_format == 'bin':
        tag = hmac.digest()
    else:
        tag = hmac.hexdigest()
    if mac_len:
        tag = tag[:mac_len]
    kwargs['_mac'] = tag


def mac_verify(kwargs=None, key='', mac_len=0, mac_format='hex'):
    key = key or config.SIGN_KEY
    if not key:
        raise Exception('No key configured for HMAC verification')
    if not kwargs:
        raise Exception('No message provided to be verified')
    expiration = kwargs.get('_expires', 0)
    mac = kwargs.pop('_mac', '')
    mac_sign(kwargs=kwargs, key=key, mac_len=mac_len, mac_format=mac_format)
    fresh_mac = kwargs.get('_mac', '')
    if not fresh_mac or fresh_mac != mac:
        raise Exception('Bad HMAC')
    if expiration and expiration < time():
        raise Exception('HMAC expired')
    for kw in ('_expires', '_mac'):
        if kw in kwargs:
            del kwargs[kw]


def maybe_submit_cloud_task(cloud, task_name):
    """Decide whether a task should be submitted to celery

    This method helps us prevent submitting new celery tasks, which are
    guaranteed to return/exit immediately without performing any actual
    actions.

    For instance, such cases include async tasks for listing DNS zones
    for clouds that have no DNS support or DNS is temporarily disabled.

    Note that this is just a helper method used to make an initial decision.

    The `cloud` argument must be a `mist.api.clouds.models.Cloud` mongoengine
    objects and `task_name` must be the name/identifier of the corresponding
    celery task.

    """
    if task_name == 'list_zones':
        if not (hasattr(cloud.ctl, 'dns') and cloud.dns_enabled):
            return False
    if task_name == 'list_networks':
        if not hasattr(cloud.ctl, 'network'):
            return False
    if task_name == 'list_projects':
        if cloud.ctl.provider != 'packet':
            return False
    if task_name in ('list_resource_groups', 'list_storage_accounts', ):
        if cloud.ctl.provider != 'azure_arm':
            return False
    return True


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
                for key, val in json.loads(msg.body.pop('extra')).items():
                    msg.body[key] = val
            except:
                pass
            return func(msg)
        return wrapped

    def echo(msg):
        event = msg.body
        # print msg.delivery_info.get('routing_key'),
        try:
            if 'email' in event and 'type' in event and 'action' in event:
                print event.pop('email'), event.pop('type'), \
                    event.pop('action')
            err = event.pop('error', False)
            if err:
                print '  error:', err
            time = event.pop('time')
            if time:
                print '  date:', datetime.datetime.fromtimestamp(time)
            for key, val in event.items():
                print '  %s: %s' % (key, val)
        except:
            print event

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
