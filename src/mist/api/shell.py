"""mist.api.shell

This module contains everything that is need to communicate with machines via
SSH.

"""
import paramiko
import websocket
import socket
import _thread
import ssl
import tempfile
import logging
import base64
import json

from time import sleep
from io import StringIO

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine, KeyMachineAssociation
from mist.api.keys.models import Key, SignedSSHKey

from mist.api.exceptions import MachineUnauthorizedError
from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import ServiceUnavailableError

from mist.api.helpers import trigger_session_update
from mist.api.logs.methods import get_story

from mist.api import config

if config.HAS_VPN:
    from mist.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat


logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)


class ParamikoShell(object):
    """sHell

    This class takes care of all SSH related issues. It initiates a connection
    to a given host and can send commands whose output can be treated in
    different ways. It can search a user's data and autoconfigure itself for
    a given machine by finding the right private key and username. Under the
    hood it uses paramiko.

    Use it like:
    shell = Shell('localhost', username='root', password='123')
    print shell.command('uptime')

    Or:
    shell = Shell('localhost')
    shell.autoconfigure(user, cloud_id, machine_id)
    for line in shell.command_stream('ps -fe'):
    print line

    """

    def __init__(self, host, username=None, key=None, password=None,
                 cert_file=None, port=22):
        """Initialize a Shell instance

        Initializes a Shell instance for host. If username is provided, then
        it tries to actually initiate the connection, by calling connect().
        Check out the docstring of connect().

        """

        if not host:
            raise RequiredParameterMissingError('host not given')
        self.host = host
        self.sudo = False

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # if username provided, try to connect
        if username:
            self.connect(username, key, password, cert_file, port)

    def connect(self, username, key=None, password=None, cert_file=None,
                port=22):
        """Initialize an SSH connection.

        Tries to connect and configure self. If only password is provided, it
        will be used for authentication. If key is provided, it is treated as
        and OpenSSH private RSA key and used for authentication. If both key
        and password are provided, password is used as a passphrase to unlock
        the private key.

        Raises MachineUnauthorizedError if it fails to connect.

        """

        if not key and not password:
            raise RequiredParameterMissingError("neither key nor password "
                                                "provided.")

        if key:
            private = key.private.value
            if isinstance(key, SignedSSHKey) and cert_file:
                # signed ssh key, use RSACert
                rsa_key = paramiko.RSACert(privkey_file_obj=StringIO(private),
                                           cert_file_obj=StringIO(cert_file))
            else:
                rsa_key = paramiko.RSAKey.from_private_key(StringIO(private))
        else:
            rsa_key = None

        attempts = 3
        while attempts:
            attempts -= 1
            try:
                self.ssh.connect(
                    self.host,
                    port=port,
                    username=username,
                    password=password,
                    pkey=rsa_key,
                    allow_agent=False,
                    look_for_keys=False,
                    timeout=10
                )
                break
            except paramiko.AuthenticationException as exc:
                log.error("ssh exception %r", exc)
                raise MachineUnauthorizedError("Couldn't connect to "
                                               "%s@%s:%s. %s"
                                               % (username, self.host,
                                                  port, exc))
            except socket.error as exc:
                log.error("Got ssh error: %r", exc)
                if not attempts:
                    raise ServiceUnavailableError("SSH timed-out repeatedly.")
            except Exception as exc:
                log.error("ssh exception %r", exc)
                # don't fail if SSHException or other paramiko exception,
                # eg related to network, but keep until all attempts are made
                if not attempts:
                    raise ServiceUnavailableError(repr(exc))

    def disconnect(self):
        """Close the SSH connection."""
        try:
            log.info("Closing ssh connection to %s", self.host)
            self.ssh.close()
        except:
            pass

    def check_sudo(self):
        """Checks if sudo is installed.

        In case it is self.sudo = True, else self.sudo = False

        """
        # FIXME
        stdout, stderr, channel = self.command("which sudo", pty=False)
        if not stderr:
            self.sudo = True
            return True

    def _command(self, cmd, pty=True):
        """Helper method used by command and stream_command."""
        channel = self.ssh.get_transport().open_session()
        channel.settimeout(10800)
        stdout = channel.makefile()
        stderr = channel.makefile_stderr()
        if pty:
            # this combines the stdout and stderr streams as if in a pty
            # if enabled both streams are combined in stdout and stderr file
            # descriptor isn't used
            channel.get_pty()
        # command starts being executed in the background
        channel.exec_command(cmd)
        return stdout, stderr, channel

    def command(self, cmd, pty=True):
        """Run command and return output.

        If pty is True, then it returns a string object that contains the
        combined streams of stdout and stderr, like they would appear in a pty.

        If pty is False, then it returns a two string tuple, consisting of
        stdout and stderr.

        """
        log.info("running command: '%s'", cmd)
        stdout, stderr, channel = self._command(cmd, pty)
        line = stdout.readline()
        out = ''
        while line:
            out += line
            line = stdout.readline()

        if pty:
            retval = channel.recv_exit_status()
            return retval, out
        else:
            line = stderr.readline()
            err = ''
            while line:
                err += line
                line = stderr.readline()
            retval = channel.recv_exit_status()

            return retval, out, err

    def command_stream(self, cmd):
        """Run command and stream output line by line.

        This function is a generator that returns the commands output line
        by line. Use like: for line in command_stream(cmd): print line.

        """
        log.info("running command: '%s'", cmd)
        stdout, stderr, channel = self._command(cmd)
        line = stdout.readline()
        while line:
            yield line
            line = stdout.readline()

    def autoconfigure(self, owner, cloud_id, machine_id,
                      key_id=None, username=None, password=None, port=22):
        """Autoconfigure SSH client.

        This will do its best effort to find a suitable key and username
        and will try to connect. If it fails it raises
        MachineUnauthorizedError, otherwise it initializes self and returns a
        (key_id, ssh_user) tuple. If connection succeeds, it updates the
        association information in the key with the current timestamp and the
        username used to connect.

        """
        log.info("autoconfiguring Shell for machine %s:%s",
                 cloud_id, machine_id)

        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        machine = Machine.objects.get(cloud=cloud, id=machine_id)
        key_associations = KeyMachineAssociation.objects(machine=machine)
        log.info('Got cloud & machine: %d key associations' % len(
            key_associations))
        if key_id:
            keys = [Key.objects.get(owner=owner, id=key_id, deleted=None)]
            log.info('Got key')
        else:
            keys = [association.key
                    for association in key_associations
                    if isinstance(association.key, Key)]
            log.info('Got keys %d' % len(keys))
        if username:
            users = [username]
        else:
            users = list(set([association.ssh_user
                              for association in key_associations
                              if association.ssh_user]))
        log.info('Got users:{}'.format(users))
        if not users:
            users = ['root', 'ubuntu', 'ec2-user', 'user', 'azureuser',
                     'core', 'centos', 'cloud-user', 'fedora']
        if port != 22:
            ports = [port]
        else:
            ports = list(set([key_assoc.port
                              for key_assoc in key_associations]))
        if 22 not in ports:
            ports.append(22)
        log.info('Got ports:{}'.format(ports))
        # store the original destination IP to prevent rewriting it when NATing
        ssh_host = self.host
        for key in keys:
            for ssh_user in users:
                for port in ports:
                    try:
                        # store the original ssh port in case of NAT
                        # by the OpenVPN server
                        ssh_port = port
                        self.host, port = dnat(owner, ssh_host, port)
                        log.info("ssh -i %s %s@%s:%s",
                                 key.name, ssh_user, self.host, port)
                        cert_file = ''
                        if isinstance(key, SignedSSHKey):
                            cert_file = key.certificate

                        self.connect(username=ssh_user,
                                     key=key,
                                     password=password,
                                     cert_file=cert_file,
                                     port=port)
                    except MachineUnauthorizedError:
                        continue

                    retval, resp = self.command('uptime')
                    new_ssh_user = None
                    if 'Please login as the user ' in resp:
                        new_ssh_user = resp.split()[5].strip('"')
                    elif 'Please login as the' in resp:
                        # for EC2 Amazon Linux machines, usually with ec2-user
                        new_ssh_user = resp.split()[4].strip('"')
                    if new_ssh_user:
                        log.info("retrying as %s", new_ssh_user)
                        try:
                            self.disconnect()
                            cert_file = ''
                            if isinstance(key, SignedSSHKey):
                                cert_file = key.certificate
                            self.connect(username=new_ssh_user,
                                         key=key,
                                         password=password,
                                         cert_file=cert_file,
                                         port=port)
                            ssh_user = new_ssh_user
                        except MachineUnauthorizedError:
                            continue
                    # we managed to connect successfully, return
                    # but first update key
                    trigger_session_update_flag = False
                    for key_assoc in KeyMachineAssociation.objects(
                            machine=machine):
                        if key_assoc.key == key:
                            if key_assoc.ssh_user != ssh_user:
                                key_assoc.ssh_user = ssh_user
                                trigger_session_update_flag = True
                                key_assoc.save()
                            break
                    else:
                        trigger_session_update_flag = True
                        # in case of a private host do NOT update the key
                        # associations with the port allocated by the OpenVPN
                        # server, instead use the original ssh_port
                        key_assoc = KeyMachineAssociation(
                            key=key, machine=machine, ssh_user=ssh_user,
                            port=ssh_port, sudo=self.check_sudo())
                        key_assoc.save()
                    machine.save()
                    if trigger_session_update_flag:
                        trigger_session_update(owner.id, ['keys'])
                    return key.name, ssh_user

        raise MachineUnauthorizedError("%s:%s" % (cloud_id, machine_id))

    def __del__(self):
        self.disconnect()


class WebSocketWrapper(object):
    """
    WebSocketWrapper class that wraps websocket.WebSocket
    """

    @staticmethod
    def ssl_credentials(cloud=None):
        if cloud and cloud.ca_cert_file:
            _ca_cert = cloud.ca_cert_file
            tempca_cert = tempfile.NamedTemporaryFile(delete=False)
            with open(tempca_cert.name, 'w') as f:
                f.write(_ca_cert)
        else:
            tempca_cert = None
        if cloud and cloud.key_file and cloud.cert_file:
            _key, _cert = cloud.key_file, cloud.cert_file
            tempkey = tempfile.NamedTemporaryFile(delete=False)
            with open(tempkey.name, 'w') as f:
                f.write(_key)
            tempcert = tempfile.NamedTemporaryFile(delete=False)
            with open(tempcert.name, 'w') as f:
                f.write(_cert)
        else:
            tempkey = None
            tempcert = None
        return tempkey, tempcert, tempca_cert

    def __init__(self):
        self.ws = websocket.WebSocket()
        self.protocol = "ws"
        self.uri = ""
        self.sslopt = {}
        self.buffer = ""

    def connect(self):

        try:
            self.ws.connect(self.uri)
        except websocket.WebSocketException:
            raise MachineUnauthorizedError()

    def disconnect(self, **kwargs):
        try:
            self.ws.send_close()
            self.ws.close()
        except:
            pass

    def _wrap_command(self, cmd):
        if cmd[-1] != "\n":
            cmd = cmd + "\n"
        return cmd

    def command(self, cmd):
        self.cmd = self._wrap_command(cmd)
        log.error(self.cmd)

        self.ws = websocket.WebSocketApp(self.uri,
                                         on_message=self._on_message,
                                         on_error=self._on_error,
                                         on_close=self._on_close)

        log.error(self.ws)
        self.ws.on_open = self._on_open
        self.ws.run_forever(ping_interval=3, ping_timeout=10)
        self.ws.close()
        retval = 0
        output = self.buffer.split("\n")[1:-1]
        return retval, "\n".join(output)

    def _on_message(self, ws, message):
        self.buffer = self.buffer + message

    def _on_close(self, ws):
        ws.close()
        self.ws.close()

    def _on_error(self, ws, error):
        log.error("Got Websocket error: %s" % error)

    def _on_open(self, ws):
        def run(*args):
            ws.send(self.cmd)
            sleep(1)
        _thread.start_new_thread(run, ())

    def __del__(self):
        self.disconnect()


class DockerShell(WebSocketWrapper):
    """
    DockerShell achieved through the Docker host's API by opening a WebSocket
    """

    def __init__(self, host):
        self.host = host
        super(DockerShell, self).__init__()

    def autoconfigure(self, owner, cloud_id, machine_id, **kwargs):
        # the shell choosing logic will change when we will offer
        # more types of shells, now this always picks interactive

        shell_type = 'logging' if kwargs.get('job_id', '') else 'interactive'
        config_method = '%s_shell' % shell_type

        getattr(self, config_method)(owner,
                                     cloud_id=cloud_id, machine_id=machine_id,
                                     job_id=kwargs.get('job_id', ''))
        self.connect()
        # This is for compatibility purposes with the ParamikoShell
        return None, None

    def interactive_shell(self, owner, **kwargs):

        docker_port, cloud = \
            self.get_docker_endpoint(owner, cloud_id=kwargs['cloud_id'])
        log.info("Autoconfiguring DockerShell for machine %s:%s",
                 cloud.id, kwargs['machine_id'])

        ssl_enabled = cloud.key_file and cloud.cert_file
        self.uri = self.build_uri(kwargs['machine_id'], docker_port,
                                  cloud=cloud, ssl_enabled=ssl_enabled)

    def logging_shell(self, owner, log_type='CFY', **kwargs):
        docker_port, container_id = \
            self.get_docker_endpoint(owner, cloud_id=None,
                                     job_id=kwargs['job_id'])
        log.info('Autoconfiguring DockerShell to stream %s logs from '
                 'container %s (User: %s)', log_type, container_id, owner.id)
        ssl_enabled = config.DOCKER_TLS_KEY and config.DOCKER_TLS_CERT
        self.uri = self.build_uri(container_id, docker_port, allow_logs=1,
                                  allow_stdin=0, ssl_enabled=ssl_enabled)

    def get_docker_endpoint(self, owner, cloud_id, job_id=None):
        if job_id:
            event = get_story(owner.id, job_id)
            assert owner.id == event['owner_id'], 'Owner ID mismatch!'
            self.host, docker_port = config.DOCKER_IP, config.DOCKER_PORT
            return docker_port, event['logs'][0]['container_id']

        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        self.host, docker_port = dnat(owner, self.host, cloud.port)
        return docker_port, cloud

    def build_uri(self, container_id, docker_port, cloud=None,
                  ssl_enabled=False, allow_logs=0, allow_stdin=1):
        if ssl_enabled:
            self.protocol = 'wss'
            ssl_key, ssl_cert, ssl_ca_cert = self.ssl_credentials(cloud)
            if ssl_ca_cert:
                self.sslopt = {
                    'ca_certs': ssl_ca_cert.name,
                }
            else:
                self.sslopt = {'cert_reqs': ssl.CERT_NONE}
            self.sslopt['keyfile'] = ssl_key.name
            self.sslopt['certfile'] = ssl_cert.name
            self.ws = websocket.WebSocket(sslopt=self.sslopt)

        if cloud and cloud.username and cloud.password:
            uri = '%s://%s:%s@%s:%s/containers/%s/attach/ws?logs=%s&stream=1&stdin=%s&stdout=1&stderr=1' % (  # noqa
                self.protocol, cloud.username, cloud.password, self.host,
                docker_port, container_id, allow_logs, allow_stdin
            )
        else:
            uri = '%s://%s:%s/containers/%s/attach/ws?logs=%s&stream=1&stdin=%s&stdout=1&stderr=1' % (  # noqa
                self.protocol, self.host, docker_port, container_id,
                allow_logs, allow_stdin
            )

        return uri

    @staticmethod
    def ssl_credentials(cloud=None):
        if cloud is None:
            tempkey = None
            tempcert = None
            tempca_cert = None
            if config.DOCKER_TLS_KEY and config.DOCKER_TLS_CERT:
                tempkey = tempfile.NamedTemporaryFile(delete=False)
                with open(tempkey.name, 'w') as f:
                    f.write(config.DOCKER_TLS_KEY)
                tempcert = tempfile.NamedTemporaryFile(delete=False)
                with open(tempcert.name, 'w') as f:
                    f.write(config.DOCKER_TLS_CERT)
            if config.DOCKER_TLS_CA:
                tempca_cert = tempfile.NamedTemporaryFile(delete=False)
                with open(tempca_cert.name, 'w') as f:
                    f.write(config.DOCKER_TLS_CA)
            return tempkey, tempcert, tempca_cert
        return super(DockerShell, DockerShell).ssl_credentials(cloud=cloud)


class LXDWebSocket(WebSocketWrapper):

    def __init__(self, host):
        super(LXDWebSocket, self).__init__()

        # for interactive shell LXD REST API
        # returns the operation id
        # the control sha
        # the secret sha
        self.curi = None
        self.cws = None
        self.host = host
        self._control = ""
        self._uuid = ""
        self._secret_0 = ""

    def control(self):
        super(LXDWebSocket, self).connect()
        self.connect_control()

    def connect_control(self):
        """
        Connect to the control websocket for LXD
        """
        try:
            self.cws.connect(self.curi)
        except websocket.WebSocketException:
            raise MachineUnauthorizedError()

    def build_uri(self, lxd_port, cloud=None,
                  ssl_enabled=False, **kwargs):

        self.protocol = 'wss'
        ssl_key, ssl_cert, ssl_ca_cert = self.ssl_credentials(cloud)
        if ssl_ca_cert:
            self.sslopt = {
                'ca_certs': ssl_ca_cert.name,
            }
        else:
            self.sslopt = {'cert_reqs': ssl.CERT_NONE}
        self.sslopt['keyfile'] = ssl_key.name
        self.sslopt['certfile'] = ssl_cert.name
        self.ws = websocket.WebSocket(sslopt=self.sslopt)
        self.cws = websocket.WebSocket(sslopt=self.sslopt)

        self.uri = '%s://%s:%s/1.0/operations/%s/' \
                   'websocket?secret=%s' % (self.protocol,
                                            self.host,
                                            lxd_port,
                                            self._uuid,
                                            self._secret_0)

        self.curi = '%s://%s:%s/1.0/operations/%s/' \
                    'websocket?secret=%s' % (self.protocol,
                                             self.host,
                                             lxd_port,
                                             self._uuid,
                                             self._control)

    def set_ws_data(self, uuid, secret, control):
        """
        Set the data for the interactive socket
        """
        self._uuid = uuid
        self._secret_0 = secret
        self._control = control

    def _wrap_command(self, cmd):
        if cmd[-1] != "\r":
            cmd = cmd + "\r"
        return cmd

    def _on_open(self, ws):
        def run(*args):
            ws.send(bytearray(self.cmd, encoding='utf-8'), opcode=2)
            sleep(1)
            _thread.start_new_thread(run, ())


class LXDShell(LXDWebSocket):
    """
        LXDShell achieved through the LXD host's API by opening a WebSocket
    """

    def __init__(self, host):
        super(LXDShell, self).__init__(host=host)

    def autoconfigure(self, owner, cloud_id, machine_id, **kwargs):

        # create an interactive shell
        # it builds the self.uri to connect below
        self.interactive_shell(owner=owner, machine_id=machine_id,
                               cloud_id=cloud_id, **kwargs)

        # connect to both the interactive websocket
        # and the control
        self.connect()
        self.connect_control()

        # This is for compatibility purposes with the ParamikoShell
        return None, None

    def interactive_shell(self, owner, machine_id, cloud_id, **kwargs):

        lxd_port, cloud = \
            self.get_lxd_endpoint(owner, cloud_id=cloud_id, job_id=None)

        log.info("Autoconfiguring LXDShell for machine %s:%s",
                 cloud.id, machine_id)

        ssl_enabled = cloud.key_file and cloud.cert_file

        from mist.api.methods import connect_provider
        conn = connect_provider(cloud)

        config = {"wait-for-websocket": True, "interactive": True}
        environment = {"TERM": "xterm"}
        config["environment"] = environment
        config["width"] = kwargs["cols"]
        config["height"] = kwargs["rows"]

        # I need here the name not mist id
        machine = Machine.objects.get(id=machine_id, cloud=cloud_id)

        cont_id = machine.name
        response = conn.ex_execute_cmd_on_container(cont_id=cont_id,
                                                    command=["/bin/sh"],
                                                    **config)

        uuid = response.uuid
        secret_0 = response.secret_0
        self.set_ws_data(control=response.control,
                         uuid=uuid, secret=secret_0)

        # build the uri to use for the connection
        self.build_uri(lxd_port=lxd_port, cloud=cloud,
                       ssl_enabled=ssl_enabled, **kwargs)

    def get_lxd_endpoint(self, owner, cloud_id, job_id=None):

        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        self.host, lxd_port = dnat(owner, self.host, cloud.port)
        return lxd_port, cloud

    def resize_pty(self, columns, rows):

        data = {
            'command': 'window-resize',
            'args': {
                'width': str(columns),
                'height': str(rows)
            }
        }
        data = json.dumps(data)
        self.cws.send(bytearray(data, encoding='utf-8'), opcode=2)
        return columns, rows


class KubernetesWebSocket(object):
    """
    Base WebSocket class inherited by DockerShell
    """

    def __init__(self):
        self.ws = websocket.WebSocket()
        self.protocol = "wss"
        self.uri = ""
        self.sslopt = {}
        self.buffer = b""
        self.header = None
        self.buflen = 1

    def connect(self):
        try:
            if self.header is not None:
                self.ws.connect(self.uri, header=self.header)
            else:
                self.ws.connect(self.uri)
        except websocket.WebSocketException as exc:
            msg = "Make sure you are authorized to access this machine"
            raise MachineUnauthorizedError(msg)

    def send(self, cmd):
        command = bytearray(b'\x00')  # stdin is 0 for k8s
        command.extend(map(ord, cmd))
        self.ws.send(command, opcode=2)

    def recv(self):
        return self.ws._recv(self.buflen)

    def disconnect(self, **kwargs):
        try:
            self.ws.send_close()
            self.ws.close()
        except:
            pass

    def _wrap_command(self, cmd):
        if cmd[-1] != "\n":
            cmd = cmd + "\n"
        return cmd

    def __del__(self):
        self.disconnect()


class KubernetesShell(KubernetesWebSocket):
    """
    Kubernetes shell into a pod.
    Can be used by KubeVirt to get a shell to a vm.
    """

    def __init__(self):
        self.host = ""
        self.port = "6443"
        super(KubernetesShell, self).__init__()

    def resize(self, columns, rows):
        if not self.ws.connected:
            return
        command = bytearray(b'\x01\033\133')
        command.extend(map(ord, '8;{};{}t\r'.format(rows, columns)))
        self.ws.send(command, opcode=2)
        # self.send('history -c\r')
        # command = "clear\r"
        # self.send(command)

    def autoconfigure(self, owner, cloud_id, machine_id, **kwargs):
        shell_type = 'interactive'
        config_method = '%s_shell' % shell_type

        getattr(self, config_method)(owner,
                                     cloud_id=cloud_id, machine_id=machine_id)
        try:
            self.connect()
        except Exception as e:
            raise
        # This is for compatibility purposes with the ParamikoShell
        return None, None

    def interactive_shell(self, owner, cloud_id, machine_id):

        machine, cloud = \
            self.get_kubernetes_endpoint(machine_id, cloud_id)
        log.info("Autoconfiguring KubernetesShell for machine %s:%s",
                 cloud.id, machine_id)

        self.uri = self.build_uri(machine, cloud=cloud)

    def build_uri(self, machine, cloud=None):
        """
        SSL is always enabled in K8s. Because it uses its own CA
        it might be required to skip the CA validation.
        """
        self.host = cloud.host
        if "https://" in self.host or "http://" in self.host:
            self.host = self.host.lstrip("http://")
            self.host = self.host.lstrip("https://")

        self.port = cloud.port
        self.protocol = 'wss'
        ssl_key, ssl_cert, ssl_ca_cert = self.ssl_credentials(cloud)
        if ssl_ca_cert:
            self.sslopt = {
                'ca_certs': ssl_ca_cert.name,
            }
        else:
            self.sslopt = {'cert_reqs': ssl.CERT_NONE}

        if ssl_key is not None and ssl_cert is not None:
            self.sslopt['keyfile'] = ssl_key.name
            self.sslopt['certfile'] = ssl_cert.name

            self.ws = websocket.WebSocket(sslopt=self.sslopt)

        elif cloud and cloud.username and cloud.password:
            usr = cloud.username.encode('utf-8')
            pwd = cloud.password.encode('utf-8')
            auth = usr + b':' + pwd
            auth = base64.b64encode(auth).decode('ascii')
            header = ['Authorization: Basic {}'.format(auth)]
            self.header = header
            self.ws = websocket.WebSocket(sslopt=self.sslopt, header=header)

        elif cloud.token:
            token = cloud.token
            self.header = ['Authorization: Bearer ' + token]
            self.ws = websocket.WebSocket(sslopt=self.sslopt,
                                          header=self.header)

        uri = ("wss://{host}:{port}/api/v1/namespaces/{namespace}/pods/{pod}/"
               "exec?command=%2Fbin%2Fbash&container=compute&stdin="
               "true&stderr=true&stdout=true&"
               "tty=true".format(host=self.host, port=self.port,
                                 namespace=machine.extra['namespace'],
                                 pod=machine.extra['pod']['name']))
        return uri

    def get_kubernetes_endpoint(self, machine_id, cloud_id):

        machine = Machine.objects.get(id=machine_id)
        cloud = Cloud.objects.get(id=cloud_id)
        return machine, cloud

    @staticmethod
    def ssl_credentials(cloud=None):
        if cloud and cloud.ca_cert_file:
            _ca_cert = cloud.ca_cert_file
            tempca_cert = tempfile.NamedTemporaryFile(delete=False)
            with open(tempca_cert.name, 'w') as f:
                f.write(_ca_cert)
        else:
            tempca_cert = None
        if cloud and cloud.key_file and cloud.cert_file:
            _key, _cert = cloud.key_file, cloud.cert_file
            tempkey = tempfile.NamedTemporaryFile(delete=False)
            with open(tempkey.name, 'w') as f:
                f.write(_key)
            tempcert = tempfile.NamedTemporaryFile(delete=False)
            with open(tempcert.name, 'w') as f:
                f.write(_cert)
        else:
            tempkey = None
            tempcert = None

        return tempkey, tempcert, tempca_cert


class Shell(object):
    """Proxy Shell Class to distinguish between Docker or Paramiko Shell
    """

    def __init__(self, host, provider=None, username=None, key=None,
                 password=None, cert_file=None, port=22,
                 enforce_paramiko=False):
        """

        :param provider: If docker, then DockerShell
        :param host: Host of machine/docker
        :param enforce_paramiko: If True, then Paramiko even for Docker
                                 containers. This is useful if we want SSH
                                 Connection to Docker containers
        :return:
        """
        self._shell = None
        self.host = host
        self.channel = None
        self.ssh = None
        if provider == 'docker' and not enforce_paramiko:
            self._shell = DockerShell(host)
        elif provider == 'kubevirt' and not enforce_paramiko:
            self._shell = KubernetesShell()
        elif provider == 'lxd' and not enforce_paramiko:
            self._shell = LXDShell(host=host)
        else:
            self._shell = ParamikoShell(host, username=username, key=key,
                                        password=password, cert_file=cert_file,
                                        port=port)
            self.ssh = self._shell.ssh

    def get_type(self):
        if isinstance(self._shell, ParamikoShell):
            return "ParamikoShell"
        elif isinstance(self._shell, DockerShell):
            return "DockerShell"
        elif isinstance(self._shell, LXDShell):
            return "LXDShell"

        raise TypeError("Unknown shell type")

    def autoconfigure(self, owner, cloud_id, machine_id, key_id=None,
                      username=None, password=None, port=22, **kwargs):
        if isinstance(self._shell, ParamikoShell):
            return self._shell.autoconfigure(
                owner, cloud_id, machine_id, key_id=key_id,
                username=username, password=password, port=port
            )
        elif isinstance(self._shell, KubernetesShell):
            return self._shell.autoconfigure(owner, cloud_id, machine_id)
        elif isinstance(self._shell, DockerShell) or\
                isinstance(self._shell, LXDShell):
            return self._shell.autoconfigure(owner=owner,
                                             cloud_id=cloud_id,
                                             machine_id=machine_id, **kwargs)

    def connect(self, username, key=None, password=None, cert_file=None,
                port=22):

        if isinstance(self._shell, ParamikoShell):
            self._shell.connect(username, key=key, password=password,
                                cert_file=cert_file, port=port)
        elif isinstance(self._shell, DockerShell) or\
                isinstance(self._shell, LXDShell):
            self._shell.connect()
        elif isinstance(self._shell, KubernetesShell):
            self._shell.connect()

    def invoke_shell(self, term='xterm', cols=None, rows=None):

        if isinstance(self._shell, ParamikoShell):
            return self._shell.ssh.invoke_shell(term, cols, rows)
        elif isinstance(self._shell, DockerShell) or\
                isinstance(self._shell, LXDShell):
            return self._shell.ws
        elif isinstance(self._shell, KubernetesShell):
            return self._shell.ws

    def send(self, body):
        if isinstance(self._shell, KubernetesShell):
            return self._shell.send(body)

    def recv(self, default=1024):
        if isinstance(self._shell, ParamikoShell):
            return self._shell.ssh.recv(default)
        elif isinstance(self._shell, DockerShell) or\
                isinstance(self._shell, LXDShell):
            return self._shell.ws.recv()
        elif isinstance(self._shell, KubernetesShell):
            return self._shell.ws.recv()

    def disconnect(self):
        self._shell.disconnect()

    def command(self, cmd, pty=True):
        if isinstance(self._shell, ParamikoShell):
            return self._shell.command(cmd, pty=pty)
        elif isinstance(self._shell, DockerShell) or\
                isinstance(self._shell, LXDShell):
            return self._shell.command(cmd)
        elif isinstance(self._shell, KubernetesShell):
            return self._shell.command(cmd)

    def command_stream(self, cmd):
        if isinstance(self._shell, ParamikoShell):
            yield self._shell.command_stream(cmd)

    def resize(self, columns, rows):

        if isinstance(self._shell, LXDShell):
            self._shell.resize_pty(columns, rows)

        return columns, rows
