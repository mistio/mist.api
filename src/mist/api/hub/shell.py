import sys
import time
import logging

import gevent
import gevent.socket

import mist.api.exceptions
import mist.api.shell
import mist.api.hub.main
import mist.api.users.models
import mist.api.logs.methods
from mist.api.misc.shell import ShellCapture

from mist.api import config


log = logging.getLogger(__name__)


class ShellHubWorker(mist.api.hub.main.HubWorker):
    def __init__(self, *args, **kwargs):
        super(ShellHubWorker, self).__init__(*args, **kwargs)
        self.shell = None
        self.channel = None
        for key in ('owner_id', 'cloud_id', 'machine_id', 'host',
                    'columns', 'rows'):
            # HACK:FIXME: Temporary fix for Orchestration shell.
            # Add a new, dedicated ShellHubWorker for Orchestration logs.
            if key in ('host', 'cloud_id', 'machine_id', ):
                if self.params.get('job_id'):
                    continue
            if not self.params.get(key):
                err = "%s: Param '%s' missing from worker kwargs." % (self.lbl,
                                                                      key)
                log.error(err)
                self.stop()
                raise Exception(err)
        self.provider = ''
        self.owner = mist.api.users.models.Owner(id=self.params['owner_id'])

    def on_ready(self, body='', msg=''):
        super(ShellHubWorker, self).on_ready(body, msg)
        self.connect()

    def connect(self):
        """Connect to shell"""
        if self.shell is not None:
            log.error("%s: Can't call on_connect twice.", self.lbl)
            return

        data = self.params
        self.provider = data.get('provider', '')

        host = data.get('host', '')
        cloud_id = data.get('cloud_id', '')
        machine_id = data.get('machine_id', '')
        job_id = data.get('job_id', '')
        cols = data["columns"]
        rows = data["rows"]

        try:

            self.shell = mist.api.shell.Shell(host, provider=self.provider)
            key_id, ssh_user = self.shell.autoconfigure(owner=self.owner,
                                                        cloud_id=cloud_id,
                                                        machine_id=machine_id,
                                                        job_id=job_id,
                                                        cols=cols,
                                                        rows=rows)
            self.params.update(key_id=key_id, ssh_user=ssh_user)

        except Exception as exc:
            if self.provider == 'docker':
                self.shell = mist.api.shell.Shell(data['host'],
                                                  provider='docker')
                key_id, ssh_user = self.shell.autoconfigure(
                    self.owner, data['cloud_id'], data['machine_id'],
                    job_id=data['job_id'],
                )
            elif self.provider == "kubevirt":
                self.shell = mist.api.shell.Shell(data['host'],
                                                  provider='kubevirt')
                key_id, ssh_user = self.shell.autoconfigure(
                    self.owner, data['cloud_id'], data['machine_id']
                )
            else:
                self.shell = mist.api.shell.Shell(data['host'])
                key_id, ssh_user = self.shell.autoconfigure(
                    self.owner, data['cloud_id'], data['machine_id']
                )
        except Exception as exc:
            log.warning("%s: Couldn't connect with SSH, error %r.",
                        self.lbl, exc)
            if isinstance(exc, mist.api.exceptions.MachineUnauthorizedError):
                err = 'Permission denied (publickey).'
            else:
                err = str(exc)
            self.emit_shell_data(err)
            self.params['error'] = err
            self.stop()
            return

        self.channel = self.shell.invoke_shell('xterm',
                                               data['columns'], data['rows'])
        self.greenlets['read_stdout'] = gevent.spawn(self.get_ssh_data)

    def on_data(self, body, msg):
        """Received data that must be forwarded to shell's stdin"""
        if self.provider == 'kubevirt':
            self.shell.send(body)

        # TODO: Factory should be moved from here
        elif self.shell.get_type() == "ParamikoShell" or \
                self.shell.get_type() == "DockerShell":
            self.channel.send(body.encode('utf-8', 'ignore'))
        elif self.shell.get_type() == "LXDShell":
            self.channel.send(bytearray(body, encoding='utf-8'), opcode=2)

    def on_resize(self, body, msg):
        """Received resize shell window command"""
        if isinstance(body, dict):
            if 'columns' in body and 'rows' in body:
                columns, rows = body['columns'], body['rows']
                log.info("%s: Resizing shell to (%s, %s).",
                         self.lbl, columns, rows)
                try:
                    if self.provider == 'kubevirt':
                        self.shell._shell.resize(columns, rows)

                    elif self.shell.get_type() == "LXDShell":

                        # also pass the channel to emulate how things
                        # were done in the past
                        columns, rows = self.shell.resize(columns=columns,
                                                          rows=rows)
                    else:
                        self.channel.resize_pty(columns, rows)

                    return columns, rows
                except Exception as exc:
                    log.warning("%s: Error resizing shell to (%s, %s): %r.",
                                self.lbl, columns, rows, exc)

    def emit_shell_data(self, data):
        self.send_to_client('data', data)

    def get_ssh_data(self):
        try:
            if self.provider == 'docker':
                try:
                    self.channel.send('\n')
                except:
                    pass
            while True:
                gevent.socket.wait_read(self.channel.fileno())
                try:
                    data = self.channel.recv(1024).decode('utf-8', 'ignore')
                except TypeError:
                    data = self.channel.recv().decode('utf-8', 'ignore')
                except AttributeError:
                    data = self.channel.recv()

                if not len(data):
                    return
                self.emit_shell_data(data)
        finally:
            self.channel.close()

    def stop(self):
        super(ShellHubWorker, self).stop()
        if self.channel is not None:
            self.channel.close()
            self.channel = None
        if self.shell is not None:
            self.shell.disconnect()
            self.shell = None


class LoggingShellHubWorker(ShellHubWorker):
    def __init__(self, *args, **kwargs):
        super(LoggingShellHubWorker, self).__init__(*args, **kwargs)
        self.capture = []
        self.capture_started_at = 0
        self.stopped = False

    def on_ready(self, body='', msg=''):
        super(LoggingShellHubWorker, self).on_ready(body, msg)
        # Don't log cfy container log views
        if (
            self.params.get('provider') != 'docker' or
            not self.params.get('job_id')
        ):
            mist.api.logs.methods.log_event(action='open', event_type='shell',
                                            shell_id=self.uuid, **self.params)

    def emit_shell_data(self, data):

        self.capture.append((time.time(), 'data', data))
        super(LoggingShellHubWorker, self).emit_shell_data(data)

    def on_resize(self, body, msg):
        res = super(LoggingShellHubWorker, self).on_resize(body, msg)
        if res:
            self.capture.append((time.time(), 'resize', res))

    def stop(self):
        if self.shell and not self.stopped:
            # if not self.shell then namespace initialized
            # but shell_open has happened
            if config.ENABLE_SHELL_CAPTURE:
                if self.capture:
                    # save captured data
                    capture = ShellCapture()
                    capture.owner = mist.api.users.models.Owner(
                        id=self.params['owner_id']
                    )
                    capture.capture_id = self.uuid
                    capture.cloud_id = self.params['cloud_id']
                    capture.machine_id = self.params['machine_id']
                    capture.key_id = self.params.get('key_id')
                    capture.host = self.params['host']
                    capture.ssh_user = self.params.get('ssh_user')
                    capture.started_at = self.capture_started_at
                    capture.finished_at = time.time()
                    capture.columns = self.params['columns']
                    capture.rows = self.params['rows']
                    capture.capture = [(tstamp - self.capture[0][0],
                                        event, data)
                                       for tstamp, event, data in self.capture]
                    capture.save()
            # Don't log cfy container log views
            if (
                self.params.get('provider') != 'docker' or
                not self.params.get('job_id')
            ):
                mist.api.logs.methods.log_event(action='close',
                                                event_type='shell',
                                                shell_id=self.uuid,
                                                **self.params)
        super(LoggingShellHubWorker, self).stop()


class ShellHubClient(mist.api.hub.main.HubClient):
    def __init__(self, *args, **kwargs):
        super(ShellHubClient, self).__init__(*args, worker_type='shell',
                                             **kwargs)

    def start(self):
        """Call super and also start stdin reader greenlet"""
        super(ShellHubClient, self).start()
        gevent.sleep(1)
        self.greenlets['stdin'] = gevent.spawn(self.send_stdin)

    def send_stdin(self):
        """Continuously read lines from stdin and send them to worker"""
        while True:
            gevent.socket.wait_read(sys.stdin.fileno())
            self.send_data(sys.stdin.readline())
            gevent.sleep(0)

    def send_data(self, data):
        self.send_to_worker('data', data)

    def resize(self, columns, rows):
        self.send_to_worker('rezize', {'columns': columns, 'rows': rows})

    def on_data(self, body, msg):
        print(body)

    def stop(self):
        self.send_close()
        super(ShellHubClient, self).stop()


if __name__ == "__main__":
    mist.api.hub.main.main(workers={'shell': LoggingShellHubWorker})
