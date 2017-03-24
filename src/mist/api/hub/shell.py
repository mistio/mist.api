import sys
import logging


import gevent
import gevent.socket


import mist.api.exceptions
import mist.api.shell
import mist.api.hub.main

import mist.api.users.models


log = logging.getLogger(__name__)


class ShellHubWorker(mist.api.hub.main.HubWorker):
    def __init__(self, *args, **kwargs):
        super(ShellHubWorker, self).__init__(*args, **kwargs)
        self.shell = None
        self.channel = None
        for key in ('owner_id', 'email', 'cloud_id', 'machine_id', 'host',
                    'columns', 'rows'):
            if not self.params.get(key):
                log.error("%s: Param '%s' missing from worker kwargs.",
                          self.lbl, key)
                self.stop()
        self.provider = ''
        self.owner = mist.api.users.models.Owner(id=self.params['owner_id'])

    def on_ready(self, msg=''):
        super(ShellHubWorker, self).on_ready(msg)
        self.connect()

    def connect(self):
        """Connect to shell"""
        if self.shell is not None:
            log.error("%s: Can't call on_connect twice.", self.lbl)
            return
        data = self.params
        self.provider = data.get('provider', '')
        try:
            self.shell = mist.api.shell.Shell(data['host'])
            key_id, ssh_user = self.shell.autoconfigure(
                self.owner, data['cloud_id'], data['machine_id']
            )
        except Exception as exc:
            if self.provider == 'docker':
                self.shell = mist.api.shell.Shell(data['host'],
                                                 provider='docker')
                key_id, ssh_user = self.shell.autoconfigure(
                    self.owner, data['cloud_id'], data['machine_id'],
                    job_id=data['job_id'],
                )
            else:
                log.warning("%s: Couldn't connect with SSH, error %r.",
                            self.lbl, exc)
                if isinstance(exc,
                              mist.api.exceptions.MachineUnauthorizedError):
                    err = 'Permission denied (publickey).'
                else:
                    err = str(exc)
                self.emit_shell_data(err)
                self.params['error'] = err
                self.stop()
                return
        self.params.update(key_id=key_id, ssh_user=ssh_user)
        self.channel = self.shell.invoke_shell('xterm',
                                               data['columns'], data['rows'])
        self.greenlets['read_stdout'] = gevent.spawn(self.get_ssh_data)

    def on_data(self, msg):
        """Received data that must be forwarded to shell's stdin"""
        self.channel.send(msg.body.encode('utf-8', 'ignore'))

    def on_resize(self, msg):
        """Received resize shell window command"""
        if isinstance(msg.body, dict):
            if 'columns' in msg.body and 'rows' in msg.body:
                columns, rows = msg.body['columns'], msg.body['rows']
                log.info("%s: Resizing shell to (%s, %s).",
                         self.lbl, columns, rows)
                try:
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


class ShellHubClient(mist.api.hub.main.HubClient):
    def __init__(self, exchange=mist.api.hub.main.EXCHANGE,
                 key=mist.api.hub.main.REQUESTS_KEY, worker_kwargs=None):
        super(ShellHubClient, self).__init__(exchange, key, 'shell',
                                             worker_kwargs)

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

    def on_data(self, msg):
        print msg.body

    def stop(self):
        self.send_close()
        super(ShellHubClient, self).stop()
