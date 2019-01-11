import logging

from mist.api.hub.tornado_client import HubClient


log = logging.getLogger(__name__)


class ShellHubClient(HubClient):
    def __init__(self, exchange='hub', key='hub', worker_kwargs=None):
        super(ShellHubClient, self).__init__(exchange, key, 'shell',
                                             worker_kwargs)

    def send_data(self, msg):
        self.send_to_worker('data', msg)

    def on_data(self, msg):
        print(msg)

    def resize(self, columns, rows):
        self.send_to_worker('resize', {'columns': columns, 'rows': rows})

    def stop(self):
        self.send_to_worker('close')
        super(ShellHubClient, self).stop()
