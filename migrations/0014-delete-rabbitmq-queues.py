#!/usr/bin/env python

import pika

from mist.api import config

QUEUES = ['command', 'machines', 'scripts', 'probe', 'ping',
          'rules', 'deployments', 'mappings', 'networks', 'volumes',
          'zones', 'buckets', 'default']


def delete_queues():
    print('Deleting rabbitmq queues')
    host, port = config.AMQP_URI.split(':')
    connection = pika.BlockingConnection(pika.ConnectionParameters(
        host=host, port=port))
    channel = connection.channel()
    for queue in QUEUES:
        response = channel.queue_delete(queue=queue)
        if isinstance(response.method, pika.spec.Queue.DeleteOk):
            print(f'Successfully deleted queue {queue}')
        else:
            print(f'Failed to delete queue {queue}, response: {response}')

    connection.close()


if __name__ == '__main__':
    delete_queues()
