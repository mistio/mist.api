#!/usr/bin/env python

import time

import certifi

from elasticsearch import Elasticsearch

from mist.api import config
from mist.api.models import Machine


def es_client():
    es = Elasticsearch(
        config.ELASTICSEARCH['elastic_host'],
        port=config.ELASTICSEARCH['elastic_port'],
        http_auth=(config.ELASTICSEARCH['elastic_username'],
                   config.ELASTICSEARCH['elastic_password']),
        use_ssl=bool(config.ELASTICSEARCH['elastic_use_ssl']),
        verify_certs=bool(config.ELASTICSEARCH['elastic_verify_certs']),
        ca_certs=certifi.where()
    )
    for i in range(20):
        if es.ping():
            return es
        print("Elasticsearch not up yet")
        time.sleep(1)
    print("Elasticsearch doesn't respond to ping")
    raise Exception()


def migrate_machine_logs():
    # Initialize ES client.
    es = es_client()
    hosts = []
    for host in es.transport.hosts:
        hosts.append(host['host'])

    print('Connected to: %s' % ', '.join(hosts))

    # Search logs with machine_id, excluding observation logs and entries that
    # already include an external_id
    index = 'app-logs-*'
    batch_size = 10
    query = {
        'query': {
            'bool': {
                'must': {
                    'exists': {
                        'field': 'machine_id'
                    }
                },
                'must_not': [{
                    'term': {
                        'type': 'observation'
                    }
                }, {
                    'exists': {
                        'field': 'external_id'
                    }
                }]
            },
        },
        'from': 0,
        'size': batch_size
    }

    machine_logs = es.search(
        index=index,
        body=query
    )

    total = machine_logs['hits']['total']
    skipped = 0
    migrated = 0
    while machine_logs['hits']['hits']:
        for m in machine_logs['hits']['hits']:
            try:
                machine = Machine.objects.get(
                    cloud=m['_source']['cloud_id'],
                    machine_id=m['_source']['machine_id'])
                # Update machine_id & set external_id
                es.update(
                    index=index,
                    id=m['_id'],
                    doc_type=m['_type'],
                    body={
                        "doc": {
                            "machine_id": machine.id,
                            "external_id": machine.machine_id
                        }
                    }
                )
                migrated += 1
            except Machine.DoesNotExist:
                skipped += 1
                continue
        query['from'] += batch_size
        machine_logs = es.search(
            index=index,
            body=query
        )
    print('Migrated %d, skipped %d, out of %d tags' % (
        migrated, skipped, total))


if __name__ == '__main__':
    migrate_machine_logs()
