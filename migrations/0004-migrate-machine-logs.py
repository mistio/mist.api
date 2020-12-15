#!/usr/bin/env python

import argparse
import datetime

from elasticsearch.exceptions import NotFoundError

from mist.api.helpers import es_client
from mist.api.models import Machine


def migrate_machine_logs(year=None, delete_missing=False, print_missing=False):
    if not year:
        year = datetime.datetime.now().year
    # Initialize ES client.
    es = es_client()
    hosts = []
    for host in es.transport.hosts:
        hosts.append(host['host'])

    print('Connected to: %s' % ', '.join(hosts))

    # Search logs with machine_id, excluding observation logs and entries that
    # already include an external_id
    index = 'app-logs-%d' % int(year)
    batch_size = 10
    query = {
        'query': {
            'bool': {
                'filter': {
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
                    }
                }
            }
        },
    }
    try:
        data = es.search(
            index=index,
            body=query,
            scroll='2m',
            size=batch_size
        )
    except NotFoundError as e:
        print("Index not found: %r" % e)
        return
    except Exception as e:
        print("Unknown exception: %r" % e)
        return

    # Get the scroll ID
    sid = data['_scroll_id']
    scroll_size = len(data['hits']['hits'])
    total = data['hits']['total']
    skipped = 0
    deleted = 0
    migrated = 0
    while scroll_size > 0:
        "Scrolling..."
        for m in data['hits']['hits']:
            try:
                # Get machine by external id
                machine = Machine.objects.get(
                    cloud=m['_source']['cloud_id'],
                    machine_id=m['_source']['external_id'])
            except (Machine.DoesNotExist, KeyError):
                try:
                    # Try to get machine by unique id just in case
                    machine = Machine.objects.get(
                        id=m['_source']['machine_id'])
                except Machine.DoesNotExist:
                    if delete_missing:
                        # Delete log that refers to a missing machine
                        es.delete(
                            index=index,
                            id=m['_id'],
                            doc_type=m['_type']
                        )
                        deleted += 1
                    else:
                        if print_missing:
                            print(m['_source'])
                        skipped += 1
                    continue
            # Update machine_id & set external_id
            es.update(
                index=index,
                id=m['_id'],
                doc_type=m['_type'],
                body={
                    "doc": {
                        "machine_id": machine.id,
                        "external_id": machine.external_id
                    }
                }
            )
            migrated += 1

        print('Migrated %d, skipped %d, deleted %d out of %d log entries' % (
            migrated, skipped, deleted, total))

        # Get next batch
        data = es.scroll(scroll_id=sid, scroll='2m')
        # Update the scroll ID
        sid = data['_scroll_id']
        # Get the number of results that returned in the last scroll
        scroll_size = len(data['hits']['hits'])


def parse_args():
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        '-y', '--year',
        help="Update the anual index for this year"
    )
    argparser.add_argument(
        '-p', '--print-missing', action='store_true',
        help="Display log entries that refer to missing machines."
    )
    argparser.add_argument(
        '-d', '--delete-missing', action='store_true',
        help="Delete log entries that refer to missing machines."
    )
    return argparser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    migrate_machine_logs(
        year=args.year,
        delete_missing=args.delete_missing,
        print_missing=args.print_missing
    )
