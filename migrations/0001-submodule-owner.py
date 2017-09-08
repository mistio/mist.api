#!/usr/bin/env python

import sys
import argparse

from mist.api.users.models import Organization
import mist.api.clouds  # Required for Machine model initialization.
from mist.api.machines.models import Machine
from mist.api.dns.models import Record


def parse_args():
    argparser = argparse.ArgumentParser(
        description="Populate `owner` field for `Machine` and `Record` models."
    )
    argparser.add_argument(
        '-p', '--purge', action='store_true',
        help="Remove models with missing parent model or owner."
    )
    return argparser.parse_args()


def migrate(purge=False):
    error = False
    for model in (Machine, Record):
        name = model.__name__.lower()
        print "Will update `owner` field in %ss" % name
        objects = model.objects(owner=None)
        print "Found %d %ss without owner:" % (objects.count(), name)
        counters = {'updated': 0, 'error': 0, 'deleted': 0, 'skipped': 0}
        for item in objects:
            # saving will trigger `clean`, which will autoset the owner
            try:
                item.save()
            except Exception as exc:
                print "Error while updating %s '%s': %r" % (name, item, exc)
                counters['error'] += 1
                if purge:
                    print "Deleting %s '%s'" % (name, item)
                    item.delete()
                    counters['deleted'] += 1
                else:
                    counters['skipped'] += 1
            else:
                counters['updated'] += 1
        for counter in counters:
            print "%ss %s: %d" % (name.capitalize(),
                                  counter, counters[counter])
        if counters['error']:
            print "Completed with errors"
            error = True
        else:
            print "Completed successfully"
        print
    if error:
        print "Exiting with errors!"
        sys.exit(1)
    print "Exiting successfully!"
    sys.exit(0)


if __name__ == '__main__':
    migrate(purge=parse_args().purge)
