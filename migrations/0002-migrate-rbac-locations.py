#!/usr/bin/env python

import sys
import argparse

from mist.api.clouds.models import CloudLocation


def parse_args():
    argparser = argparse.ArgumentParser(
        description="Populate `owner` field for `CloudLocation` model."
    )
    argparser.add_argument(
        '-p', '--purge', action='store_true',
        help="Remove models with missing parent model or owner."
    )
    return argparser.parse_args()


def migrate(purge=False):
    error = False
    print("Will update `owner` field in CloudLocation objects")
    objects = CloudLocation.objects(owner=None)
    print("Found %d objects without owner:" % (objects.count()))
    counters = {'updated': 0, 'error': 0, 'deleted': 0, 'skipped': 0}
    for item in objects:
        # saving will trigger `clean`, which will autoset the owner
        try:
            item.save()
        except Exception:
            counters['error'] += 1
            if purge:
                item.delete()
                counters['deleted'] += 1
            else:
                counters['skipped'] += 1
        else:
            counters['updated'] += 1
    for counter in counters:
        print("%ss %s: %d" % ("CloudLocation",
                              counter, counters[counter]))
    if counters['error']:
        print("Completed with errors")
        error = True
    else:
        print("Completed successfully")
    print

    if error:
        print("Exiting with errors!")
        sys.exit(1)
    print("Exiting successfully!")
    sys.exit(0)


if __name__ == '__main__':
    migrate(purge=parse_args().purge)
