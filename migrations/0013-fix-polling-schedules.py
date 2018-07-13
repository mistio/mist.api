#!/usr/bin/env python

import sys
import argparse

import mongoengine as me

from mist.api.poller.models import PollingSchedule


def parse_args():
    argparser = argparse.ArgumentParser(
        description="Update polling schedules, fix names, ensure uniqueness"
    )
    return argparser.parse_args()


def migrate():
    counters = {
        'updated': 0,
        'error': 0,
        'deleted': 0,
        'skipped': 0,
    }
    for sched in PollingSchedule.objects.all():
        try:
            name = sched.get_name()
        except Exception as exc:
            print "Couldn't get new name for '%s': %r" % (sched.name, exc)
            counters['error'] += 1
        else:
            if name == sched.name:
                counters['skipped'] += 1
            else:
                sched.name = name
                try:
                    sched.save()
                except me.NotUniqueError:
                    print "Will delete duplicate schedule for '%s'." % name
                    try:
                        sched.delete()
                    except Exception as exc:
                        print "Couldn't update '%s': %r" % (name, exc)
                        counters['error'] += 1
                    else:
                        counters['deleted'] += 1
                except Exception as exc:
                    print "Couldn't update '%s': %r" % (name, exc)
                    counters['error'] += 1
                else:
                    counters['updated'] += 1

    for counter in counters:
        print "Schedules %s: %d" % (counter, counters[counter])
    if counters['error']:
        print "Completed with errors"
        sys.exit(1)
    else:
        print "Completed successfully"
        print


if __name__ == '__main__':
    parse_args()
    migrate()
