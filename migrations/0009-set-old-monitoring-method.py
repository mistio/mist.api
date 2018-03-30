#!/usr/bin/env python

import argparse

from mist.api import config
from mist.api.machines.models import Machine


def parse_args():
    argparser = argparse.ArgumentParser(
        description="Set all machines' monitoring method.")
    argparser.add_argument('method', choices=config.MONITORING_METHODS,
                           help="Monitoring method to set.")
    return argparser.parse_args()


def main(method):
    qs = Machine.objects(monitoring__method__ne=method)
    print("%d machines found with monitoring.method != '%s'" % (qs.count(),
                                                                method))
    qs.update(monitoring__method=method)


if __name__ == '__main__':
    main(parse_args().method)
