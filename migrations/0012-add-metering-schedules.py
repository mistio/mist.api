import traceback

from mist.api.users.models import Organization
from mist.api.poller.models import MeteringPollingSchedule


if __name__ == '__main__':
    """Add a MeteringPollingSchedule per Organization"""
    orgs = Organization.objects()

    failed = succeeded = 0

    for org in orgs:
        try:
            MeteringPollingSchedule.add(org)
        except Exception:
            traceback.print_exc()
            failed += 1
            print '%s ... ERROR' % org
        else:
            succeeded += 1
            print '%s ... OK' % org

    print
    print 'Added: %d/%d' % (succeeded, orgs.count())
    print 'Failed: %d' % failed
    print
    print 'Completed %s' % ('with errors!' if failed else 'successfully!')
    print
