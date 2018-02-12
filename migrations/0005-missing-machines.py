import traceback

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine


def set_missing():
    """Declare machines, whose cloud has been marked as deleted, as missing"""
    failed = succeeded = 0
    clouds = Cloud.objects(deleted__ne=None)

    print
    print 'Searching through %d clouds' % clouds.count()
    print

    for c in clouds:
        try:
            print 'Updating machines of', c,
            updated = Machine.objects(
                cloud=c, missing_since=None).update(missing_since=c.deleted)
        except Exception:
            print '[ERROR]'
            traceback.print_exc()
            failed += 1
        else:
            print '[OK:%s]' % updated
            succeeded += 1

    print
    print 'Failed:', failed
    print 'Succeeded:', succeeded
    print
    print 'Completed %s' % ('with errors!' if failed else 'successfully!')
    print


if __name__ == '__main__':
    set_missing()
