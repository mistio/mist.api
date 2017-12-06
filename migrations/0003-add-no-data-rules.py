import traceback

from mist.api.users.models import Organization
from mist.api.rules.models.main import NoDataRule


def nodata():
    """Ensure a NoDataRule is active per Organization."""
    failed = skipped = succeeded = 0

    orgs = Organization.objects()

    for org in orgs:
        try:
            if org.count_mon_machines():
                try:
                    NoDataRule.objects.get(owner_id=org.id, title='NoData')
                except NoDataRule.DoesNotExist:
                    rule = NoDataRule(owner_id=org.id)
                    rule.ctl.auto_setup()
                    succeeded += 1
                    print '%s ... OK' % org
                else:
                    skipped += 1
            else:
                skipped += 1
        except Exception:
            traceback.print_exc()
            failed += 1
            print '%s ... ERROR' % org

    print
    print 'Enabled: %d/%d' % (succeeded, orgs.count())
    print 'Skipped: %d' % (orgs.count() - succeeded - failed)
    print 'Failed: %d' % failed
    print
    print 'Completed %s' % ('with errors!' if failed else 'successfully!')
    print


if __name__ == '__main__':
    nodata()
