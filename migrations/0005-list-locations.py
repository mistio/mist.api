import traceback

from mist.api.clouds.models import Cloud


def trigger_list_locations():
    clouds = Cloud.objects()

    print
    print 'Creating and storing in database CloudLocation objects'
    print

    failed = 0

    for cloud in clouds:
        try:
            locations = cloud.ctl.compute.list_locations()
        except Exception as exc:
            print 'Error: %s' % exc
            traceback.print_exc()
            traceback.print_exc()
            failed += 1
            continue

    print ' ********* Failures when running list_locations: %d *************' % failed


def trigger_list_machines():
    clouds = Cloud.objects()

    failed = 0

    print
    print 'Running list machines to update machine model with location field'
    print

    for cloud in clouds:
        try:
            cloud.ctl.compute.list_machines()
        except Exception as exc:
            print 'Error: %s' % exc
            traceback.print_exc()
            traceback.print_exc()
            failed += 1
            continue

    print ' ********* Failures when running list_machines: %d *************' % failed

if __name__ == '__main__':
    trigger_list_locations()
    trigger_list_machines()
