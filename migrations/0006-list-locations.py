import traceback

from mist.api.clouds.models import Cloud
from mist.api.poller.models import ListLocationsPollingSchedule


def trigger_location_polling_schedules():
    clouds = Cloud.objects(deleted=None)

    print
    print 'Creating and storing in database ListLocationsPollingSchedules'
    print

    failed = 0

    for cloud in clouds:
        try:
            ListLocationsPollingSchedule.add(cloud)
        except Exception as exc:
            print 'Error: %s' % exc
            traceback.print_exc()
            failed += 1
            continue

    print ' ****** Failures: %d *********' % failed


if __name__ == '__main__':
    trigger_location_polling_schedules()
