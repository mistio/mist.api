import traceback

from mist.api.clouds.models import Cloud

from mist.api.poller.models import ListNetworksPollingSchedule


def trigger_network_polling_schedules():
    clouds = Cloud.objects(deleted=None)

    print
    print 'Creating and storing in database ListNetworksPollingSchedule'
    print

    failed = 0

    for cloud in clouds:
        if not hasattr(cloud.ctl, 'network'):
            continue
        try:
            ListNetworksPollingSchedule.add(cloud)
        except Exception:
            traceback.print_exc()
            failed += 1

    print ' ****** Failures: %d *********' % failed


if __name__ == '__main__':
    trigger_network_polling_schedules()
