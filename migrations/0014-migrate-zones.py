import traceback

from mist.api.clouds.models import Cloud

from mist.api.poller.models import ListZonesPollingSchedule


def trigger_zone_polling_schedules():
    clouds = Cloud.objects(deleted=None)

    print
    print 'Creating and storing in database ListZonesPollingSchedule'
    print

    failed = 0

    for cloud in clouds:
        if not hasattr(cloud.ctl, 'dns') or not clout.dns_enabled:
            continue
        try:
            ListZonesPollingSchedule.add(cloud)
        except Exception:
            traceback.print_exc()
            failed += 1

    print ' ****** Failures: %d *********' % failed


if __name__ == '__main__':
    trigger_zone_polling_schedules()
