import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine

from mist.api.poller.models import ListSizesPollingSchedule


def trigger_size_polling_schedules():
    clouds = Cloud.objects(deleted=None)

    print
    print 'Creating and storing in database ListSizesPollingSchedule'
    print

    failed = 0

    for cloud in clouds:
        try:
            schedule = ListSizesPollingSchedule.add(cloud)
            schedule.set_default_interval(60 * 60 * 24)
            schedule.save()

        except Exception as exc:
            print 'Error: %s' % exc
            traceback.print_exc()
            failed += 1
            continue

    print ' ****** Failures: %d *********' % failed


def remove_string_field_type():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_machines = db['machines']

    machines = Machine.objects().only('id')

    print
    print 'Removing size field from %d migrated machines' % db_machines.count()
    print

    failed = migrated = 0

    for machine in machines:
        try:
            print 'Updating machine %s ...' % machine['id'],
            db_machines.update_one(
                {'_id': machine['id']},
                {'$unset': {'size': ''}}
            )
        except Exception as exc:
            traceback.print_exc()
            failed += 1
            continue
        else:
            print 'OK'
            migrated += 1
            print 'migrated: %d' % migrated

    c.close()


if __name__ == '__main__':
    trigger_size_polling_schedules()
    remove_string_field_type()
