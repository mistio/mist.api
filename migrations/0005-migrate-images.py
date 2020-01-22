import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from mist.api.clouds.models import Cloud
from mist.api.images.models import CloudImage
from mist.api.machines.models import Machine
from mist.api.poller.models import ListImagesPollingSchedule


def migrate_images():
    # first delete deprecated CloudImage objects
    CloudImage.objects().delete()

    # unset image_id field from Machine
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_machines = db['machines']

    machines = Machine.objects().only('id')

    print
    print 'Removing image_id field from %d migrated machines' % db_machines.count()
    print

    failed = migrated = 0

    for machine in machines:
        try:
            print 'Updating machine %s ...' % machine['id'],
            db_machines.update_one(
                {'_id': machine['id']},
                {'$unset': {'image_id': ''}}
            )
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            print 'OK'
            migrated += 1
            print 'migrated: %d' % migrated

    # unset starred field from Cloud
    db_clouds = db['clouds']

    clouds = Cloud.objects().only('id')

    print
    print 'Removing starred field from %d migrated clouds' % db_clouds.count()
    print

    failed = migrated = 0

    for cloud in clouds:
        try:
            print 'Updating cloud %s ...' % cloud['id'],
            db_machines.update_one(
                {'_id': machine['id']},
                {'$unset': {'starred': []}}
            )
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            print 'OK'
            migrated += 1
            print 'migrated: %d' % migrated

    c.close()

    # add ListImagesPollingSchedule objects
    print
    print 'Creating and storing in database ListImagesPollingSchedule'
    print

    failed = 0

    for cloud in clouds:
        try:
            # TODO: verify that this triggers list_images()
            schedule = ListImagesPollingSchedule.add(cloud)
            schedule.set_default_interval(60 * 60 * 24)
            schedule.save()

        except Exception as exc:
            print 'Error: %s' % exc
            traceback.print_exc()
            failed += 1
            continue

    print ' ****** Failures: %d *********' % failed

    # trigger list_machines to populate CloudImage RefField
    clouds = Cloud.objects(deleted=None)

    failed = 0

    print
    print 'Running list machines to update machine model with image field'
    print

    for cloud in clouds:
        try:
            cloud.ctl.compute.list_machines()
        except Exception as exc:
            print 'Error: %s' % exc
            traceback.print_exc()
            failed += 1
            continue

    print ' ****** Failures when running list_machines: %d **********' % failed


if __name__ == '__main__':
    migrate_images()
