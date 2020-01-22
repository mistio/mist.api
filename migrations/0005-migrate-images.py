import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.poller.models import ListImagesPollingSchedule


def migrate_images():
    # first delete deprecated CloudImage objects
    # from mist.api.images.models import CloudImage
    # CloudImage.objects().delete()

    # unset image_id field from Machine
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_machines = db['machines']

    machines = Machine.objects().only('id')

    failed = migrated = 0

    print('Will try to update: ' + str(db_machines.count()))

    for machine in machines:
        try:
            print('Updating machine ' + machine['id'])
            db_machines.update_one(
                {'_id': machine['id']},
                {'$unset': {'image_id': ''}}
            )
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            print('OK')
            migrated += 1

    print('Machines migrated: ' + str(migrated))
    print('Failed to migrate: ' + str(failed))

    # unset starred field from Cloud
    db_clouds = db['clouds']

    clouds = Cloud.objects().only('id')

    failed = migrated = 0

    print('Will try to update: ' + str(db_clouds.count()))
    for cloud in clouds:
        try:
            print('Updating cloud ' + cloud['id'])
            db_clouds.update_one(
                {'_id': cloud['id']},
                {'$unset': {'starred': []}}
            )
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            print('OK')
            migrated += 1

    print('Clouds migrated: ' + str(migrated))

    c.close()

    # add ListImagesPollingSchedule objects
    print
    print('Creating and storing in database ListImagesPollingSchedule')
    print

    failed = 0
    clouds = Cloud.objects(deleted=None)

    for cloud in clouds:
        try:
            # TODO: verify that this triggers list_images()
            schedule = ListImagesPollingSchedule.add(cloud)
            schedule.set_default_interval(60 * 60 * 24)
            schedule.save()

        except Exception as exc:
            print('Error: %s') % exc
            traceback.print_exc()
            failed += 1
            continue

    print(' ****** Failures: ' + str(failed))

    # trigger list_images and list_machines to populate CloudImage RefField
    failed = 0

    print
    print('Listing images and machines to update machine.image field')
    print
    for cloud in clouds:
        print('Updating cloud ' + cloud['id'])
        try:
            cloud.ctl.compute.list_images()
            cloud.ctl.compute.list_machines()
        except Exception as exc:
            traceback.print_exc()
            failed += 1
            continue

    print('****** Failed to update: ' + str(failed))


if __name__ == '__main__':
    migrate_images()
