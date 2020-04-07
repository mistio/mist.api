import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from mist.api.clouds.models import LibvirtCloud
from mist.api.machines.models import Machine


def migrate_libvirt_clouds():
    # unset image_id field from Machine
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_clouds = db['clouds']

    clouds = LibvirtCloud.objects()

    failed = migrated = 0

    for cloud in clouds:
        try:
            print('Updating cloud ' + cloud['id'])
            machines = Machine.objects(cloud=cloud, missing_since=None)
            for machine in machines:
                if machine.extra.get('tags', {}).get('type') == 'hypervisor':
                    machine.extra.update({'images_location':
                                          cloud.images_location})
                    machine.save()
                    break

            db_clouds.update_one(
                {'_id': cloud['id']},
                {'$unset': {'host': '',
                            'username': '',
                            'port': '',
                            'key': '',
                            'images_location': ''}}
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


def trigger_list_machines():
    clouds = LibvirtCloud.objects()

    failed = 0

    print('Listing  machines...')
    print
    for cloud in clouds:
        print('Updating cloud ' + cloud['id'])
        try:
            cloud.ctl.compute.list_machines()
        except Exception:
            traceback.print_exc()
            failed += 1
            continue

    print('****** Failed to update: ' + str(failed))


if __name__ == '__main__':
    migrate_libvirt_clouds()
    # trigger_list_machines()
