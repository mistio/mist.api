import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from mist.api.clouds.models import LibvirtCloud
from mist.api.machines.models import Machine


def migrate_libvirt_clouds():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_clouds = db['clouds']

    clouds = LibvirtCloud.objects()

    failed = migrated = skipped = 0

    for cloud in clouds:
        try:
            machines = Machine.objects(cloud=cloud, missing_since=None)
            images_location = db_clouds.find_one(
                {'_id': cloud['id']}).get('images_location')
            if not images_location:
                skipped += 1
                continue
            print('Updating cloud ' + cloud['id'])
            for machine in machines:
                if machine.extra.get('tags', {}).get('type') == 'hypervisor':
                    updated_extra = {
                        'images_location': images_location,
                    }
                    machine.extra.update(updated_extra)
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
            cloud.ctl.compute.list_machines()
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            print('OK')
            migrated += 1

    print('Clouds migrated: %d' % migrated)
    if skipped:
        print('Skipped: %d' % skipped)

    c.close()


if __name__ == '__main__':
    migrate_libvirt_clouds()
