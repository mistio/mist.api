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

    failed = migrated = 0

    for cloud in clouds:
        try:
            machines = Machine.objects(cloud=cloud, missing_since=None)
            print('Updating cloud ' + cloud['id'])
            for machine in machines:
                if machine.machine_type == 'hypervisor' and \
                   (machine.id not in cloud.hosts):
                    cloud.hosts.append(machine.id)
            cloud.save()
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            print('OK')
            migrated += 1

    print(f'Libvirt clouds with host field populated: {migrated}'
          f', out of total {len(clouds)} Libvirt clouds')

    c.close()


if __name__ == '__main__':
    migrate_libvirt_clouds()
