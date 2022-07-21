import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from mist.api.clouds.models import LibvirtCloud
from mist.api.machines.models import Machine


def migrate_libvirt_hypervisors():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_clouds = db['clouds']

    clouds = LibvirtCloud.objects()

    failed = migrated = skipped = 0

    for cloud in clouds:
        try:
            machines = Machine.objects(cloud=cloud, missing_since=None)
            for machine in machines:
                if machine.machine_id.replace('-', '.') == machine.hostname:
                    machine_type = "hypervisor"
                    machine.save()
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
    migrate_libvirt_hypervisors()