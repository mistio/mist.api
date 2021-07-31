import traceback

from pymongo.helpers import DuplicateKeyError

from mist.api.clouds.models import LibvirtCloud
from mist.api.machines.models import Machine


def migrate_libvirt_clouds():

    try:
        clouds = LibvirtCloud.objects()
    except DuplicateKeyError:
        import importlib.machinery
        loader = importlib.machinery.SourceFileLoader(
            'cloud-title-migration',
            '/mist.api/migrations/0016-migrate-cloud-title.py')
        loader.load_module('cloud-title-migration').migrate_clouds()
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


if __name__ == '__main__':
    migrate_libvirt_clouds()
