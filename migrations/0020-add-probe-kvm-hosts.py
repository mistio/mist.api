import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI
from mist.api.models import Machine
from mist.api.clouds.models import LibvirtCloud
from mist.api.poller.models import SSHProbeMachinePollingSchedule


def add_ssh_probe_kvm_hosts():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_clouds = db['clouds']

    clouds = LibvirtCloud.objects(deleted=None)

    failed = 0
    migrated = 0

    for cloud in clouds:
        for id in cloud.hosts:
            try:
                host = Machine.objects.get(id=id)
                SSHProbeMachinePollingSchedule.add(host,
                                                   interval=86400)
            except Exception:
                traceback.print_exc()
                failed += 1
                continue
            else:
                print(f'Added probe to host: {host.name} with id: {host.id} .')
                migrated += 1

    print(f'Hosts migrated: {migrated}. Failed attempts: {failed}.')
    c.close()


if __name__ == '__main__':
    add_ssh_probe_kvm_hosts()
