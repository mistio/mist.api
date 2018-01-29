import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine

from mist.api.misc.cloud import CloudSize


def remove_string_field_type():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_machines = db['machines']

    machines = Machine.objects()

    print
    print 'Removing StringField size field from %d migrated machines...' % db_machines.count()
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
            print 'Error: %s' % exc
            traceback.print_exc()
            traceback.print_exc()
            failed += 1
            continue
        else:
            print 'OK'
            migrated += 1
            print 'migrated: %d' % migrated

    c.close()


def list_size_objects():
    clouds = Cloud.objects()

    print
    print 'Creating and storing in databse CloudSize objects'
    print

    size_objects = 0

    for cloud in clouds:
        sizes = cloud.ctl.compute.list_sizes()
        size_objects += len(sizes)

    print 'Created %d CloudSize objects' % size_objects


if __name__ == '__main__':
    remove_string_field_type()
    list_size_objects()
