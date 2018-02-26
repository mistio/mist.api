import traceback
from pymongo import MongoClient
from mist.api.config import MONGO_URI

from mist.api.clouds.models import CloudLocation


def remove_missing_since_field():

    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_locations = db['locations']

    locations = CloudLocation.objects()

    print
    print 'Removing unnecessary missing_since field from CloudLocation model'
    print

    failed = 0

    for location in locations:
        try:
            db_locations.update_one(
                {'_id': location['id']},
                {'$unset': {'missing_since': ''}}
            )
        except Exception as exc:
            print 'Error: %s' % exc
            traceback.print_exc()
            traceback.print_exc()
            continue

    print ' ****** Failures: %d *********' % failed

    c.close()


if __name__ == '__main__':
    remove_missing_since_field()
