import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI


def migrate_packet_clouds():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_clouds = db['clouds']

    query = {"_cls": "Cloud.PacketCloud"}
    value = {'$set': {'_cls': "Cloud.EquinixMetalCloud"}}
    try:
        db_clouds.update_many(query, value)
    except Exception:
        traceback.print_exc()
    else:
        print('OK')


if __name__ == '__main__':
    migrate_packet_clouds()
