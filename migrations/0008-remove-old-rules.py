import traceback

from mist.api import config
from pymongo import MongoClient


def remove():
    """Remove the `rules` field from the `owner` collection"""
    try:
        conn = MongoClient(config.MONGO_URI)
        db = conn.get_database("mist2")
        result = db.owner.update_many({}, {"$unset": {"rules": ""}})
    except Exception:
        traceback.print_exc()
    else:
        print '\n%s\n' % result.raw_result
    finally:
        conn.close()


if __name__ == '__main__':
    remove()
