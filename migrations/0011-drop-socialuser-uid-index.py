import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI


def drop_socialuser_uid_index():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_social_users = db['social_auth_user']

    try:
        db_social_users.drop_index("uid_1")
    except Exception:
        traceback.print_exc()
    else:
        print('OK')


if __name__ == '__main__':
    drop_socialuser_uid_index()
