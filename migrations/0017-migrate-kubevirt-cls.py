#!/usr/bin/env python
from pymongo import MongoClient
from mist.api.config import MONGO_URI


def migrate_kubevirt_clouds():
    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_clouds = db['clouds']

    try:
        db_clouds.update_many(
            {"_cls": "Cloud.KubeVirtCloud"},
            {"$set": {"_cls": "Cloud._KubernetesBaseCloud.KubeVirtCloud"}}
        )
        print('OK')
    except Exception as e:
        print(' ****** KubeVirt migration failed: %r', e)


if __name__ == '__main__':
    migrate_kubevirt_clouds()
