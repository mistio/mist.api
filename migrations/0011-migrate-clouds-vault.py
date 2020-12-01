import traceback
import mongoengine as me

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from mist.api.secrets.models import VaultSecret
from mist.api.users.models import Owner

from mist.api.clouds.models import *  # noqa


def migrate_clouds():

    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_clouds = db['clouds']
    failed = migrated = 0
    print('Will try to update %s clouds' % str(db_clouds.count()))
    for cloud in db_clouds.find():
        try:
            print('Updating cloud %s (%s)' % (cloud['_id'], cloud['title']))
            owner = Owner.objects.get(id=cloud['owner'])

            private_fields = getattr(eval(cloud['_cls'].split('.')[1]),
                                     '_private_fields')
            for private_field in private_fields:
                try:
                    secret = VaultSecret.objects.get(name="clouds/%s" %
                                                     cloud['title'],
                                                     owner=owner)
                except me.DoesNotExist:
                    secret = VaultSecret(name="clouds/%s" % cloud['title'],
                                         owner=owner)
                    secret.save()

                # update_one in clouds collection
                secret_value = {
                    "secret": secret.id,
                    "key": private_field
                }

                db_clouds.update_one(
                    {'_id': cloud['_id']},
                    {'$set': {private_field: secret_value}}
                )

                # save to vault only if the private_field is set
                if cloud[private_field]:
                    secret_dict = {
                        private_field: cloud[private_field]
                    }

                    secret.ctl.create_or_update_secret(owner.name, secret_dict)
        except Exception:
            print('*** WARNING ** Could not migrate cloud %s' % cloud['_id'])
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1

    print('Clouds migrated: ' + str(migrated))
    print('Failed to migrate: ' + str(failed))


if __name__ == '__main__':
    migrate_clouds()
