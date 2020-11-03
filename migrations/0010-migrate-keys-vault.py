import traceback

from pymongo import MongoClient
from mist.api.config import MONGO_URI

from mist.api.secrets.models import VaultSecret
from mist.api.users.models import Owner


def migrate_keys():

    c = MongoClient(MONGO_URI)
    db = c.get_database('mist2')
    db_keys = db['keys']
    failed = migrated = 0
    print('Will try to update %s keys' % str(db_keys.count()))

    for key in db_keys.find():
        try:
            print('Updating key ' + key['_id'])
            private = key['private']
            owner = Owner.objects.get(id=key['owner'])

            # insert new secret in secrets collection
            secret = VaultSecret(name=key["name"], owner=owner)
            secret.save()
            # store secret in Vault
            secret_dict = {
                'private': private
            }
            secret.ctl.create_or_update_secret(owner.name, secret_dict)

            # update_one in keys collection
            # secret_value = SecretValue(secret=secret, key='private')
            secret_value = {
                "secret": secret.id,
                "key": "private"
            }

            db_keys.update_one(
                {'_id': key['_id']},
                {'$set': {'private': secret_value}}
            )
        except Exception:
            print('*** WARNING ** Could not migrate key %s' % key['_id'])
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1

    print('Keys migrated: ' + str(migrated))
    print('Failed to migrate: ' + str(failed))


if __name__ == '__main__':
    migrate_keys()
