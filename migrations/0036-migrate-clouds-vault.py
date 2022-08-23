import traceback
import mongoengine as me

from pymongo import MongoClient
from mongoengine.fields import EmbeddedDocumentField

from mist.api import config

from mist.api.secrets.models import VaultSecret, SecretValue
from mist.api.users.models import Owner

from mist.api.clouds.models import *  # noqa


def migrate_clouds():

    c = MongoClient(config.MONGO_URI)
    db = c.get_database('mist2')
    db_clouds = db['clouds']
    failed = migrated = skipped = 0
    print('Will try to update %s clouds' % str(db_clouds.count()))
    for cloud in db_clouds.find():
        skipped_all = True
        try:
            print('Updating cloud %s (%s)' % (cloud['_id'], cloud['name']))
            owner = Owner.objects.get(id=cloud['owner'])

            fields = getattr(eval(cloud['_cls'].split('.')[1]),
                             '_fields')
            for field in fields:
                # Skip fields that are not references to secrets
                if not (isinstance(fields[field], EmbeddedDocumentField) and
                        fields[field].document_type is SecretValue):
                    continue

                if cloud.get(field) is None or (
                        isinstance(cloud[field], dict) and
                        cloud[field].get('secret')):
                    continue
                else:
                    skipped_all = False

                name = f"{config.VAULT_CLOUDS_PATH}{cloud['name']}"
                try:
                    secret = VaultSecret.objects.get(name=name,
                                                     owner=owner)
                except me.DoesNotExist:
                    secret = VaultSecret(name=name,
                                         owner=owner)
                    secret.save()

                # update_one in clouds collection
                secret_value = {
                    "secret": secret.id,
                    "key": field
                }

                db_clouds.update_one(
                    {'_id': cloud['_id']},
                    {'$set': {field: secret_value}}
                )

                # save to vault only if the field is set
                if cloud.get(field, None):
                    secret_dict = {
                        field: cloud[field]
                    }
                    secret.create_or_update(secret_dict)
        except Exception:
            print('*** WARNING ** Could not migrate cloud %s' % cloud['_id'])
            traceback.print_exc()
            failed += 1
            continue
        else:
            if skipped_all:
                skipped += 1
                print('Skipped')
            else:
                migrated += 1

    print('Clouds migrated: ' + str(migrated))
    print('Clouds skipped: ' + str(skipped))
    print('Failed to migrate: ' + str(failed))


if __name__ == '__main__':
    migrate_clouds()
