import traceback

from mist.api.users.models import Organization
from mist.api import config


def migrate_organizations():

    orgs = Organization.objects()
    failed = migrated = 0
    print('Will try to update %s organizations' % len(orgs))

    for org in orgs:
        try:
            print('Updating org %s...' % org.id)
            secret_engine_path = config.VAULT_SECRET_ENGINE_PATHS[org.name] \
                if org.name in config.VAULT_SECRET_ENGINE_PATHS else org.name
            org.vault_secret_engine_path = secret_engine_path
            org.save()
        except Exception:
            print('*** WARNING ** Could not migrate org %s' % org.id)
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1

    print('Organizations migrated: ' + str(migrated))
    print('Failed to migrate: ' + str(failed))


if __name__ == '__main__':
    migrate_organizations()
