import traceback

from mist.api.users.models import Organization
from mist.api.secrets.methods import generate_secrets_engine_path
from mist.api import config


def migrate_organizations():

    orgs = Organization.objects()
    failed = migrated = skipped = 0
    print('Will try to update %s organizations' % len(orgs))

    for org in orgs:
        if org.vault_secret_engine_path:
            print(f'Skipping org {org.id}, vault secret engine path exists')
            skipped += 1
            continue
        try:
            print('Updating org %s...' % org.id)
            try:
                secret_engine_path = config.VAULT_SECRET_ENGINE_PATHS[org.name]
            except (KeyError, AttributeError):
                secret_engine_path = generate_secrets_engine_path(org.name)

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
    print(f'Organizations skipped: {skipped}')


if __name__ == '__main__':
    migrate_organizations()
