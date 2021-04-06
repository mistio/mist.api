import traceback

from mist.api.users.models import Organization

from mist.api.poller.models import ListVaultSecretsPollingSchedule


def add_list_vault_secrets_polling_schedules():

    orgs = Organization.objects()
    failed = migrated = 0
    print('Will try to add ListVaultSecretsPollingSchedules \
        for %s organizations' % len(orgs))

    for org in orgs:
        try:
            print('Updating org %s...' % org.id)
            ListVaultSecretsPollingSchedule.add(org)
        except Exception:
            print('*** WARNING ** Could not add polling schedule \
                for org %s' % org.id)
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1

    print('Organizations migrated: ' + str(migrated))
    print('Failed to migrate: ' + str(failed))


if __name__ == '__main__':
    add_list_vault_secrets_polling_schedules()
