import traceback

from mist.api.clouds.models import LinodeCloud


def migrate_linode_api_version():
    failed = migrated = 0
    clouds = LinodeCloud.objects()
    for cloud in clouds:
        try:
            cloud.apiversion = '3.0'
            cloud.save()
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
        else:
            migrated += 1
            print('OK')

    print('LinodeClouds migrated: ' + str(migrated))
    print('LinodeClouds failed to migrate: ' + str(failed))


if __name__ == '__main__':
    migrate_linode_api_version()
