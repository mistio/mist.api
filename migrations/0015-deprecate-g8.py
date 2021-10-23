#!/usr/bin/env python
from mist.api.models import Machine, Network, Volume


def remove_deprecated_clouds():
    try:
        from mist.api.clouds.deprecated.models import GigG8Cloud, VCloud
    except ImportError:
        return

    failed = updated = 0
    g8clouds = GigG8Cloud.objects()
    vclouds = VCloud.objects()
    total = len(g8clouds) + len(vclouds)
    if not total:
        return
    print(f'Removing {total} clouds')

    for clouds in [g8clouds, vclouds]:
        for cloud in clouds:
            try:
                Machine.objects(cloud=cloud).delete()
                Network.objects(cloud=cloud).delete()
                Volume.objects(cloud=cloud).delete()
                cloud.delete()
                updated += 1
                print('OK')
            except Exception as e:
                failed += 1
                print('Delete cloud %s (%s) failed: %r' % (
                    cloud.id, cloud.name, e))

    print(f'{updated} clouds deleted succesfully')
    print(f'{failed} clouds failed')


if __name__ == '__main__':
    remove_deprecated_clouds()
