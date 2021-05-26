#!/usr/bin/env python
import traceback

from mist.api.users.models import Organization


def run_update_mappings():

    failed = updated = 0
    orgs = Organization.objects()
    total = len(orgs)
    print(f'Running update_mappings on {total} organizations')

    for org in orgs:
        try:
            org.mapper.update(asynchronous=False)
        except Exception:
            print(f'update_mappings failed for org: {org.id}')
            traceback.print_exc()
            failed += 1
            continue
        else:
            print('OK')
            updated += 1

    print(f'{updated} orgs updated succesfully')
    print(f'{failed} orgs failed')


if __name__ == '__main__':
    run_update_mappings()
