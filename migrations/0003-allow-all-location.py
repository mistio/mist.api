#!/usr/bin/env python

import sys

from mist.rbac.models import Rule

from mist.api.users.models import Organization


def migrate(purge=False):
    error = False
    teams_total = 0
    orgs = Organization.objects()
    print("Found %d organizations." % len(orgs))
    for org in orgs:
        teams_total += len(org.teams)

    non_owner_teams = teams_total - len(orgs)
    print("Will add `ALLOW * ON location` in %d policies." % (non_owner_teams))

    counters = {'updated': 0, 'error': 0, 'skipped': 0}

    for org in orgs:
        for team in org.teams:
            if team.name != 'Owners':
                rule = Rule()
                rule.operator = 'ALLOW'
                rule.rtype = 'location'
                rule.clean()
                team.policy.rules.append(rule)
                try:
                    team.save()
                except Exception:
                    counters['error'] += 1
                else:
                    counters['updated'] += 1
            else:
                counters['skipped'] += 1

    for counter in counters:
        print("Policies %s: %d" % (counter, counters[counter]))
    if counters['error']:
        print("Completed with errors")
        error = True
    else:
        print("Completed successfully")

    if error:
        print("Exiting with errors!")
        sys.exit(1)
    print("Exiting successfully!")
    sys.exit(0)


if __name__ == '__main__':
    migrate()
