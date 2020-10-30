#!/usr/bin/env python

from mist.api.users.models import Organization


def migrate_rbac_images():
    ''''Add `ALLOW images * rule to team's policy'''
    try:
        from mist.rbac.models import Rule
    except ImportError:
        return  # Nothing to migrate

    orgs = Organization.objects()
    total_teams = failed = migrated = skipped = 0
    print("WIll update teams of %d organizations" % len(orgs))

    for org in orgs:
        total_teams += len(org.teams)
        for team in org.teams:
            # no need to adjust Owners team or empty policies
            if team.name != 'Owners' and team.policy.rules:
                rule = Rule()
                rule.operator = 'ALLOW'
                rule.rtype = 'image'
                rule.rtags = {}
                rule.constraints = {}
                team.policy.rules.append(rule)

                try:
                    team.save()
                    # also update the mapper
                    org.mapper.update(team=team)
                    migrated += 1
                    print('Successfully migrated team %s of Org \
                        %s' % (team.name, org.name))
                except Exception as e:
                    print(' *** WARNING *** : Failed to migrate team %s. \
                        Exception: %s' % (team.name, e))

            else:
                skipped += 1

    print('*** Successfully migrated %d teams of a total of \
        %d ***' % (migrated, total_teams))
    print('*** Skipped migrating %d teams (either Owners team or empty \
         policy ***' % skipped)
    print('*** Failed to migrate %d teams ***' % failed)


if __name__ == '__main__':
    migrate_rbac_images()
