import sys
import traceback

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.users.models import Organization
from mist.api.rules.models import MachineMetricRule


def migrate_rules():
    """Migrate all non-migrated rules."""
    failed = 0
    migrated = 0

    # If the migration has already been applied, then `rules` will
    # not exist on Organization.
    if 'rules' not in Organization._fields:
        orgs = []
    else:
        orgs = Organization.objects(rules__nin=[{}, None])

    for o in orgs:
        for rule_id, rule in o.rules.iteritems():
            try:
                if rule.migrated:
                    continue
                print "Migrating %s of %s" % (rule_id, o),
                migrate_old_rule(o, rule_id, rule)
            except KeyboardInterrupt:
                failed += 1
                break
            except (Cloud.DoesNotExist, Machine.DoesNotExist) as err:
                print "ERROR", str(err)
                failed += 1
            except Exception:
                failed += 1
                print
                traceback.print_exc()
                print
            else:
                rule.migrated = True
                rule.save()
                migrated += 1
                print "OK"
        else:
            continue
        break

    print
    print "Migrated:", migrated
    print "Failed:", failed


def migrate_old_rule(owner, rule_id, old_rule):
    """Migrate a single rule."""
    kwargs = prepare_kwargs(owner, old_rule)
    rule = MachineMetricRule.add(owner_id=owner.id, title=rule_id, **kwargs)
    verify(old_rule, rule_id, rule)


def prepare_kwargs(owner, old_rule):
    """Prepare the rule's parameters."""
    cloud = Cloud.objects.get(id=old_rule.cloud, owner=owner)
    machine = Machine.objects.get(cloud=cloud, machine_id=old_rule.machine)
    kwargs = {
        'queries': [{
            'target': old_rule.metric,
            'operator': old_rule.operator,
            'threshold': old_rule.value,
            'aggregation': old_rule.aggregate,
        }],
        'window': {
            'start': old_rule.reminder_offset + 60,
            'period': 'seconds',
        },
        'frequency': {
            'every': old_rule.reminder_offset + 60,
            'period': 'seconds',
        },
        'actions': [
            {
                'type': 'notification',
                'emails': old_rule.emails or [],
            },
        ],
        'conditions': [
            {
                'type': 'machines',
                'ids': [machine.id],
            },
        ],
    }
    if old_rule.action == 'command':
        kwargs['actions'].append({'type': 'command',
                                  'command': old_rule.command})
    elif old_rule.action in ('reboot', 'destroy', ):
        kwargs['actions'].append({'type': 'machine_action',
                                  'action': old_rule.action})
    return kwargs


def verify(old_rule, rule_id, new_rule):
    """Ensure backwards compatibility. Exit immediately, if it fails."""
    try:
        assert rule_id == new_rule.rule_id, 'rule_id'
        assert old_rule.metric == new_rule.metric, 'metric'
        assert old_rule.operator == new_rule.operator, 'operator'
        assert old_rule.value == new_rule.value, 'value'
        assert old_rule.aggregate == new_rule.aggregate, 'aggregate'
        assert old_rule.reminder_offset == new_rule.reminder_offset, 'offset'
        assert old_rule.machine == new_rule.machine, 'machine'
        assert old_rule.cloud == new_rule.cloud, 'cloud'
        assert old_rule.action == new_rule.action, 'action'
        assert old_rule.emails == new_rule.emails, 'emails'
        if old_rule.action == 'command':
            assert (old_rule.command or '') == new_rule.command, 'command'
    except AssertionError as err:
        print "Failed to verify %s: %r" % (new_rule, err)
        new_rule.delete()
        sys.exit(1)


if __name__ == '__main__':
    migrate_rules()
