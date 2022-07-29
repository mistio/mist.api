import traceback
from datetime import datetime, timedelta


def add_machine_probes():
    # machines should meet the following criteria:
    # should not be missing
    # their cloud should not be deleted or disabled
    # should have at least 1 key association
    # should not have a schedule already
    # org of cloud was active in the last 6 months

    # date 183 days ago ~ 6 months
    date_6_months_ago = datetime.now() - timedelta(days=183)

    from mist.api.models import Machine, Cloud, Organization
    from mist.api.poller.models import SSHProbeMachinePollingSchedule
    from mist.api.machines.models import KeyMachineAssociation
    from mist.api.config import MACHINE_SSH_PROBE_INTERVAL

    machines = Machine.objects(
        missing_since=None,
        cloud__in=Cloud.objects(
            deleted=None,
            enabled=True,
            owner__in=Organization.objects(
                last_active__gt=date_6_months_ago))
    )
    total = len(machines)
    migrated = 0
    skipped = 0
    failed = 0

    for machine in machines:
        try:
            # remove any old schedule
            SSHProbeMachinePollingSchedule.objects(
                machine_id=machine.id).delete()

            # check for keys
            if KeyMachineAssociation.objects(machine=machine).count() == 0:
                skipped += 1
                continue

            # add schedule
            SSHProbeMachinePollingSchedule.add(
                machine=machine,
                interval=MACHINE_SSH_PROBE_INTERVAL
            )
            migrated += 1
        except Exception:
            traceback.print_exc()
            failed += 1
            continue
    print(f'Out of {total} total machines:\n'
          f'Skipped: {skipped} machines without a key.\n'
          f'Failed: {failed} machines\n'
          f'Migrated: {migrated} machines successfully'
          )


if __name__ == "__main__":
    add_machine_probes()
