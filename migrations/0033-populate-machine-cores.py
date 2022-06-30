#!/usr/bin/env python

import datetime

from mist.api.models import Organization, Machine
from mist.api.poller.models import FindCoresMachinePollingSchedule
from mist.api.metering.tasks import find_machine_cores


def delete_find_cores_machine_polling_schedule():
    deleted_schedules = FindCoresMachinePollingSchedule.objects().delete()
    print(f"Deleted {deleted_schedules} FindCoresMachinePollingSchedules")


def send_find_machine_cores_tasks():
    timedelta = datetime.timedelta(days=30)
    migrated_machines = 0
    for organization in Organization.objects(last_active__gt=datetime.datetime.now() - timedelta):  # noqa
        for machine in Machine.objects(owner=organization, missing_since=None, machine_type__nin=["container", "pod"]):  # noqa
            find_machine_cores.send(machine.id)
            migrated_machines += 1

    print(f"Sent find_machine_cores task for {migrated_machines} machines")


if __name__ == '__main__':
    delete_find_cores_machine_polling_schedule()
    send_find_machine_cores_tasks()
