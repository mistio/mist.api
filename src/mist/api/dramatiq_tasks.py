import time
import logging

import mongoengine as me
import dramatiq

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.auth.methods import AuthContext
# from mist.api.exceptions import MachineCreationError
from mist.api.dramatiq_app import broker

log = logging.getLogger(__name__)


@dramatiq.actor(queue_name='dramatiq_create_machine', broker=broker)
def dramatiq_create_machine_async(auth_context_serialized, plan):
    auth_context = AuthContext.deserialize(auth_context_serialized)
    cloud = Cloud.objects.get(id=plan['cloud'])

    node = cloud.ctl.compute.create_machine(plan)
    for i in range(0, 10):
        try:
            machine = Machine.objects.get(cloud=cloud, machine_id=node.id)
            break
        except me.DoesNotExist:
            if i < 6:
                time.sleep(i * 10)
                continue
            try:
                cloud.ctl.compute._list_machines()
            except Exception as e:
                if i > 8:
                    raise(e)
                else:
                    continue

    machine.assign_to(auth_context.user)
