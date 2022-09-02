import logging
import datetime

import jsonpatch

from random import randrange

from mist.api import config
from mist.api.helpers import amqp_publish_user
from mist.api.exceptions import MachineUnavailableError
from mist.api.concurrency.models import PeriodicTaskInfo

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)


def override_polling_schedule(func):
    def wrapper(*args, **kwargs):
        from mist.api.poller.models import ListMachinesPollingSchedule
        self = args[0]
        cloud = self.machine.cloud
        retval = func(*args, **kwargs)
        log.info('Overriding default polling interval')
        schedule = ListMachinesPollingSchedule.objects.get(cloud=cloud.id)
        schedule.add_interval(10, ttl=600)
        schedule.save()
        return retval
    return wrapper


class MachineController(object):
    def __init__(self, machine):
        """Initialize machine controller given a machine

        Most times one is expected to access a controller from inside the
        machine, like this:

          machine = mist.api.machines.models.Machine.objects.get(id=machine_id)
          machine.cloud.ctl.compute.reboot()
        """

        self.machine = machine

    @override_polling_schedule
    def start(self):
        return self.machine.cloud.ctl.compute.start_machine(self.machine)

    @override_polling_schedule
    def stop(self):
        return self.machine.cloud.ctl.compute.stop_machine(self.machine)

    @override_polling_schedule
    def suspend(self):
        """Suspends machine - used in KVM libvirt to pause machine"""
        return self.machine.cloud.ctl.compute.suspend_machine(self.machine)

    @override_polling_schedule
    def resume(self):
        """Resumes machine - used in KVM libvirt to resume suspended machine"""
        return self.machine.cloud.ctl.compute.resume_machine(self.machine)

    @override_polling_schedule
    def reboot(self):
        return self.machine.cloud.ctl.compute.reboot_machine(self.machine)

    @override_polling_schedule
    def destroy(self):
        return self.machine.cloud.ctl.compute.destroy_machine(self.machine)

    @override_polling_schedule
    def remove(self):
        return self.machine.cloud.ctl.compute.remove_machine(self.machine)

    @override_polling_schedule
    def resize(self, size_id, kwargs):
        """Resize a machine on an other plan."""
        return self.machine.cloud.ctl.compute.resize_machine(self.machine,
                                                             size_id, kwargs)

    def rename(self, name):
        """Renames a machine on a certain cloud."""
        return self.machine.cloud.ctl.compute.rename_machine(self.machine,
                                                             name)

    def expose(self, port_forwards):
        """Exposes a machine's port to a public one"""
        return self.machine.cloud.ctl.compute.expose_port(self.machine,
                                                          port_forwards)

    def power_cycle(self):
        return self.machine.cloud.ctl.compute.power_cycle_machine(self.machine)

    # TODO we want this also ?
    # def tag(self):
    #     return self.machine.cloud.ctl.compute.tag(self.machine)

    def list_snapshots(self):
        """List machine snapshots - used in vSphere"""
        return self.machine.cloud.ctl.compute.list_machine_snapshots(
            self.machine)

    def create_snapshot(self, snapshot_name, description='',
                        dump_memory=False, quiesce=False):
        """Creates a snapshot for machine - used in vSphere"""
        return self.machine.cloud.ctl.compute.create_machine_snapshot(
            self.machine, snapshot_name, description, dump_memory, quiesce)

    def remove_snapshot(self, snapshot_name=None):
        """
        Removes a machine snapshot - used in vSphere
        If snapshot_name is None then removes the last one
        """
        return self.machine.cloud.ctl.compute.remove_machine_snapshot(
            self.machine, snapshot_name)

    def revert_to_snapshot(self, snapshot_name=None):
        """
        Reverts a machine to a specific snapshot - used in vSphere
        If snapshot_name is None then reverts to the last one
        """
        return self.machine.cloud.ctl.compute.revert_machine_to_snapshot(
            self.machine, snapshot_name)

    @override_polling_schedule
    def undefine(self, delete_domain_image=False):
        """Undefines machine - used in KVM libvirt
        to destroy machine and delete XML conf"""
        return self.machine.cloud.ctl.compute.undefine_machine(
            self.machine,
            delete_domain_image=delete_domain_image)

    @override_polling_schedule
    def clone(self, name=None):
        """
        Clones machine - used in KVM libvirt and vSphere
        """
        return self.machine.cloud.ctl.compute.clone_machine(self.machine,
                                                            name=name)

    def associate_key(self, key, username=None, port=22, no_connect=False):
        """Associate an sshkey with a machine"""
        return key.ctl.associate(self.machine, username=username,
                                 port=port, no_connect=no_connect)

    def get_host(self):
        if self.machine.hostname:
            return self.machine.hostname
        if self.machine.public_ips:
            return self.machine.public_ips[0]
        if self.machine.private_ips:
            return self.machine.private_ips[0]
        raise MachineUnavailableError("Couldn't find machine host.")

    def update(self, auth_context, params={}):
        if params.get('expiration'):
            """
            FIXME: we're recreating instead of updating existing expiration
                   schedules because updating them doesn't seem to affect the
                   actual expiration datetime.
            """
            from mist.api.schedules.models import Schedule
            exp_date = params['expiration']['date']
            exp_reminder = int(params['expiration'].get('notify', 0) or 0)
            exp_action = params['expiration'].get('action', 'stop')
            assert exp_action in ['stop', 'destroy'], 'Invalid action'
            if self.machine.expiration:  # Existing expiration schedule
                # Delete after removing db ref
                sched = self.machine.expiration
                self.machine.expiration = None
                self.machine.save()
                sched.delete()

            if exp_date:  # Create new expiration schedule
                params = {
                    'description': 'Scheduled to run when machine expires',
                    'task_enabled': True,
                    'schedule_type': 'one_off',
                    'schedule_entry': exp_date,
                    'action': exp_action,
                    'selectors': [
                        {'type': 'machines', 'ids': [self.machine.id]}
                    ],
                    'notify': exp_reminder
                }
                name = self.machine.name + '-expiration-' + str(
                    randrange(1000))
                self.machine.expiration = Schedule.add(auth_context, name,
                                                       **params)
                self.machine.save()

            # Prepare exp date JSON patch to update the UI
            if not self.machine.expiration:
                patch = [{
                    'op': 'remove',
                    'path': '/%s-%s/expiration' % (
                        self.machine.id, self.machine.external_id)
                }]
            else:
                patch = [{
                    'op': 'replace',
                    'path': '/%s-%s/expiration' % (
                        self.machine.id, self.machine.external_id),
                    'value': not self.machine.expiration and None or {
                        'id': self.machine.expiration.id,
                        'date': self.machine.expiration.when.entry,
                        'action': self.machine.expiration.actions[0].action,
                        'notify': self.machine.expiration.reminder and int((
                            self.machine.expiration.when.entry -
                            self.machine.expiration.reminder.when.
                            entry
                        ).total_seconds()) or 0
                    }
                }]
            # Publish patches to rabbitmq.
            amqp_publish_user(self.machine.cloud.owner.id,
                              routing_key='patch_machines',
                              data={'cloud_id': self.machine.cloud.id,
                                    'patch': patch})

        return self.machine

    def ping_probe(self, persist=True):
        if not self.machine.cloud.enabled:
            return False
        from mist.api.methods import ping
        from mist.api.machines.models import PingProbe

        def _get_probe_dict():
            data = {}
            if self.machine.ping_probe is not None:
                data = self.machine.ping_probe.as_dict()
            return {
                '%s-%s' % (self.machine.id, self.machine.external_id): {
                    'probe': {
                        'ping': data
                    }
                }
            }

        try:
            host = self.machine.ctl.get_host()
            if host in ['localhost', '127.0.0.1']:
                return
        except RuntimeError:
            return

        old_probe_data = _get_probe_dict()

        task_key = 'machine:ping_probe:%s' % self.machine.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        with task.task_runner(persist=persist):
            try:
                data = ping(self.machine.cloud.owner, self.get_host())
            except:
                probe = self.machine.ping_probe
                if probe is not None:
                    probe.unreachable_since = datetime.datetime.now()
                raise
            else:
                probe = PingProbe()
                probe.update_from_dict(data)
            finally:
                self.machine.ping_probe = probe
                self.machine.save()
                new_probe_data = _get_probe_dict()
                patch = jsonpatch.JsonPatch.from_diff(old_probe_data,
                                                      new_probe_data).patch
                if patch:
                    amqp_publish_user(self.machine.cloud.owner.id,
                                      routing_key='patch_machines',
                                      data={'cloud_id': self.machine.cloud.id,
                                            'patch': patch})
        probe_result = self.machine.ping_probe
        return probe_result and probe_result.as_dict()

    def ssh_probe(self, persist=True):
        if not self.machine.cloud.enabled:
            return False
        from mist.api.methods import probe_ssh_only
        from mist.api.machines.models import SSHProbe

        def _get_probe_dict():
            data = {}
            if self.machine.ssh_probe is not None:
                data = self.machine.ssh_probe.as_dict()
            return {
                '%s-%s' % (self.machine.id, self.machine.external_id): {
                    'probe': {
                        'ssh': data
                    }
                }
            }

        old_probe_data = _get_probe_dict()

        task_key = 'machine:ssh_probe:%s' % self.machine.id
        task = PeriodicTaskInfo.get_or_add(task_key)
        with task.task_runner(persist=persist):
            try:
                data = probe_ssh_only(
                    self.machine.cloud.owner, self.machine.cloud.id,
                    self.machine.id, self.get_host(),
                )
            except:
                probe = self.machine.ssh_probe
                if probe is not None:
                    probe.unreachable_since = datetime.datetime.now()
                raise
            else:
                probe = SSHProbe()
                probe.update_from_dict(data)
            finally:
                self.machine.ssh_probe = probe
                self.machine.save()
                new_probe_data = _get_probe_dict()
                patch = jsonpatch.JsonPatch.from_diff(old_probe_data,
                                                      new_probe_data).patch
                if patch:
                    amqp_publish_user(self.machine.cloud.owner.id,
                                      routing_key='patch_machines',
                                      data={'cloud_id': self.machine.cloud.id,
                                            'patch': patch})
        probe_result = self.machine.ssh_probe
        return probe_result and probe_result.as_dict()
