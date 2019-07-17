import datetime

import jsonpatch

from random import randrange

from mist.api.helpers import amqp_publish_user

from mist.api.concurrency.models import PeriodicTaskInfo


class MachineController(object):
    def __init__(self, machine):
        """Initialize machine controller given a machine

        Most times one is expected to access a controller from inside the
        machine, like this:

          machine = mist.api.machines.models.Machine.objects.get(id=machine_id)
          machine.cloud.ctl.compute.reboot()
        """

        self.machine = machine

    def start(self):
        return self.machine.cloud.ctl.compute.start_machine(self.machine)

    def stop(self):
        return self.machine.cloud.ctl.compute.stop_machine(self.machine)

    def suspend(self):
        """Suspends machine - used in KVM libvirt to pause machine"""
        return self.machine.cloud.ctl.compute.suspend_machine(self.machine)

    def resume(self):
        """Resumes machine - used in KVM libvirt to resume suspended machine"""
        return self.machine.cloud.ctl.compute.resume_machine(self.machine)

    def reboot(self):
        return self.machine.cloud.ctl.compute.reboot_machine(self.machine)

    def destroy(self):
        return self.machine.cloud.ctl.compute.destroy_machine(self.machine)

    def remove(self):
        return self.machine.cloud.ctl.compute.remove_machine(self.machine)

    def resize(self, size_id, kwargs):
        """Resize a machine on an other plan."""
        return self.machine.cloud.ctl.compute.resize_machine(self.machine,
                                                             size_id, kwargs)

    def rename(self, name):
        """Renames a machine on a certain cloud."""
        return self.machine.cloud.ctl.compute.rename_machine(self.machine,
                                                             name)

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

    def undefine(self):
        """Undefines machine - used in KVM libvirt
        to destroy machine and delete XML conf"""
        return self.machine.cloud.ctl.compute.undefine_machine(self.machine)

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
        raise RuntimeError("Couldn't find machine host.")

    def update(self, auth_context, expiration={}):
        schedule = self.machine.expiration_schedule

        self.machine.expiration_action = expiration.get('action', 'stop')
        self.machine.expiration_date = expiration.get('date')
        self.machine.expiration_notify = expiration.get('notify', 0)

        # schedule needs to be removed
        if schedule and not expiration.get('date', ''):
            # remove the reminder as well
            if schedule.reminder:
                schedule.reminder.delete()

            schedule.delete()
            self.machine.expiration_schedule = None

        # schedule needs to be added
        elif schedule is None and expiration.get('date'):
            params = {}
            description = 'Scheduled to run when machine expires'
            params.update({'schedule_type': 'one_off'})
            params.update({'description': description})
            params.update({'task_enabled': True})
            params.update({'schedule_entry': expiration.get('date')})
            params.update({'action': expiration.get('action')})
            conditions = [{'type': 'machines', 'ids': [self.machine.id]}]
            params.update({'conditions': conditions})
            name = self.machine.name + '_expires' + str(randrange(1000))
            notify = expiration.get('notify', 0)
            params.update({'notify': notify})
            from mist.api.schedules.models import Schedule
            exp_sch = Schedule.add(auth_context, name, **params)
            self.machine.expiration_schedule = exp_sch

        # schedule exists, will modify it
        elif schedule and expiration.get('date'):
            # reminder needs to be deleted
            if schedule.reminder:
                schedule.reminder.delete()
                schedule.reminder = None
                schedule.save()

            params = {}
            params.update({'schedule_entry': expiration.get('date')})
            params.update({'action': expiration.get('action', 'stop')})
            params.update({'notify': expiration.get('notify', 0)})
            conditions = [{'type': 'machines', 'ids': [self.machine.id]}]
            params.update({'conditions': conditions})
            name = self.machine.name + '_expires' + str(randrange(1000))
            schedule.ctl.set_auth_context(auth_context)
            schedule.ctl.update(**params)

        self.machine.save()

        return

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
                '%s-%s' % (self.machine.id, self.machine.machine_id): {
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
                '%s-%s' % (self.machine.id, self.machine.machine_id): {
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
                    self.machine.machine_id, self.get_host(),
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
