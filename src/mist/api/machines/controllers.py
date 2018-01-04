import datetime

import jsonpatch

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

    def resize(self, plan_id, kwargs):
        """Resize a machine on an other plan."""
        return self.machine.cloud.ctl.compute.resize_machine(self.machine,
                                                             plan_id, kwargs)

    def rename(self, name):
        """Renames a machine on a certain cloud."""
        return self.machine.cloud.ctl.compute.rename_machine(self.machine,
                                                             name)

    # TODO we want this also ?
    # def tag(self):
    #     return self.machine.cloud.ctl.compute.tag(self.machine)

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

    def ping_probe(self, persist=True):

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
        return self.machine.ping_probe.as_dict()

    def ssh_probe(self, persist=True):
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
        return self.machine.ssh_probe.as_dict()
