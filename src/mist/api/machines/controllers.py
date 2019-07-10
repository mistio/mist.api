import datetime

import jsonpatch

from mist.api.helpers import amqp_publish_user
from mist.api.helpers import send_email

from mist.api.exceptions import ServiceUnavailableError

from mist.api.concurrency.models import PeriodicTaskInfo

from mist.api import config


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

    def update(self, expiration_date, expiration_action='stop', expiration_notify=0):
        self.machine.expiration_action = expiration_action
        self.machine.expiration_date = expiration_date
        self.machine.expiration_notify = expiration_notify
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

    def check_exp_date(self, persist=True):
        machine = self.machine
        # check whether action (stop / destroy) is needed
        now = datetime.datetime.now()
        if machine.expiration_date:
            if machine.expiration_date <= now:
                if machine.expiration_action == 'stop':
                    machine.ctl.stop()
                elif machine.expiration_action == 'destroy':
                    machine.ctl.destroy()

                subject = config.MACHINE_EXPIRED_EMAIL_SUBJECT
                main_body = config.MACHINE_EXPIRED_EMAIL_BODY
                body = main_body % ((machine.owned_by.first_name + " " +
                                    machine.owned_by.last_name),
                                    machine.name,
                                    machine.expiration_date,
                                    machine.expiration_action,
                                    config.CORE_URI)
                if not send_email(subject, body, machine.owned_by.email):
                    raise ServiceUnavailableError("Could not send notification"
                                                  " email that machine"
                                                  " expired.")

                return

        # check whether notification is needed
        if machine.expiration_notify:
            _delta = datetime.timedelta(0, machine.expiration_notify)
            notify_at = self.machine.expiration_date - _delta
            if notify_at <= now:
                # notify both owner and creator
                mails = [machine.owned_by.email, machine.created_by.email]
                for mail in list(set(mails)):
                    if mail == machine.owned_by.email:
                        user = machine.owned_by
                    else:
                        user = machine.created_by
                    subject = config.MACHINE_EXPIRE_NOTIFY_EMAIL_SUBJECT
                    main_body = config.MACHINE_EXPIRE_NOTIFY_EMAIL_BODY
                    body = main_body % ((user.first_name + " " +
                                        user.last_name),
                                        machine.name,
                                        machine.expiration_action,
                                        machine.expiration_date,
                                        config.CORE_URI)

                    if not send_email(subject, body, user.email):
                        raise ServiceUnavailableError("Could not send notification"
                                                    " email about machine that"
                                                    " is about to expire.")
                machine.expiration_notify = ''
                machine.save()

                return
