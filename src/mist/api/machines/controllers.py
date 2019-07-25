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

    def update(self, auth_context, params={}):
        if params.get('expiration'):
            from mist.api.schedules.models import Schedule
            exp_date = params['expiration']['date']
            exp_reminder = int(params['expiration'].get('notify', 0) or 0)
            exp_action = params['expiration']['action']
            assert exp_action in ['stop', 'destroy'], 'Invalid action'
            if self.machine.expiration:  # Existing expiration schedule
                if exp_date:  # Update schedule
                    self.machine.expiration.schedule_type.entry = \
                        datetime.datetime.strptime(
                            exp_date, '%Y-%m-%d %H:%M:%S')
                    self.machine.expiration.max_run_count += 1
                    self.machine.expiration.save()
                    if exp_reminder:
                        if self.machine.expiration.reminder:
                            # Update existing reminder
                            rmd = self.machine.expiration.reminder
                            rmd.schedule_type.entry = \
                                self.machine.expiration.schedule_type.entry - \
                                datetime.timedelta(seconds=exp_reminder)
                            rmd.max_run_count += 1
                            rmd.save()
                        else:  # Create new reminder
                            notify_at = (
                                self.machine.expiration.schedule_type.entry -
                                datetime.timedelta(0, exp_reminder)
                            ).strftime('%Y-%m-%d %H:%M:%S')
                            params = {
                                'action': 'notify',
                                'schedule_type': 'reminder',
                                'description': 'Machine expiration reminder',
                                'task_enabled': True,
                                'schedule_entry': notify_at,
                                'conditions': self.machine.expiration.as_dict(
                                ).get('conditions')
                            }
                            name = self.machine.expiration.name + \
                                '-reminder'
                            self.machine.expiration.reminder = Schedule.add(
                                auth_context, name, **params)

                    elif exp_reminder == 0:
                        if self.machine.expiration.reminder:
                            # Delete existing reminder safely
                            rmd = self.machine.expiration.reminder
                            self.machine.expiration.reminder = None
                            self.machine.expiration.save()
                            rmd.delete()
                else:  # Delete existing schedule safely
                    sched = self.machine.expiration
                    self.machine.expiration = None
                    self.machine.save()
                    sched.delete()
            else:  # No expiration schedule found
                if exp_date:  # Create new expiration schedule
                    params = {
                        'description': 'Scheduled to run when machine expires',
                        'task_enabled': True,
                        'schedule_type': 'one_off',
                        'schedule_entry': exp_date,
                        'action': exp_action,
                        'conditions': [
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
            patch = [{
                'op': 'replace',
                'path': '/%s-%s/expiration' % (
                    self.machine.id, self.machine.machine_id),
                'value': {
                    'id': self.machine.expiration.id,
                    'date': self.machine.expiration.schedule_type.entry,
                    'action': self.machine.expiration.task_type.action,
                    'notify': self.machine.expiration.reminder and int((
                        self.machine.expiration.schedule_type.entry -
                        self.machine.expiration.reminder.schedule_type.entry
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
