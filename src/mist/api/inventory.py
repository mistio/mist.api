from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine, KeyMachineAssociation
from mist.api.keys.models import SSHKey, SignedSSHKey

from mist.api import config

if config.HAS_VPN:
    from mist.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat


class MistInventory(object):
    def __init__(self, owner, machines=None):
        self.owner = owner
        self.hosts = {}
        self.keys = {}
        self._cache = {}
        self.load(machines)

    def load(self, machines=None):
        self.hosts = {}
        self.keys = {}
        if not machines:
            clouds = Cloud.objects(owner=self.owner, deleted=None)
            machines = [(machine.cloud.id, machine.external_id)
                        for machine in Machine.objects(cloud__in=clouds)]
        for cloud_id, external_id in machines:
            try:
                name, ip_addr = self.find_machine_details(
                    cloud_id, external_id)
                key_id, ssh_user, port = self.find_ssh_settings(
                    cloud_id, external_id)
            except Exception as exc:
                print(exc)
                continue
            ip_addr, port = dnat(self.owner, ip_addr, port)
            if key_id not in self.keys:
                key = SSHKey.objects.get(owner=self.owner, name=key_id,
                                         deleted=None)
                self.keys[key_id] = key.private.value
                if isinstance(key, SignedSSHKey):
                    # if signed ssh key, provide the key appending a -cert.pub
                    # on the name since this is how ssh will include it as
                    # an identify file
                    self.keys['%s-cert.pub' % key_id] = key.certificate
                    # pub key also needed for openssh 7.2
                    self.keys['%s.pub' % key_id] = key.public
            if name in self.hosts:
                num = 2
                while ('%s-%d' % (name, num)) in self.hosts:
                    num += 1
                name = '%s-%d' % (name, num)

            self.hosts[name] = {
                'ansible_ssh_host': ip_addr,
                'ansible_ssh_port': port,
                'ansible_ssh_user': ssh_user,
                'ansible_ssh_private_key_file': 'id_rsa/%s' % key_id,
            }

    def export(self, include_localhost=True):
        ans_inv = ''
        if include_localhost:
            ans_inv += 'localhost\tansible_connection=local\n\n'
        for name, host in list(self.hosts.items()):
            vars_part = ' '.join(["%s=%s" % item
                                  for item in list(host.items())])
            ans_inv += '%s\t%s\n' % (name, vars_part)
        ans_inv += ('\n[all:vars]\n'
                    'ansible_python_interpreter="/usr/bin/env python2"\n')
        ans_cfg = '[defaults]\nhostfile=./inventory\nhost_key_checking=False\n'
        files = {'ansible.cfg': ans_cfg, 'inventory': ans_inv}
        for key_id, private_key in list(self.keys.items()):
            files.update({'id_rsa/%s' % key_id: private_key})
        return files

    def _list_machines(self, cloud_id):
        if cloud_id not in self._cache:
            print('Actually doing list_machines for %s' % cloud_id)
            from mist.api.machines.methods import list_machines
            machines = list_machines(self.owner, cloud_id)
            self._cache[cloud_id] = machines
        return self._cache[cloud_id]

    def find_machine_details(self, cloud_id, external_id):
        machines = self._list_machines(cloud_id)
        for machine in machines:
            if machine['external_id'] == external_id:
                name = machine['name'].replace(' ', '_')
                ips = [ip for ip in machine['public_ips'] if ':' not in ip]
                # in case ips is empty search for private IPs
                if not ips:
                    ips = [ip for ip in machine['private_ips']
                           if ':' not in ip]
                if not name:
                    name = external_id
                if not ips:
                    raise Exception('Machine ip not found in list machines')
                ip_addr = ips[0] if ips else ''  # can be either public or priv
                return name, ip_addr
        raise Exception('Machine not found in list_machines')

    def find_ssh_settings(self, cloud_id, external_id):
        cloud = Cloud.objects.get(owner=self.owner, id=cloud_id, deleted=None)
        machine = Machine.objects.get(cloud=cloud, external_id=external_id)
        key_associations = KeyMachineAssociation.objects(machine=machine)
        if not key_associations:
            raise Exception("Machine doesn't have SSH association")
        assoc = sorted(key_associations, key=lambda a: a.last_used)[-1]
        return assoc.key.name, assoc.ssh_user or 'root', assoc.port
