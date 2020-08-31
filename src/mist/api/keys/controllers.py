import logging
from Crypto.PublicKey import RSA
from mist.api.keys.base import BaseKeyController
from mist.api.exceptions import MachineUnauthorizedError

log = logging.getLogger(__name__)


class SSHKeyController(BaseKeyController):

    def generate(self):
        """Generates a new RSA keypair and assigns to self. TODO """
        from Crypto import Random
        from mist.api.secrets.models import VaultSecret, SecretValue
        Random.atfork()
        key = RSA.generate(2048)

        vault_secret = VaultSecret('ssh', data={"private": key.exportKey().decode()})
        vault_secret.save()

        secret_value = SecretValue(secret=vault_secret)

        self.key.private = secret_value
        self.key.private.key_name = "private"

        self.key.public = key.exportKey('OpenSSH').decode()

    def vault_integrate(self, secret_backend, secret_name, key):
        """ Integrates a key from Vault and stores only the SecretValue """
        from mist.api.secrets.models import VaultSecret, SecretValue

        vault_secret = VaultSecret(
            secret_engine_name=secret_backend,
            data=None,
            name=secret_name,
        ).save()

        self.key.private = SecretValue(vault_secret, key_name=key)
        self.key.private.key_name = "Vault" + key
        self.key.public = self.key.ctl.construct_public_from_private()

    def associate(self, machine, username='root', port=22, no_connect=False):
        key_assoc = super(SSHKeyController, self).associate(
            machine,
            username=username,
            port=port,
            no_connect=no_connect)

        if not no_connect:
            self.deploy(machine, username=username, port=key_assoc.port)

    def disassociate(self, machine):
        log.info("Undeploy key = %s" % machine.hostname)

        self.undeploy(machine)
        super(SSHKeyController, self).disassociate(machine)

    def deploy(self, machine, username=None, port=22):
        """"""
        from mist.api.machines.models import KeyMachineAssociation
        # try to actually deploy
        log.info("Deploying key to host %s", machine.hostname)
        filename = '~/.ssh/authorized_keys'
        grep_output = '`grep \'%s\' %s`' % (self.key.public, filename)
        new_line_check_cmd = (
            'if [ "$(tail -c1 %(file)s; echo x)" != "\\nx" ];'
            ' then echo "" >> %(file)s; fi' % {'file': filename}
        )
        append_cmd = ('if [ -z "%s" ]; then echo "%s" >> %s; fi'
                      % (grep_output, self.key.public, filename))
        command = new_line_check_cmd + " ; " + append_cmd
        log.debug("command = %s", command)

        # FIXME
        from mist.api.methods import ssh_command

        deploy_error = False

        # a little hack to take the username from the first associated key
        key_associations = KeyMachineAssociation.objects(machine=machine)
        if key_associations:
            # in case user changes the username from the ui
            if key_associations[0].ssh_user != 'root':
                username = key_associations[0].ssh_user

        try:
            # Deploy key.
            ssh_command(self.key.owner, machine.cloud.id, machine.id,
                        machine.hostname, command,
                        username=username, port=port)
            log.info("Key associated and deployed successfully.")
        except MachineUnauthorizedError:
            # Couldn't deploy key, maybe key was already deployed?
            deploy_error = True
        try:
            ssh_command(self.key.owner, machine.cloud.id, machine.id,
                        machine.hostname, 'uptime', key_id=self.key.id,
                        username=username, port=port)
        except MachineUnauthorizedError:
            if deploy_error:
                super(SSHKeyController, self).disassociate(machine)
                raise MachineUnauthorizedError("Couldn't connect to "
                                               "deploy new SSH key.")
            raise

    def undeploy(self, machine):
        log.info("Trying to actually remove key from authorized_keys.")
        command = \
            'grep -v "' + self.key.public + \
            '" ~/.ssh/authorized_keys ' + \
            '> ~/.ssh/authorized_keys.tmp ; ' + \
            'mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys ' + \
            '&& chmod go-w ~/.ssh/authorized_keys'
        try:
            # FIXME
            from mist.api.methods import ssh_command
            ssh_command(self.key.owner, machine.cloud.id,
                        machine.id, machine.hostname, command)
        except Exception as exc:
            log.info("Undeploying key %s failed: %s", self.key.id, str(exc))
