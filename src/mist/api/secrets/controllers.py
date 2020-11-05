import hvac
import logging

import mongoengine as me

from mist.api import config

from mist.api.exceptions import BadRequestError

log = logging.getLogger(__name__)


def create_secret_name(path):
    if path == '.':
        return ''
    elif not path.endswith('/'):
        return path + '/'
    else:
        return path


class BaseSecretController(object):
    def __init__(self, secret):
        """Initialize a secret controller given a secret

           Most times one is expected to access a controller from inside the
           secret, like this:

           secret = mist.api.secrets.models.Secret.objects.get(id=secret.id)
           secret.ctl.construct_public_from_private()
        """
        self.secret = secret


class VaultSecretController(BaseSecretController):

    client = hvac.Client

    def __init__(self, secret):
        super(VaultSecretController, self).__init__(secret)
        token = config.VAULT_TOKEN
        url = config.VAULT_ADDR

        self.client = hvac.Client(url=url, token=token)
        try:
            self.client.is_authenticated()
        except hvac.exceptions.VaultDown:
            raise BadRequestError("Vault is sealed.")

    def list_secrets(self, path):
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                mount_point=self.secret.owner.name,
                path=path
            )
        except hvac.exceptions.InvalidPath:
            raise BadRequestError("The path specified does not exist \
                in Vault.")

        path = create_secret_name(path)
        from mist.api.secrets.models import VaultSecret
        secrets = []
        for key in response['data']['keys']:
            if not key.endswith('/'):  # if not a dir
                try:
                    secret = VaultSecret.objects.get(name=path + key,
                                                     owner=self.secret.owner)
                except me.DoesNotExist:
                    secret = VaultSecret(name=path + key,
                                         owner=self.secret.owner)
                    secret.save()
                secrets.append(secret)
            else:
                # find recursively all the secrets
                secrets += self.list_secrets(key)

        return secrets

    def create_or_update_secret(self, secret):
        """ Create a Vault KV* Secret """
        try:
            self.client.secrets.kv.v2.patch(
                mount_point=self.secret.owner.name,
                path=self.secret.name,
                secret=secret
            )
        except hvac.exceptions.InvalidPath as exc:
            # no existing data in this path
            if 'No value found' in exc.args[0]:
                self.client.secrets.kv.v2.create_or_update_secret(
                    mount_point=self.secret.owner.name,
                    path=self.secret.name,
                    secret=secret
                )
            else:  # TODO: check error msg
                log.info('No KV secret engine found for org %s. \
                    Creating one...' % self.secret.owner)
                self.client.sys.enable_secrets_engine(backend_type='kv',
                                                      path=self.secret.owner,
                                                      options={'version': 2}
                                                      )
                self.client.secrets.kv.v2.create_or_update_secret(
                    mount_point=self.secret.owner.name,
                    path=self.secret.name,
                    secret=secret
                )

    def read_secret(self):
        """ Read a Vault KV* Secret """
        api_response = self.client.secrets.kv.v2.read_secret_version(
            mount_point=self.secret.owner.name,
            path=self.secret.name
        )

        return api_response['data']['data']

    def delete_secret(self):
        " Delete a Vault KV* Secret"
        self.client.secrets.kv.v2.delete_metadata_and_all_versions(
            mount_point=self.secret.owner.name,
            path=self.secret.name
        )

        # list all secrets
        self.list_secrets(path='.')