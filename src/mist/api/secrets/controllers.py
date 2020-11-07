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

    def check_if_secret_engine_exists(self):
        '''
        This method checks whether a secret engine exists for
        the org. If it doesn't, it creates one.
        '''
        org_name = self.secret.owner.name
        response = self.client.sys.list_mounted_secrets_engines()
        existing_secret_engines = response['data'].keys()
        # if no secret engine exists for the org, create one
        if org_name + '/' not in existing_secret_engines:
            log.info('No KV secret engine found for org %s. \
                    Creating one...' % org_name)
            self.client.sys.enable_secrets_engine(backend_type='kv',
                                                  path=org_name,
                                                  options={'version': 2}
                                                  )

    def list_secrets(self, path='.'):
        self.check_if_secret_engine_exists()
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                mount_point=self.secret.owner.name,
                path=path
            )
            keys = response['data']['keys']
        except hvac.exceptions.InvalidPath:
            if path == '.':  # there aren't any secrets stored
                keys = []
            else:
                raise BadRequestError("The path specified does not exist \
                    in Vault.")
        path = create_secret_name(path)
        from mist.api.secrets.models import VaultSecret
        secrets = []
        for key in keys:
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

        # delete secret objects that have been removed from Vault, from mongoDB
        VaultSecret.objects(owner=self.secret.owner,
                            id__nin=[s.id for s in secrets]).delete()
        return secrets

    def create_or_update_secret(self, secret):
        """ Create a Vault KV* Secret """
        self.check_if_secret_engine_exists()
        try:
            self.client.secrets.kv.v2.patch(
                mount_point=self.secret.owner.name,
                path=self.secret.name,
                secret=secret
            )
        except hvac.exceptions.InvalidPath:
            # no existing data in this path
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
