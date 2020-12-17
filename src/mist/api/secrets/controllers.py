import hvac
import logging

import mongoengine as me

from mist.api import config

from mist.api.exceptions import BadRequestError, ForbiddenError

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
        org = self.secret.owner
        try:
            response = self.client.sys.list_mounted_secrets_engines()
        except hvac.exceptions.Forbidden:
            raise ForbiddenError("Make sure your token has access to the \
                Vault instance")
        existing_secret_engines = response['data'].keys()
        # if no secret engine exists for the org, create one
        if org.vault_secret_engine_path + '/' not in existing_secret_engines:
            log.info('No KV secret engine found for org %s. \
                    Creating one...' % org.name)
            self.client.sys.enable_secrets_engine(backend_type='kv',
                                                  path=org.
                                                  vault_secret_engine_path,
                                                  options={
                                                      'version':
                                                      config.VAULT_KV_VERSION
                                                  }
                                                  )

    def list_secrets(self, path='.'):
        self.check_if_secret_engine_exists()
        org = self.secret.owner
        if config.VAULT_KV_VERSION == 2:
            try:
                response = self.client.secrets.kv.list_secrets(
                    mount_point=org.vault_secret_engine_path,
                    path=path
                )
                keys = response['data']['keys']
            except hvac.exceptions.InvalidPath:
                if path == '.':  # there aren't any secrets stored
                    keys = []
                else:
                    raise BadRequestError("The path specified does not exist \
                        in Vault.")
            except hvac.exceptions.Forbidden:
                raise BadRequestError("Make sure your Vault token has the \
                    permissions to list secrets")
        else:
            try:
                response = self.client.secrets.kv.v1.list_secrets(
                    mount_point=org.vault_secret_engine_path,
                    path=path
                )
                keys = response['data']['keys']
            except hvac.exceptions.InvalidPath:
                if path == '.':  # there aren't any secrets stored
                    keys = []
                else:
                    raise BadRequestError("The path specified does not exist \
                        in Vault.")
            except hvac.exceptions.Forbidden:
                raise BadRequestError("Make sure your Vault token has the \
                    permissions to list secrets")
        path = create_secret_name(path)
        from mist.api.secrets.models import VaultSecret
        secrets = []
        for key in keys:
            if not key.endswith('/'):  # if not a dir
                try:
                    secret = VaultSecret.objects.get(name=path + key,
                                                     owner=org)
                except me.DoesNotExist:
                    secret = VaultSecret(name=path + key,
                                         owner=org)
                    secret.save()
                secrets.append(secret)
            else:
                # find recursively all the secrets
                secrets += self.list_secrets(path + key)

        return set(secrets)

    def create_or_update_secret(self, secret):
        """ Create a Vault KV* Secret """
        self.check_if_secret_engine_exists()
        try:  # kv2 update
            self.client.secrets.kv.v2.patch(
                mount_point=self.secret.owner.vault_secret_engine_path,
                path=self.secret.name,
                secret=secret
            )
        # except KeyError:  # kv1 update
        #     self.client.secrets.kv.v1.create_or_update_secret(
        #         mount_point=self.secret.owner.vault_secret_engine_path,
        #         path=self.secret.name,
        #         secret=secret
        #     )
        except hvac.exceptions.InvalidPath:
            # no existing data in this path
            if config.VAULT_KV_VERSION == 2:  # kv2 create
                self.client.secrets.kv.v2.create_or_update_secret(
                    mount_point=self.secret.owner.vault_secret_engine_path,
                    path=self.secret.name,
                    secret=secret
                )
            else:
                # needs to be different than version 2
                # it seems that some secrets in kv1 are arbitrary 
                # stored under /data and others not
                try:  # existing secret
                    existing_secret = self.secret.ctl.read_secret()
                except BadRequestError:  # new secret
                    existing_secret = {}
                secret.update(existing_secret)
                self.client.secrets.kv.v1.create_or_update_secret(
                    mount_point=self.secret.owner.vault_secret_engine_path,
                    path=self.secret.name,
                    secret=secret
                )
        except hvac.exceptions.Forbidden:
            raise BadRequestError("Make sure your Vault token has the \
                permissions to create secret")

    def read_secret(self):
        """ Read a Vault KV* Secret """
        if config.VAULT_KV_VERSION == 2:
            try:
                api_response = self.client.secrets.kv.v2.read_secret_version(
                    mount_point=self.secret.owner.vault_secret_engine_path,
                    path=self.secret.name
                )
            except hvac.exceptions.Forbidden:
                raise BadRequestError("Make sure your Vault token has the \
                    permissions to read secret")
            except hvac.exceptions.InvalidPath:
                raise BadRequestError("Secret does not exist")
            
            return api_response['data']['data']
        else:
            try:
                api_response = self.client.secrets.kv.v1.read_secret(
                    mount_point=self.secret.owner.vault_secret_engine_path,
                    path=self.secret.name
                )
            except hvac.exceptions.Forbidden:
                raise BadRequestError("Make sure your Vault token has the \
                    permissions to read secret")
            except hvac.exceptions.InvalidPath:
                raise BadRequestError("Secret does not exist")

            return api_response['data']

    def delete_secret(self):
        " Delete a Vault KV* Secret"
        if config.VAULT_KV_VERSION == 2:
            try:
                self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                    mount_point=self.secret.owner.vault_secret_engine_path,
                    path=self.secret.name
                )
            except hvac.exceptions.Forbidden:
                raise BadRequestError("Make sure your Vault token has the \
                    permissions to delete secret")
        else:
            try:
                self.client.secrets.kv.v1.delete_secret(
                    mount_point=self.secret.owner.vault_secret_engine_path,
                    path=self.secret.name
                )
            except hvac.exceptions.Forbidden:
                raise BadRequestError("Make sure your Vault token has the \
                    permissions to delete secret") 

        # list all secrets
        self.list_secrets(path='.')
