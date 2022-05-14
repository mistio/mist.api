from __future__ import annotations
import logging
from typing import TYPE_CHECKING, List, Dict, Any

import hvac
import mongoengine as me

from mist.api import config
from mist.api.exceptions import BadRequestError, ForbiddenError
from mist.api.exceptions import ServiceUnavailableError
from mist.api.secrets.models import Secret, VaultSecret

if TYPE_CHECKING:
    from mist.api.users.models import Organization


log = logging.getLogger(__name__)


def create_secret_name(path: str) -> str:
    if path == '.':
        return ''
    elif not path.endswith('/'):
        return path + '/'
    else:
        return path


class BaseSecretController:
    def __init__(self, org: Organization) -> None:
        """
        Initialize a secrets controller given an organization.

        It is expected to access a controller from inside the organization.

        For example:

        org = Organization.objects.get(id=org_id)
        org.secrets_ctl.list_secrets()
        """
        self.org = org

    def list_secrets(self,
                     path: str = '.',
                     recursive: bool = False) -> List[Secret]:
        raise NotImplementedError()

    def create_or_update_secret(self,
                                name: str,
                                attributes: Dict[str, Any]) -> None:
        raise NotImplementedError()

    def read_secret(self, name: str) -> Dict[str, Any]:
        raise NotImplementedError()

    def delete_secret(self, name: str) -> None:
        raise NotImplementedError()


class VaultSecretController(BaseSecretController):

    def __init__(self, org: Organization) -> None:
        super().__init__(org)
        url = org.vault_address or config.VAULT_ADDR
        token = org.vault_token or (
            not org.vault_address and config.VAULT_TOKEN)
        is_authenticated = False
        if token:
            self.client = hvac.Client(url=url, token=token)
            try:
                is_authenticated = self.client.is_authenticated()
            except hvac.exceptions.VaultDown:
                raise ServiceUnavailableError("Vault is sealed.")

        if not token or not is_authenticated:
            role_id = org.vault_role_id if org.vault_address else \
                config.VAULT_ROLE_ID
            secret_id = org.vault_secret_id if org.vault_address else \
                config.VAULT_SECRET_ID
            if role_id and secret_id:
                self.client = hvac.Client(url=url)
                try:
                    result = self.client.auth.approle.login(
                        role_id=role_id,
                        secret_id=secret_id,
                    )
                except hvac.exceptions.InvalidRequest:
                    raise BadRequestError(
                        "Vault approle authentication failed.")
                client_token = result.get('auth', {}).get('client_token')
                if client_token:
                    org.vault_token = client_token
                    org.save()
                    return
            raise BadRequestError("Vault authentication failed.")

    def check_if_secrets_engine_exists(self) -> bool:
        """Check whether a secrets engine exists for the org.
        """
        try:
            response = self.client.sys.list_mounted_secrets_engines()
        except hvac.exceptions.Forbidden:
            raise ForbiddenError(
                "Make sure your token has access to the Vault instance"
            )
        secret_engines = response['data'].keys()
        return self.org.vault_secret_engine_path + '/' in secret_engines

    def ensure_secrets_engine(self) -> None:
        """
        Make sure that a secrets engine exists for the organization.

        If one does not exist, it will be created.
        """
        if self.check_if_secrets_engine_exists():
            return
        log.info("Creating secrets engine for org %s", self.org.id)
        self.client.sys.enable_secrets_engine(
            backend_type='kv',
            path=self.org.vault_secret_engine_path,
            options={
                'version': config.VAULT_KV_VERSION,
            }
        )


class KV1VaultSecretController(VaultSecretController):

    def list_secrets(self,
                     path: str = '.',
                     recursive: bool = False
                     ) -> List[VaultSecret]:
        """
        List Vault secrets in the specified path.

        Parameters:
          path(str): Specifies the path of the secrets to list.
          recursive(bool): List secrets following all sub-paths available.
                           This is meant to be True only when polling secrets.
        """
        self.ensure_secrets_engine()

        try:
            response = self.client.secrets.kv.v1.list_secrets(
                mount_point=self.org.vault_secret_engine_path,
                path=path
            )
            keys = response['data']['keys']
        except hvac.exceptions.InvalidPath:
            if path == '.':  # there aren't any secrets stored
                keys = []
            else:
                raise BadRequestError(
                    "The path specified does not exist in Vault."
                )
        except hvac.exceptions.Forbidden:
            raise BadRequestError(
                "Make sure your Vault token has the "
                "permissions to list secrets"
            )

        current_path = create_secret_name(path)
        secrets = []
        for key in keys:
            try:
                secret = VaultSecret.objects.get(name=current_path + key,
                                                 owner=self.org)
            except me.DoesNotExist:
                secret = VaultSecret(name=current_path + key,
                                     owner=self.org)

            if key.endswith('/') and recursive:
                secrets += self.list_secrets(current_path + key,
                                             recursive=True)
            secret.save()
            secrets.append(secret)

        if path == '.' and recursive:  # this is meant for poller only
            # delete secret objects that have been removed
            # from Vault, from mongoDB
            VaultSecret.objects(
                owner=self.org,
                id__nin=[s.id for s in secrets]).delete()

        return list(set(secrets))

    def create_or_update_secret(self,
                                name: str,
                                attributes: Dict[str, Any]) -> None:
        """
        Create a new version of a secret at the specified path.

        Parameters:
          name(str): The name/path of the secret to create or update.
          attributes(dict): The contents of the secret.
        """
        self.ensure_secrets_engine()
        try:  # existing secret
            existing_secret = self.org.ctl.read_secret(name)
        except BadRequestError:  # new secret
            existing_secret = {}

        try:
            self.client.secrets.kv.v1.create_or_update_secret(
                mount_point=self.org.vault_secret_engine_path,
                path=name,
                secret={**existing_secret, **attributes},
            )
        except hvac.exceptions.Forbidden:
            raise BadRequestError(
                "Make sure your Vault token has the "
                "permissions to create secret")
        # self.list_secrets(recursive=True)

    def read_secret(self, name: str) -> Dict[str, Any]:
        """
        Retrieve the secret's contents at the specified path.

        Parameters:
          name(str): The name/path of the secret to retrieve.
        """
        try:
            api_response = self.client.secrets.kv.v1.read_secret(
                mount_point=self.org.vault_secret_engine_path,
                path=name,
            )
        except hvac.exceptions.Forbidden:
            raise BadRequestError(
                "Make sure your Vault token has the "
                "permissions to read secret")
        except hvac.exceptions.InvalidPath:
            raise BadRequestError("Secret does not exist")

        return api_response['data']

    def delete_secret(self, name: str) -> None:
        """
        Permanently delete the secret at the specified path.

        Parameters:
          name(str): The name/path of the secret to delete.
        """
        try:
            self.client.secrets.kv.v1.delete_secret(
                mount_point=self.org.vault_secret_engine_path,
                path=name,
            )
        except hvac.exceptions.Forbidden:
            raise BadRequestError(
                "Make sure your Vault token has the "
                "permissions to delete secret")

        # list all secrets
        self.list_secrets(path='.', recursive=True)


class KV2VaultSecretController(VaultSecretController):

    def list_secrets(self,
                     path: str = '.',
                     recursive: bool = False) -> List[VaultSecret]:
        """
        List Vault secrets in the specified path.

        Parameters:
          path(str): Specifies the path of the secrets to list.
          recursive(bool): List secrets following all sub-paths available.
                           This is meant to be True only when polling secrets.
        """
        self.ensure_secrets_engine()

        try:
            response = self.client.secrets.kv.list_secrets(
                mount_point=self.org.vault_secret_engine_path,
                path=path
            )
            keys = response['data']['keys']
        except hvac.exceptions.InvalidPath:
            if path == '.':  # there aren't any secrets stored
                keys = []
            else:
                raise BadRequestError(
                    "The path specified does not exist in Vault.")

        except hvac.exceptions.Forbidden:
            raise BadRequestError(
                "Make sure your Vault token has the "
                "permissions to list secrets")

        current_path = create_secret_name(path)
        secrets = []
        for key in keys:
            try:
                secret = VaultSecret.objects.get(name=current_path + key,
                                                 owner=self.org)
            except me.DoesNotExist:
                secret = VaultSecret(name=current_path + key,
                                     owner=self.org)

            if key.endswith('/') and recursive:
                secrets += self.list_secrets(current_path + key,
                                             recursive=True)
            secret.save()
            secrets.append(secret)

        if path == '.' and recursive:  # this is meant for poller only
            # delete secret objects that have been removed
            # from Vault, from mongoDB
            VaultSecret.objects(owner=self.org,
                                id__nin=[s.id for s in secrets]).delete()
        return list(set(secrets))

    def create_or_update_secret(self,
                                name: str,
                                attributes: Dict[str, Any]) -> None:
        """
        Create a new version of a secret at the specified path.

        Parameters:
          name(str): The name/path of the secret to create or update.
          attributes(dict): The contents of the secret.
        """
        self.ensure_secrets_engine()
        try:
            self.client.secrets.kv.v2.patch(
                mount_point=self.org.vault_secret_engine_path,
                path=name,
                secret=attributes,
            )
        except (hvac.exceptions.InvalidPath, KeyError):
            # no existing data in this path
            self.client.secrets.kv.v2.create_or_update_secret(
                mount_point=self.org.vault_secret_engine_path,
                path=name,
                secret=attributes,
            )
        except hvac.exceptions.Forbidden:
            raise BadRequestError(
                "Make sure your Vault token has the "
                "permissions to create a secret")

        # self.list_secrets(recursive=True)

    def read_secret(self, name: str) -> Dict[str, Any]:
        """
        Retrieve the secret's contents at the specified path.

        Parameters:
          name(str): The name/path of the secret to retrieve.
        """
        try:
            api_response = self.client.secrets.kv.v2.read_secret_version(
                mount_point=self.org.vault_secret_engine_path,
                path=name,
            )
        except hvac.exceptions.Forbidden:
            raise BadRequestError("Make sure your Vault token has the "
                                  "permissions to read secret")
        except hvac.exceptions.InvalidPath:
            raise BadRequestError("Secret does not exist")

        return api_response['data']['data']

    def delete_secret(self, name: str) -> None:
        """
        Permanently delete the secret at the specified path.

        Parameters:
          name(str): The name/path of the secret to delete.
        """
        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                mount_point=self.org.vault_secret_engine_path,
                path=name,
            )
        except hvac.exceptions.Forbidden:
            raise BadRequestError(
                "Make sure your Vault token has the "
                "permissions to delete secret")

        # list all secrets
        self.list_secrets(path='.', recursive=True)
