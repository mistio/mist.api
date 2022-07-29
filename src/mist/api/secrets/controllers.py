from __future__ import annotations
import time
import logging
from typing import TYPE_CHECKING, List, Dict, Any, Tuple

import hvac
import mongoengine as me

from mist.api import config
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ServiceUnavailableError
from mist.api.secrets.models import Secret, VaultSecret

if TYPE_CHECKING:
    from mist.api.users.models import Organization


log = logging.getLogger(__name__)


def create_secret_name(path: str) -> str:
    if path == ".":
        return ""
    elif not path.endswith("/"):
        return path + "/"
    else:
        return path


class MistVaultError(Exception):
    ...


class VaultPortalClient:
    """The portal's Vault client. This client should only be used to mount
    secrets engines and create policies for Organization clients.

    Either approle credentials(VAULT_ROLE_ID,VAULT_SECRET_ID) or
    token(VAULT_TOKEN) must be available in config.py with the required
    policies attached.
    """

    _client = hvac.Client(url=config.VAULT_ADDR)

    def authenticate(self) -> None:
        if config.VAULT_SECRET_ID and config.VAULT_ROLE_ID:
            try:
                self._client.auth.approle.login(
                    role_id=config.VAULT_ROLE_ID,
                    secret_id=config.VAULT_SECRET_ID,
                )
            except hvac.exceptions.InvalidRequest:
                raise MistVaultError("Vault approle authentication failed.")
        elif config.VAULT_TOKEN:
            self._client.token = config.VAULT_TOKEN
        else:
            raise MistVaultError("Vault credentials missing")

        try:
            is_authenticated = self._client.is_authenticated()
        except hvac.exceptions.VaultDown:
            raise MistVaultError("Vault is sealed")

        if is_authenticated is False:
            raise MistVaultError(
                "Failed to authenticate with portal Vault client"
            )

    def get_approle_credentials(
        self,
        secrets_engine_path: str,
    ) -> Tuple[str, str]:
        """
        Generate scoped approle credentials for the provided secrets engine.

        Returns a tuple of the created role_id, secret_id
        """

        policy = config.VAULT_ORGANIZATION_POLICY.format(
            secret_engine_path=secrets_engine_path
        )
        policy_name = config.VAULT_ORGANIZATION_POLICY_NAME.format(
            secret_engine_path=secrets_engine_path
        )
        role_name = config.VAULT_ORGANIZATION_ROLE_NAME.format(
            secret_engine_path=secrets_engine_path
        )

        self._client.sys.create_or_update_policy(
            name=policy_name,
            policy=policy,
        )

        try:
            self._client.auth.approle.create_or_update_approle(
                role_name=role_name,
                token_policies=[policy_name],
                token_type="service",
            )
        except hvac.exceptions.InvalidPath:
            raise MistVaultError("Unsupported Vault path")

        role_id = self._client.auth.approle.read_role_id(role_name=role_name)[
            "data"
        ]["role_id"]

        secret_id = self._client.auth.approle.generate_secret_id(
            role_name=role_name,
        )["data"]["secret_id"]

        return role_id, secret_id


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

    def list_secrets(
        self, path: str = ".", recursive: bool = False
    ) -> List[Secret]:
        raise NotImplementedError()

    def create_or_update_secret(
        self, name: str, attributes: Dict[str, Any]
    ) -> None:
        raise NotImplementedError()

    def read_secret(self, name: str) -> Dict[str, Any]:
        raise NotImplementedError()

    def delete_secret(self, name: str) -> None:
        raise NotImplementedError()


class VaultSecretController(BaseSecretController):
    def __init__(self, org: Organization) -> None:
        super().__init__(org)
        url = org.vault_address or config.VAULT_ADDR
        token = None
        if org.vault_token:
            token = org.vault_token
        elif (
            not org.vault_address and
            not org.vault_role_id and
            config.VAULT_TOKEN
        ):
            token = config.VAULT_TOKEN
        is_authenticated = False
        if token:
            self.client = hvac.Client(url=url, token=token)
            try:
                is_authenticated = self.client.is_authenticated()
            except hvac.exceptions.VaultDown:
                raise ServiceUnavailableError("Vault is sealed.")

        if not token or not is_authenticated:
            if org.vault_role_id and org.vault_secret_id:
                self.client = hvac.Client(url=url)
                try:
                    result = self.client.auth.approle.login(
                        role_id=org.vault_role_id,
                        secret_id=org.vault_secret_id,
                    )
                except hvac.exceptions.InvalidRequest:
                    raise BadRequestError(
                        "Vault approle authentication failed."
                    )
                client_token = result.get("auth", {}).get("client_token")
                if client_token:
                    org.vault_token = client_token
                    org.save()
                    return
            raise BadRequestError("Vault authentication failed.")

    def ensure_secrets_engine(self) -> None:
        """
        Make sure that a secrets engine exists for the organization.
        """
        try:
            self.client.sys.enable_secrets_engine(
                backend_type="kv",
                path=self.org.vault_secret_engine_path,
                options={
                    "version": config.VAULT_KV_VERSION,
                },
            )
        except hvac.exceptions.InvalidRequest:
            log.info("Secrets engine already exists for org %s", self.org.id)
        else:
            log.info("Created secrets engine for org %s", self.org.id)


class KV1VaultSecretController(VaultSecretController):
    def list_secrets(
        self, path: str = ".", recursive: bool = False
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
                mount_point=self.org.vault_secret_engine_path, path=path
            )
            keys = response["data"]["keys"]
        except hvac.exceptions.InvalidPath:
            if path == ".":  # there aren't any secrets stored
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
                secret = VaultSecret.objects.get(
                    name=current_path + key, owner=self.org
                )
            except me.DoesNotExist:
                secret = VaultSecret(name=current_path + key, owner=self.org)

            if key.endswith("/") and recursive:
                secrets += self.list_secrets(
                    current_path + key, recursive=True
                )
            secret.save()
            secrets.append(secret)

        if path == "." and recursive:  # this is meant for poller only
            # delete secret objects that have been removed
            # from Vault, from mongoDB
            VaultSecret.objects(
                owner=self.org, id__nin=[s.id for s in secrets]
            ).delete()

        return list(set(secrets))

    def create_or_update_secret(
        self, name: str, attributes: Dict[str, Any]
    ) -> None:
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
                "permissions to create secret"
            )
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
                "permissions to read secret"
            )
        except hvac.exceptions.InvalidPath:
            raise BadRequestError("Secret does not exist")

        return api_response["data"]

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
                "permissions to delete secret"
            )

        # list all secrets
        self.list_secrets(path=".", recursive=True)


class KV2VaultSecretController(VaultSecretController):
    def list_secrets(
        self, path: str = ".", recursive: bool = False
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
            response = self.client.secrets.kv.list_secrets(
                mount_point=self.org.vault_secret_engine_path, path=path
            )
            keys = response["data"]["keys"]
        except hvac.exceptions.InvalidPath:
            if path == ".":  # there aren't any secrets stored
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
                secret = VaultSecret.objects.get(
                    name=current_path + key, owner=self.org
                )
            except me.DoesNotExist:
                secret = VaultSecret(name=current_path + key, owner=self.org)

            if key.endswith("/") and recursive:
                secrets += self.list_secrets(
                    current_path + key, recursive=True
                )
            secret.save()
            secrets.append(secret)

        if path == "." and recursive:  # this is meant for poller only
            # delete secret objects that have been removed
            # from Vault, from mongoDB
            VaultSecret.objects(
                owner=self.org, id__nin=[s.id for s in secrets]
            ).delete()
        return list(set(secrets))

    def create_or_update_secret(
        self, name: str, attributes: Dict[str, Any]
    ) -> None:
        """
        Create a new version of a secret at the specified path.

        Parameters:
          name(str): The name/path of the secret to create or update.
          attributes(dict): The contents of the secret.
        """
        self.ensure_secrets_engine()
        for _ in range(5):
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

                return
            except hvac.exceptions.Forbidden:
                raise BadRequestError(
                    "Make sure your Vault token has the "
                    "permissions to create a secret")
            except hvac.exceptions.InvalidRequest as exc:
                # When a KV2 secrets engine is mounted, it starts as KV1 and
                # immediately upgrades itself. During this time, requests to
                # create or read secrets will result in 400, containing a
                # message like the one below.
                # See the following issue for more info:
                # https://github.com/hashicorp/terraform-provider-vault/issues/677  # noqa: E501
                if "Upgrading from non-versioned to versioned data" in str(exc):  # noqa: E501
                    time.sleep(1)
                    continue

                raise
            else:
                return

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
            raise BadRequestError(
                "Make sure your Vault token has the "
                "permissions to read secret"
            )
        except hvac.exceptions.InvalidPath:
            raise BadRequestError("Secret does not exist")

        return api_response["data"]["data"]

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
                "permissions to delete secret"
            )

        # list all secrets
        self.list_secrets(path=".", recursive=True)
