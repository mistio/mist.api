from __future__ import annotations
import re
import random
import string
from typing import Any, Tuple, Optional, TYPE_CHECKING

from mist.api.secrets.models import VaultSecret

if TYPE_CHECKING:
    from mist.api.users.models import Organization


def maybe_get_secret_from_arg(
    value: Any, owner: Organization
) -> Tuple[Optional[VaultSecret], str, bool]:
    """
    Determine whether a user provided parameter is a Vault path.

    To identify a provided value as a Vault path, this value must be
    a string that starts with the word "secret", followed by the Vault path
    enclosed in parenthesis, e.g secret(path/to/vault/secret:key)

    NOTE: Everything after the ":" is the actual secret key that its value
    contains the sensitive data.

    For example the path /secrets/clouds/GCE might contain the following:
    {
        "key1": <data>,
        "key2": <data>,
        ...
    }

    To use the value of "key1", the path should be:
    secret(secrets/clouds/GCE:key1)

    Returns:
        If the secret exists:
        A tuple containing the VaultSecret, the secret key and a boolean
        denoting whether the secret was found.

        If the secret doesn't exist a tuple of (None, "", False) is returned.
    """
    prefix = "secret("
    suffix = ")"
    if (
        isinstance(value, str) and
        value.startswith(prefix) and
        value.endswith(suffix)
    ):
        # Get rid of the "secret()" identifier
        secret_selector = value[len(prefix):-len(suffix)]

        name, key = secret_selector.split(":")
        try:
            secret = VaultSecret.objects.get(name=name, owner=owner)
            return (secret, key, True)
        except VaultSecret.DoesNotExist:
            return (None, "", False)

    return (None, "", False)


def list_secrets(owner, cached=True, path="."):
    if cached:
        secrets = VaultSecret.objects(owner=owner)
        if path != ".":
            secrets = [
                secret for secret in secrets if secret.name.startswith(path)
            ]

    else:
        secrets = owner.secrets_ctl.list_secrets(path)

        # Update RBAC Mappings given the list of new secrets.
        owner.mapper.update(secrets, asynchronous=False)

    return [_secret.as_dict() for _secret in secrets]


def filter_list_secrets(auth_context, cached=True, path=".", perm="read"):
    secrets = list_secrets(auth_context.owner, cached, path)
    if not auth_context.is_owner():
        allowed_resources = auth_context.get_allowed_resources(perm)
        for i in range(len(secrets) - 1, -1, -1):
            if secrets[i]["id"] not in allowed_resources["secrets"]:
                secrets.pop(i)
    return secrets


def generate_secrets_engine_path(name: str) -> str:
    """
    Create a string that will be used as the name for a secrets engine.

    Replaces non alphanumeric characters except full stop with dash and
    appends 6 random alphanumeric characters to avoid collisions.
    """
    converted_name = re.sub("[^a-zA-Z0-9\.]", "-", name)
    append_string = "".join(
        random.SystemRandom().choice(string.ascii_lowercase + string.digits)
        for _ in range(6)
    )

    return f"{converted_name}-{append_string}"
