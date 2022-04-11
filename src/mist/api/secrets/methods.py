import mongoengine as me

from mist.api.secrets.models import VaultSecret


def maybe_get_secret_from_arg(value, owner):
    '''
    This method parses a value given, which might
    refer to a private key or to part of cloud
    credentials (eg token, api_key, certificate etc).
    Returns (secret, key, True) if the value is of the following format:
    secret(clouds.ec2.apikey), otherwise (None, '', False)
    '''
    if isinstance(value, str) and value.startswith('secret('):
        secret_selector = value[7:-1].replace('.', '/').split('/')
        secret_name = '/'.join(secret_selector[:-1])
        try:
            secret = VaultSecret.objects.get(name=secret_name, owner=owner)
            return (secret, secret_selector[-1], True)
        except me.DoesNotExist:
            return (None, '', False)

    return (None, '', False)


def list_secrets(owner, cached=True, path='.'):
    if cached:
        secrets = VaultSecret.objects(owner=owner)
        if path != '.':
            secrets = [secret for secret in secrets
                       if secret.name.startswith(path)]

    else:
        # TODO: is there a better way?
        secret = VaultSecret(owner=owner)
        secrets = secret.ctl.list_secrets(path)

        # Update RBAC Mappings given the list of new secrets.
        owner.mapper.update(secrets, asynchronous=False)

    return [_secret.as_dict() for _secret in secrets]


def filter_list_secrets(auth_context, cached=True, path='.', perm='read'):
    secrets = list_secrets(auth_context.owner, cached, path)
    if not auth_context.is_owner():
        allowed_resources = auth_context.get_allowed_resources(perm)
        for i in range(len(secrets) - 1, -1, -1):
            if secrets[i]['id'] not in allowed_resources['secrets']:
                secrets.pop(i)
    return secrets
