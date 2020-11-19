import mongoengine as me

from mist.api.secrets.models import VaultSecret


def maybe_get_secret(value, owner):
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
