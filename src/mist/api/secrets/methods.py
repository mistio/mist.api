import mongoengine as me

from mist.api.secrets.models import VaultSecret


def value_refers_to_secret(value, owner):
    '''
        This method parses a value given, which might
        refer to a private key or to part of cloud
        credentials (eg token, api_key, certificate etc)
        Returns (secret, key) if the value is of the following format:
        <secret_id>:key, otherwise None, ''
    '''
    if len(value.split(':')) == 2:
        secret_id, key = value.split(':')
        try:
            secret = VaultSecret.objects.get(id=secret_id, owner=owner)
            return (secret, key)
        except me.DoesNotExist:
            return (None, '')

    return (None, '')
