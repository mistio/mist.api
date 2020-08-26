import hvac
from mist.api import config

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
        assert(self.client.is_authenticated())

    def list_secrets(self):
        """ List all available Secrets in Secret Engine """
        print(self.client.list(self.secret.secret_engine_name)['data'])

    def list_sec_engines(self):
        """ List all available Secret Engines """
        print(self.client.list_secret_backends()['data'])
