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

        self.client = hvac.Client(url=url, token='s.Stog1SrqidWVQcr6R60N446a')
        assert(self.client.is_authenticated())

    def create_secret(self, org_name, key, value):
        """ Create a Vault KV* Secret """
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                mount_point=org_name,
                path=self.secret.name,
                secret={key: value}
            )
        except hvac.exceptions.InvalidPath:
            # create relative handler for specific org
            self.client.sys.enable_secrets_engine(backend_type='kv', path=org_name,
                                                  options={'version':2}
                                                  )
            self.client.secrets.kv.v2.create_or_update_secret(
                mount_point=org_name,
                path=self.secret.name,
                secret={key: value}
            )

    def read_secret(self, org_name):
        """ Read a Vault KV* Secret """
        api_response = self.client.secrets.kv.v2.read_secret_version(
                                mount_point=org_name,
                                path=self.secret.name
                            )

        return api_response

    def delete_secret(self, org_name):
        " Delete a Vault KV* Secret"
        self.client.secrets.kv.v2.delete_secret(
            mount_point=org_name,
            path=self.secret.name
        )
