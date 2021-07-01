from mist.api.dramatiq_app import dramatiq
from mist.api.auth.models import AuthToken

__all__ = ['revoke_token']


@dramatiq.actor(time_limit=20_000, max_retries=3)
def revoke_token(token):
    auth_token = AuthToken.objects.get(token=token)
    auth_token.invalidate()
    auth_token.save()
