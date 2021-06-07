from mist.api.celery_app import app

from mist.api.auth.models import AuthToken

__all__ = ['revoke_token']


@app.task
def revoke_token(token):
    auth_token = AuthToken.objects.get(token=token)
    auth_token.invalidate()
    auth_token.save()
