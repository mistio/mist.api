from mist.api.celery_app import app

from mist.api.auth.models import AuthToken


@app.task
def revoke_token(token):
    auth_token = AuthToken.objects.get(token=token)
    auth_token.invalidate()
    auth_token.save()
