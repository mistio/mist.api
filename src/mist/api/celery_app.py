from celery import Celery

from mist.api.config import CELERY_SETTINGS


app = Celery('tasks')
app.conf.update(**CELERY_SETTINGS)
app.autodiscover_tasks(['mist.api.poller'])
app.autodiscover_tasks(['mist.api.portal'])
app.autodiscover_tasks(['mist.api.monitoring'])
app.autodiscover_tasks(['mist.api.rules'])
app.autodiscover_tasks(['mist.api.auth'])
