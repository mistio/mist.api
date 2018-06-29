from celery import Celery

from mist.api.config import CELERY_SETTINGS, PLUGINS


app = Celery('tasks')
app.conf.update(**CELERY_SETTINGS)
app.autodiscover_tasks([
    'mist.api',
    'mist.api.poller',
    'mist.api.portal',
    'mist.api.monitoring',
    'mist.api.metering',
    'mist.api.rules',
    'mist.api.auth',
])

app.autodiscover_tasks(['mist.%s' % _plugin for _plugin in PLUGINS])
