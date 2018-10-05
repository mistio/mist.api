import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': 'root',
            'HOST': 'postgres',
            'USER': 'root',
            'PASSWORD': 'example',
            'PORT': '5432',
    }
}

INSTALLED_APPS = (
    'mist.api.keys',
)

SECRET_KEY = 'REPLACE_ME'