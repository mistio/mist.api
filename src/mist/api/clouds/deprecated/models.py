import mongoengine as me
from mist.api.clouds.models import Cloud
from mist.api.clouds.controllers.main.base import BaseMainController
from mist.api.clouds.controllers.compute.base import BaseComputeController


class DummyComputeController(BaseComputeController):
    provider = 'dummy'


class DummyMainController(BaseMainController):
    provider = 'dummy'
    ComputeController = DummyComputeController


class GigG8Cloud(Cloud):
    apikey = me.StringField(required=True)
    user_id = me.IntField(required=True)
    url = me.StringField(required=True)
    _private_fields = ('apikey', )
    _controller_cls = DummyMainController


class VCloud(Cloud):
    host = me.StringField(required=True)
    username = me.StringField(required=True)
    password = me.StringField(required=True)
    port = me.IntField(required=True, default=443)
    _private_fields = ('password', )
    _controller_cls = DummyMainController
