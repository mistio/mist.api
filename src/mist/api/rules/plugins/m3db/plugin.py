import logging

import mist.api.rules.plugins.graphite.plugin as graphite
import mist.api.config as config
from mist.api.rules.plugins import base


log = logging.getLogger(__name__)


class M3dbBackendPlugin(graphite.GraphiteBackendPlugin):

    def __init__(self, rule, rids=None):
        super().__init__(rule, rids=rids)
        self.uri = config.M3DB_URI

    @property
    def window(self):
        return '-%ds' % self.rule.window.timedelta.total_seconds()


class M3dbNoDataPlugin(base.NoDataMixin, M3dbBackendPlugin):
    pass
