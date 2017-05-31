import re
import json
import time
import logging
import requests

from tornado.httputil import url_concat
from tornado.httpclient import AsyncHTTPClient

from mist.api.config import INFLUX
from mist.api.helpers import iso_to_seconds
from mist.api.helpers import trigger_session_update

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ServiceUnavailableError

from mist.api.machines.models import Machine


log = logging.getLogger(__name__)


AGGREGATORS = set((
    'MEAN',
))


def aggregate(query, field, func='MEAN'):
    """Apply aggregator `func` on field `field` of the provided query."""
    assert func.upper() in AGGREGATORS, 'Aggregator "%s" not supported' % func
    return query.replace(field, '%s(%s)' % (func.upper(), field))


def filter(query, fields=None, start='', stop=''):
    """Add a filter to the query.

    This method adds a "WHERE" clause to the provided InfluxDB query based
    on the `fields` dictionary. The values of `fields` may be either single
    terms, a regex, or a list, whose individual terms will be ORed together.
    The final list of filters is joined together by a logical AND.

    """
    filters = []
    or_stmt = []
    assert isinstance(fields, dict)
    for key, value in fields.iteritems():
        if isinstance(value, list):
            or_stmt = ['"%s" = \'%s\'' % (key, val) for val in value]
        elif re.match('^/.*/$', value):  # re.match('/.*/', value):
            filters.append('"%s" =~ %s' % (key, value))
        else:
            filters.append('"%s" = \'%s\'' % (key, value))
    if or_stmt:
        filters.append('(%s)' % ' OR '.join(or_stmt))
    if stop:
        filters.insert(0, '"time" =< now() - %s' % stop)
    if start:
        filters.insert(0, '"time" >= now() - %s' % start)
    return '%s WHERE %s' % (query, ' AND '.join(filters))


def group(query, fields=None, step=None):
    """Group results by `fields` and/or `step`."""
    if fields is None:
        fields = []
    if isinstance(fields, basestring):
        fields = [fields]
    fields = ['"%s"' % f for f in fields]
    if step:
        fields.insert(0, 'time(%s)' % step)
    return '%s GROUP BY %s' % (query, ','.join(fields)) if fields else query


class BaseStatsHandler(object):
    """A generic handler for querying InfluxDB and processing series."""

    group = None

    influx = '%(host)s/query?db=%(db)s' % INFLUX

    def __init__(self, machine):
        """Initialize self bound to `machine`."""
        self.machine = machine

        self.column = None
        self.measurement = None

    def get_stats(self, metric, start=None, stop=None, step=None,
                  callback=None, tornado_async=False):
        """Query InfluxDB for the given metric."""
        if step and not (stop or start):
            raise BadRequestError('Aggregate functions with "GROUP BY time" '
                                  'also require a "WHERE time" clause')

        # Get the measurement and requested column(s). Update tags.
        self.measurement, self.column, tags = self.parse_path(metric)

        # Construct query.
        q = 'SELECT %s FROM %s' % (self.column, self.measurement)
        if step:
            q = aggregate(q)
        q = group(filter(q, tags, start, stop), self.group, step)

        if not tornado_async:
            data = requests.get(self.influx, params=dict(q=q))
            if not data.ok:
                log.error('Got %d HTTP status code on get_stats: %s',
                          data.status_code, data.content)
                if data.status_code == 400:
                    raise BadRequestError()
                raise ServiceUnavailableError()
            if callback is not None:
                return callback(self._on_stats_callback(data.json()))
            return self._on_stats_callback(data.json())

        def _on_tornado_response(resp):
            if resp.code != 200:
                log.error('Code %d on get_stats: %s', resp.code, resp.body)
                if resp.code == 400:
                    raise BadRequestError()
                raise ServiceUnavailableError()
            return callback(self._on_stats_callback(json.loads(resp.body)))

        AsyncHTTPClient().fetch(url_concat(self.influx, dict(q=q)),
                                callback=_on_tornado_response)

    def parse_path(self, metric):
        """Parse metric to extract the measurement, column, and tags."""
        if isinstance(self.machine, Machine):
            tags = {'machine_id': self.machine.id}
        else:
            tags = {'machine_id': self.machine}

        measurement, fields = metric.split('.', 1)
        fields = fields.split('.')
        column = fields[-1]
        if len(fields) > 1:
            for tag in fields[:-1]:
                tag = tag.split('=')
                if len(tag) is not 2:
                    log.error('%s got unexpected tag: %s',
                              self.__class__.__name__, tag)
                    continue
                tags[tag[0]] = tag[1]

        return measurement, column, tags

    def _on_stats_callback(self, data):
        """Process series returned by InfluxDB."""
        results = {}
        for result in data.get('results', []):
            for series in result.get('series', []):
                # Get series name and columns.
                measurement = series.get('name', self.measurement)
                columns = series.get('columns', [])
                # Get tags, if exist.
                tags = '.'.join(['%s=%s' % (key, val) for key, val in
                                 series.get('tags', {}).iteritems()])
                for value in series.get('values', []):
                    timestamp = iso_to_seconds(value[0])
                    for index, point in enumerate(value):
                        if index == 0:  # Skip the "time" column.
                            continue
                        name = measurement.upper()
                        column = columns[index]
                        if column == 'mean':  # This is not very descriptive.
                            column = 'mean_%s' % self.column
                        if tags:
                            id = '%s.%s.%s' % (measurement, tags, column)
                            name += ' %s' % ' '.join(series['tags'].values())
                        else:
                            id = '%s.%s' % (measurement, column)
                        name += ' %s' % column.replace('_', ' ')
                        if id not in results:
                            results[id] = {
                                'name': name,
                                'column': column,
                                'measurement': measurement,
                                'datapoints': [],
                                'max_value': None,
                                'min_value': None,
                                'priority': 0,
                                'unit': '',
                            }
                        results[id]['datapoints'].append(((point, timestamp)))
        return results


class MainStatsHandler(BaseStatsHandler):

    def __init__(self, machine):
        super(MainStatsHandler, self).__init__(machine)
        assert isinstance(self.machine, Machine)

    def _on_stats_callback(self, data):
        results = super(MainStatsHandler, self)._on_stats_callback(data)
        self._update_status(results)
        return results

    def _update_status(self, results):
        """Update the InstallationStatus of self.machine.

        Update `self.machine.monitoring.installation_status` and set proper
        activation timestamps, once monitoring data is available.

        """
        owner = self.machine.owner
        istatus = self.machine.monitoring.installation_status
        if not istatus.activated_at:
            for value in results.itervalues():
                for point in value['datapoints']:
                    if point[0] is not None and point[1] >= istatus.started_at:
                        if not istatus.finished_at:
                            istatus.finished_at = time.time()
                        istatus.activated_at = time.time()
                        istatus.state = 'succeeded'
                        self.machine.save()
                        trigger_session_update(owner, ['monitoring'])
                        return


class CPUHandler(MainStatsHandler):

    group = 'cpu'


class DiskHandler(MainStatsHandler):

    group = 'device'


class DiskIOHandler(MainStatsHandler):

    group = 'name'


class NetworkHandler(MainStatsHandler):

    group = 'interface'


class MultiLoadHandler(BaseStatsHandler):

    group = 'machine_id'

    def _on_stats_callback(self, data):
        results = {}
        for result in data.get('results', []):
            for series in result.get('series', []):
                # Get series name and columns.
                measurement = series.get('name', self.measurement)
                columns = series.get('columns', [])
                # Get machine_id in order to groub results by it.
                machine_id = series.get('tags', {}).get('machine_id')
                if not machine_id:
                    log.error('%s: no machine_id', self.__class__.__name__)
                    continue
                # Get datapoints.
                for value in series.get('values', []):
                    timestamp = iso_to_seconds(value[0])
                    for index, point in enumerate(value):
                        if index == 0:
                            continue
                        column = columns[index]
                        if column == 'mean':
                            column = 'mean_%s' % self.column
                        name = measurement.upper()
                        name += ' %s' % column.replace('_', ' ')
                        if machine_id not in results:
                            results[machine_id] = {
                                'id': '%s.%s' % (measurement, column),
                                'name': machine_id,
                                'column': column,
                                'measurement': measurement,
                                'datapoints': [],
                                'max_value': None,
                                'min_value': None,
                                'priority': 0,
                                'unit': '',
                            }
                        results[machine_id]['datapoints'].append(((point,
                                                                   timestamp)))
        return results


# Map of measurement types to corresponding handler subclasses for
# special processing needs.
HANDLERS = {
    'cpu': CPUHandler,
    'net': NetworkHandler,
    'disk': DiskHandler,
    'diskio': DiskIOHandler,
}
