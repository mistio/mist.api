import re
import json
import time
import logging
import requests

from future.utils import string_types

from tornado.httputil import url_concat
from tornado.httpclient import AsyncHTTPClient

from mist.api.config import INFLUX
from mist.api.helpers import iso_to_seconds

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ServiceUnavailableError

from mist.api.machines.models import Machine

from mist.api.monitoring.influxdb.helpers import notify_machine_monitoring


log = logging.getLogger(__name__)


AGGREGATIONS = set((
    'MEAN',
))


TRANSFORMATIONS = set((
    'DERIVATIVE',
    'NON_NEGATIVE_DERIVATIVE',
))


def aggregate(query, field, func='MEAN'):
    """Apply aggregator `func` on field `field` of the provided query."""
    assert func.upper() in AGGREGATIONS, 'Aggregator "%s" not supported' % func
    return query.replace(field, '%s(%s)' % (func.upper(), field))


def add_filter(query, fields=None, start='', stop=''):
    """Add a filter to the query.

    This method adds a "WHERE" clause to the provided InfluxDB query based
    on the `fields` dictionary. The values of `fields` may be either single
    terms, a regex, or a list, whose individual terms will be ORed together.
    The final list of filters is joined together by a logical AND.

    """
    filters = []
    or_stmt = []
    assert isinstance(fields, dict)
    for key, value in fields.items():
        if isinstance(value, list):
            or_stmt = ['"%s" = \'%s\'' % (key, val) for val in value]
        elif re.match('^/.*/$', value):
            filters.append('"%s" =~ %s' % (key, value))
        else:
            filters.append('"%s" = \'%s\'' % (key, value))
    if or_stmt:
        filters.append('(%s)' % ' OR '.join(or_stmt))
    if stop:
        try:
            stop = str(int(stop)) + 's'
            filters.insert(0, '"time" <= %s' % stop)
        except ValueError:
            filters.insert(0, '"time" <= now() - %s' % stop)
    if start:
        try:
            start = str(int(start)) + 's'
            filters.insert(0, '"time" > %s' % start)
        except ValueError:
            filters.insert(0, '"time" > now() - %s' % start)

    return '%s WHERE %s' % (query, ' AND '.join(filters))


def group(query, fields=None, step=None):
    """Group results by `fields` and/or `step`."""
    if fields is None:
        fields = []
    if isinstance(fields, string_types):
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
        """Query InfluxDB for the given metric.

        This method, after parsing the metric given, is responsible for
        incrementally constructing the InfluxDB query.

        The provided metric should be in the form of:

            <measurement>.<tags>.<column>

        Also, metrics may be enclosed in nested function, such as:

            MEAN(system.load1)

        or even:

            DERIVATIVE(MEAN(net.bytes_sent))

        """
        # A list of functions, extracted from `metric` to be applied later on.
        functions = []

        # Attempt to match nested functions in `metric` in order to extract the
        # actual metric and store any functions in `functions` so that they can
        # be re-applied later on.
        regex = r'^(\w+)\((.+)\)$'
        match = re.match(regex, metric)
        while match:
            groups = match.groups()
            metric = groups[1]
            functions.append(groups[0].upper())
            match = re.match(regex, metric)

        # Get the measurement and requested column(s). Update tags.
        self.measurement, self.column, tags = self.parse_path(metric)

        # Construct query.
        q = 'SELECT %s' % self.column
        for function in functions:
            if function not in AGGREGATIONS | TRANSFORMATIONS:
                raise BadRequestError('Function %s not supported' % function)
            q = q.replace(self.column, '%s(%s)' % (function, self.column))
        if functions and not re.match('^/.*/$', self.column):  # Not for regex.
            q += ' AS %s' % self.column
        q += ' FROM "%s"' % self.measurement
        q = group(add_filter(q, tags, start, stop), self.group, step)

        if not tornado_async:
            data = requests.get(self.influx, params=dict(q=q))
            log.warn('Query: %s' % q)
            if not data.ok:
                log.error('Got %d HTTP status code on get_stats: %s',
                          data.status_code, data.content)
                log.error('Query: %s' % q)
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
        """Parse metric to extract the measurement, column, and tags.

        This method must be invoked by get_stats, before constructing the
        InfluxDB query, in order to extract the necessary information from
        the given metric, which is in the following format:

            <measurement>.<tags>.<column>

        where <tags> (optional) must be in "key=value" format and delimited
        by ".".

        This method should set `self.measurement` and `self.column` to the
        pure values extracted from `metric`, before any further processing
        takes place.

        Subclasses may override this method in order to edit the resulting
        measurement or column and apply functions to aggregate, select, and
        transform data.

        """
        # Measurement.
        measurement, fields = metric.split('.', 1)
        if not (measurement and fields):
            raise BadRequestError('Invalid metric: %s' % metric)

        # Column.
        fields = fields.split('.')
        column = fields[-1]

        # Tags.
        if isinstance(self.machine, Machine):
            tags = {'machine_id': self.machine.id}
        else:
            tags = {'machine_id': self.machine}

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
            if result.get('error'):
                raise BadRequestError(result['error'])
            for series in result.get('series', []):
                # Get series name and columns.
                measurement = series.get('name', self.measurement)
                columns = series.get('columns', [])
                # Get tags, if exist.
                tags = '.'.join(['%s=%s' % (key, val) for key, val in
                                 series.get('tags', {}).items()])
                for value in series.get('values', []):
                    timestamp = iso_to_seconds(value[0])
                    for index, point in enumerate(value):
                        if index == 0:  # Skip the "time" column.
                            continue
                        if isinstance(point, string_types):  # Skip tags.
                            continue
                        name = measurement.upper()
                        column = columns[index]
                        if tags:
                            id = '%s.%s.%s' % (measurement, tags, column)
                            name += ' %s' % ' '.join(
                                list(series['tags'].values()))
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
        istatus = self.machine.monitoring.installation_status
        if not istatus.activated_at:
            for value in results.values():
                for point in value['datapoints']:
                    if point[0] is not None and \
                       int(point[1]) >= istatus.started_at:
                        if not istatus.finished_at:
                            istatus.finished_at = time.time()
                        istatus.activated_at = time.time()
                        istatus.state = 'succeeded'
                        self.machine.save()
                        owner = self.machine.owner
                        # FIXME Resolve circular imports.
                        from mist.api.rules.tasks import add_nodata_rule
                        add_nodata_rule.delay(owner.id, 'influxdb')
                        notify_machine_monitoring(self.machine)
                        return


class CPUHandler(MainStatsHandler):

    group = 'cpu'


class DiskHandler(MainStatsHandler):

    group = 'device'


class DiskIOHandler(MainStatsHandler):

    group = 'name'

    def get_stats(self, metric, start=None, stop=None, step=None,
                  callback=None, tornado_async=False):
        return super(DiskIOHandler, self).get_stats(
            'NON_NEGATIVE_DERIVATIVE(%s)' % metric,
            start, stop, step, callback, tornado_async
        )


class NetworkHandler(MainStatsHandler):

    group = 'interface'

    def get_stats(self, metric, start=None, stop=None, step=None,
                  callback=None, tornado_async=False):
        return super(NetworkHandler, self).get_stats(
            'NON_NEGATIVE_DERIVATIVE(%s)' % metric,
            start, stop, step, callback, tornado_async
        )


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
