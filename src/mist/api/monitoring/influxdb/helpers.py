"""Here we define helper methods that help us explore the schema of InfluxDB,
including information on measurements, field keys and their values, and tags"""

import logging
import requests

from mist.api.config import INFLUX
from mist.api.exceptions import ServiceUnavailableError

log = logging.getLogger(__name__)


def show_measurements(machine_id=None):
    """Return a list of measurements filtered by machine_id, if provided."""
    q = 'SHOW MEASUREMENTS'
    q += ' WHERE "machine_id" = \'%s\'' % machine_id if machine_id else ''
    url = '%(host)s/query?db=%(db)s' % INFLUX
    data = requests.get(url, params=dict(q=q))
    if not data.ok:
        log.error('Got %d on SHOW MEASUR: %s', data.status_code, data.content)
        raise ServiceUnavailableError()
    measurements = set()
    results = data.json().get('results', [])
    if results:
        results = results[0]
        series = results.get('series', [])
    else:
        series = []
    if series:
        values = series[0].get('values', [])
        measurements = set([value[0] for value in values])
    return list(measurements)


def show_fields(measurement=None):
    """Return field keys and their respective values, including tags."""
    # Make sure measurement names are inside quotes to escape special
    # characters, such as "." or "-".
    if isinstance(measurement, list):
        measurement = ','.join(['"%s"' % m for m in measurement])
    elif measurement:
        measurement = '"%s"' % measurement
    q = 'SHOW FIELD KEYS'
    q += ' FROM %s' % measurement if measurement else ''
    url = '%(host)s/query?db=%(db)s' % INFLUX
    data = requests.get('%s&q=%s' % (url, q))
    if not data.ok:
        log.error('Got %d on SHOW FIELDS: %s', data.status_code, data.content)
        raise ServiceUnavailableError()
    fields = []
    results = data.json().get('results', [])
    if results:
        tags = show_tags(measurement)
        results = results[0]
    else:
        results = {}
    for series in results.get('series', []):
        name = series['name']
        for value in series['values']:  # eg. value = [u'load1', u'float']
            pairs = []
            column = value[0]
            for key, values in tags[name].items():
                if key in ('host', 'machine_id', ):
                    continue
                pairs += ['%s=%s' % (key, value) for value in values]
            if pairs:
                ids = ['%s.%s.%s' % (name, pair, column) for pair in pairs]
            else:
                ids = ['%s.%s' % (name, column)]
            for id in ids:
                fields.append({
                    'id': id,
                    'name': '%s %s' % (name.upper(), column.replace('_', ' ')),
                    'column': column,
                    'measurement': name,
                    'max_value': None,
                    'min_value': None,
                    'priority': 0,
                    'unit': '',
                })
    return fields


def show_tags(measurement=None):
    """Return all tags associated with the specified measurement."""
    tags = {}
    for series, keys in show_tag_keys(measurement).items():
        tags[series] = {}
        for key in keys:
            tags[series][key] = show_tag_values(key)
    return tags


def show_tag_keys(measurement=None):
    """Return all tag keys."""
    q = 'SHOW TAG KEYS'
    q += ' FROM %s' % measurement if measurement is not None else ''
    url = '%(host)s/query?db=%(db)s' % INFLUX
    data = requests.get('%s&q=%s' % (url, q))
    if not data.ok:
        log.error('Got %d on SHOW TAG KEY: %s', data.status_code, data.content)
        raise ServiceUnavailableError()
    tags = {}
    results = data.json().get('results', [])
    results = results[0] if results else {}
    for series in results.get('series', []):
        name = series['name']
        if not series['values']:
            continue
        if name not in tags:
            tags[name] = []
        for value in series['values']:
            value = value[0]
            if value not in ('host', 'machine_id', ):
                tags[name].append(value)
    return tags


def show_tag_values(key):
    """Return all tag values of the specified key."""
    q = 'SHOW TAG VALUES WITH KEY = "%s"' % key
    url = '%(host)s/query?db=%(db)s' % INFLUX
    data = requests.get('%s&q=%s' % (url, q))
    if not data.ok:
        log.error('Got %d on SHOW TAG VAL: %s', data.status_code, data.content)
        raise ServiceUnavailableError()
    tags = set()
    results = data.json().get('results', [])
    results = results[0] if results else {}
    for series in results.get('series', []):
        for value in series['values']:
            tags.add(value[1])
    return list(tags)
