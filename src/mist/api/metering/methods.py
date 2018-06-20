import logging
import datetime

import requests

from mist.api import config

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ServiceUnavailableError


log = logging.getLogger(__name__)


def get_usage(owner_id='', full_days=6):
    """Request metering data

    If no owner_id is specified, then sum for all owners.

    """

    assert isinstance(full_days, int)

    # Get the start of the samples' range.
    now = datetime.datetime.utcnow()
    today = datetime.datetime(year=now.year, month=now.month, day=now.day)
    start = today - datetime.timedelta(days=full_days)

    # Prepare base URL.
    url = '%s/query?db=metering' % config.INFLUX['host']

    # Prepare query.
    query = "SELECT"
    query += " MAX(cores) AS cores,"
    query += " NON_NEGATIVE_DERIVATIVE(MAX(checks)) AS checks,"
    query += " NON_NEGATIVE_DERIVATIVE(MAX(datapoints)) AS datapoints, "
    query += " MAX(cost) AS cost "
    query += "FROM usage"
    query += " WHERE time >= '%s'" % start.isoformat(sep=' ')
    if owner_id:
        query += " AND owner = '%s' " % owner_id
    query += "GROUP BY time(1d)"
    if not owner_id:
        query += ",owner"

    # Request metering info.
    results = requests.get('%s&q=%s' % (url, query))
    if not results.ok:
        log.error('Failed to execute query "%s": %s', query, results.content)
        if results.status_code == 400:
            raise BadRequestError()
        raise ServiceUnavailableError()

    try:
        results = results.json()
        series_list = results['results'][0]['series']
    except (KeyError, IndexError):
        log.error('Failed to execute: %s', query)
        raise BadRequestError('Failed to parse results: %s' % results)

    if owner_id and len(series_list) > 1:
        raise BadRequestError("Got multiple series for single owner.")

    data = {}
    for series in series_list:
        for value in series.get('values', []):
            usage = {k: v for k, v in zip(series['columns'], value)}
            date = usage.pop('time')
            if date not in data:
                data[date] = usage
            else:
                for k, v in usage.items():
                    if k not in data[date] or data[date][k] is None:
                        data[date][k] = v
                    elif v is not None:
                        data[date][k] += v

    return [
        {
            'date': d,
            'cost': data[d].get('cost', 0),
            'usage': data[d]
        } for d in sorted(data)
    ]


def get_current_portal_usage():
    usage = get_usage(owner_id='', full_days=2)
    current = usage[-2]['usage']
    for k in current:
        if current[k] is None:
            current[k] = 0
    return current
