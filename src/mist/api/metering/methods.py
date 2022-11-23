import logging
import datetime
import requests

from mist.api import config

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ServiceUnavailableError


log = logging.getLogger(__name__)


def _query_cores(start, end, owner_id=''):
    """Get the total number of cores from `start` to date

    The result will also include the total price per day grouped by owner_id.
    The cost's query is executed alongside the cores' to facilitate comfort.

    """
    query = "SELECT"
    query += " MAX(cores) AS cores,"
    query += " MAX(cost) AS cost "
    query += "FROM usage"
    query += " WHERE time >= '%s'" % start.isoformat(sep=' ')
    query += " AND time < '%s'" % end.isoformat(sep=' ')
    if owner_id:
        query += " AND owner = '%s' " % owner_id
    query += "GROUP BY time(1d)"
    if not owner_id:
        query += ",owner"

    return _query_influxdb(query, owner_id)


def _query_checks(start, end, owner_id=''):
    """Get the number of rules checks from `start` to `end` in 1-day windows"""
    series = []
    assert (isinstance(end, datetime.datetime) and
            isinstance(start, datetime.datetime))
    while start < end:
        stop = start + datetime.timedelta(days=1)
        results = _query_influxdb(
            _get_checks_or_datapoints_query('checks',
                                            start, stop, owner_id), owner_id
        )
        series.append(('%sZ' % start.isoformat(), results))
        start += datetime.timedelta(days=1)
    return _parse_checks_or_datapoints_series(series, 'checks', owner_id)


def _query_datapoints(start, end, owner_id=''):
    """Get the number of datapoints from `start` to `end` in 1-day windows"""
    series = []
    assert (isinstance(end, datetime.datetime) and
            isinstance(start, datetime.datetime))
    while start < end:
        stop = start + datetime.timedelta(days=1)
        results = _query_influxdb(
            _get_checks_or_datapoints_query('datapoints',
                                            start, stop, owner_id), owner_id
        )
        series.append(('%sZ' % start.isoformat(), results))
        start += datetime.timedelta(days=1)
    return _parse_checks_or_datapoints_series(series, 'datapoints', owner_id)


def _get_checks_or_datapoints_query(field, start, end, owner_id=''):
    """Return the query for fetching the number of checks or datapoints

    This method is meant to only be invoked by the methods `_query_checks`
    and `_query_datapoints`. It returns the query (as a string) used to
    calculate the number of rules' checks or datapoints per day.

    """
    assert field in ('checks', 'datapoints', ), field
    assert isinstance(start, datetime.datetime)
    assert isinstance(end, datetime.datetime)

    query = "SELECT MEAN(rate) * 60 * 60 * 24 AS %s " % field
    query += "FROM ("
    query += " SELECT NON_NEGATIVE_DERIVATIVE(%s, 1s) AS rate" % field
    query += " FROM usage"
    query += " WHERE time >= '%s'" % start.isoformat(sep=' ')
    query += " AND time < '%s'" % end.isoformat(sep=' ')
    if owner_id:
        query += " AND owner = '%s'" % owner_id
    else:
        query += " GROUP BY owner"
    query += ")"
    if not owner_id:
        query += " GROUP BY owner"

    return query


def _parse_checks_or_datapoints_series(results, field, owner_id=''):
    """Parse the `results` of an InfluxDB query on `field`

    This method is meant to only be invoked by the methods `_query_checks`
    and `_query_datapoints`. It returns the results of the corresponding
    query in a common format after backfilling missing points in the series.

    """
    assert field in ('checks', 'datapoints', )
    data = {}

    # Group cores, checks, and datapoints by owner.
    for start_iso, result in results:
        for series in result:
            values = series.get('values', [])
            assert len(values) == 1, 'Expected a single value. Got %s' % values
            value = values[0][-1]
            value = int(round(value)) if value else None
            owner = series.get('tags', {}).get('owner', owner_id)
            data.setdefault(owner, []).append([start_iso, value])

    # Backfill missing points with None.
    for start_iso, result in results:
        for values in list(data.values()):
            timestamps = set(v[0] for v in values)
            if start_iso not in timestamps:
                values.append([start_iso, None])

    # Return results per owner.
    return [
        {
            'columns': ['time', field],
            'name': 'usage',
            'tags': {
                'owner': o,
            },
            'values': values
        } for o, values in data.items()
    ]


def _merge_series(ensure_keys=None, *series_lists):
    """Merge all series in `series_lists` in `data`"""
    data = {}
    ensure_keys = ensure_keys or []
    assert isinstance(ensure_keys, list)

    # Group series per date.
    for series_list in series_lists:
        for series in series_list:
            for value in series.get('values', []):
                usage = {k: v for k, v in zip(series['columns'], value)}
                date = usage.pop('time')
                if date not in data:
                    data[date] = usage
                else:
                    for k, v in list(usage.items()):
                        if k not in data[date] or data[date][k] is None:
                            data[date][k] = v
                        elif v is not None:
                            data[date][k] += v

    # Ensure keys exists. This is mostly to ensure compatibility.
    for _, usage in data.items():
        for key in ensure_keys:
            usage.setdefault(key)

    return data


def _query_influxdb(query, owner_id):
    # Prepare base URL.
    url = '%s/query?db=metering' % config.INFLUX['host']

    # Request metering info.
    results = requests.get('%s&q=%s' % (url, query))
    if not results.ok:
        log.error('Failed to execute query "%s": %s', query, results.content)
        if results.status_code == 400:
            raise BadRequestError()
        raise ServiceUnavailableError()

    # Get the `results` key. If the query is valid, this shouldn't fail. Even
    # if InfluxDB returns an empty response, the `results` key should be there.
    results = results.json()
    results = results['results']

    try:
        series_list = results[0]['series']
    except IndexError:
        # raise BadRequestError('Failed to parse results: %s' % results)
        log.error('Failed to parse results: %s', results)
        series_list = []
    except KeyError:
        series_list = []
    else:
        if owner_id and len(series_list) > 1:
            raise BadRequestError("Got multiple series for single owner.")
    return series_list


def get_usage(owner_id='', full_days=6):
    """Request metering data

    If no owner_id is specified, then sum for all owners.

    """
    assert isinstance(full_days, int)

    # Get the start and end timestamps of the samples' range.
    now = datetime.datetime.utcnow()
    today = datetime.datetime(year=now.year, month=now.month, day=now.day)

    start = today - datetime.timedelta(days=full_days)
    end = today + datetime.timedelta(days=1)

    # Get all metrics.
    parts = []
    for func in (_query_cores, _query_checks, _query_datapoints):
        part = func(start, end, owner_id)
        parts.append(part)

    # Merge series.
    data = _merge_series(['cores', 'checks', 'datapoints'], *parts)

    return [
        {
            'date': d,
            'cost': data[d].pop('cost', 0),
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
