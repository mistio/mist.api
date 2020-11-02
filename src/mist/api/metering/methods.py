import logging
import datetime
import requests

from mist.api import config
from mist.api.models import Organization


log = logging.getLogger(__name__)


def _merge_series(ensure_keys=None, *series_lists):
    """Merge all series in `series_lists` in `data`"""
    data = {}
    ensure_keys = ensure_keys or []
    assert isinstance(ensure_keys, list)

    # Group series per date.
    for series_list in series_lists:
        for key, series in series_list.items():
            metric = key.split('.')[-1]
            for value, timestamp in series:
                dt = str(datetime.datetime.fromtimestamp(timestamp))
                if data.get(dt):
                    data[dt][metric] = value
                else:
                    data[dt] = {metric: value}

    # Ensure keys exists. This is mostly to ensure compatibility.
    for _, usage in data.items():
        for key in ensure_keys:
            usage.setdefault(key)

    return data


def get_usage(owner_id, full_days=6):
    """Request metering data

    If no owner_id is specified, then sum for all owners.

    """
    assert isinstance(full_days, int)

    # Get all metrics.
    parts = []
    metrics = ['cores', 'checks', 'datapoints']
    for metric in metrics:
        query = (
            f"fetch('{owner_id}.usage.{metric}',"
            f"start='-{full_days}days', stop='', step='1days')"
        )
        try:
            result = requests.get(
                "%s/v1/metering/datapoints?query=%s" % (
                    config.TSFDB_URI, query),
                headers={'x-org-id': owner_id},
                timeout=15
            )
            if not result.ok:
                raise Exception(f"Could not fetch usage.{metric} from TSFDB")
            result = result.json()
            parts.append(result['series'])
        except Exception as exc:
            log.error('Failed upon datapoints metering: %r', exc)

    # Merge series.
    data = _merge_series(['cores', 'checks', 'datapoints'], *parts)

    stop = datetime.datetime.now()
    stop = stop.replace(hour=0, minute=0, second=0, microsecond=0)
    start = stop - datetime.timedelta(days=full_days - 1)

    result = []
    dt = start
    usage_empty = {metric: 0 for metric in metrics}
    while dt <= stop:
        result.append({
            'date': str(dt),
            'cost': data.get(str(dt), {}).pop('cost', 0),
            'usage': data.get(str(dt), usage_empty)
        })
        dt += datetime.timedelta(days=1)

    return result


def get_current_portal_usage():
    metrics = ['cores', 'checks', 'datapoints']
    result = {}
    for metric in metrics:
        result.setdefault(metric, 0)
    for org in Organization.objects():
        usage = get_usage(owner_id=org.id, full_days=2)
        current = usage[-2]['usage']
        for k in current:
            if current[k] is not None:
                result[k] += current[k]
    return result
