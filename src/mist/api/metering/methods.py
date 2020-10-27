import logging
import datetime
import requests

from mist.api import config

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ServiceUnavailableError


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


def get_usage(owner_id='', full_days=6):
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
