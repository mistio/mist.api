import logging
import requests

from mist.api import config

from mist.api.helpers import view_config
from mist.api.helpers import params_from_request

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ServiceUnavailableError

from mist.api.auth.methods import auth_context_from_request


log = logging.getLogger(__name__)


@view_config(
    route_name='api_v1_metering', request_method='GET', renderer='json'
)
def metering(request):
    """Request metering data"""
    auth_context = auth_context_from_request(request)
    start = params_from_request(request).get('start', '6d')  # 1 week default.

    # Prepare base URL.
    url = '%(host)s/query?db=metering' % config.INFLUX

    # Prepare query.
    query = 'SELECT'
    query += ' MAX(cores) AS cores,'
    query += ' NON_NEGATIVE_DERIVATIVE(MAX(checks)) AS checks '
    query += 'FROM usage'
    query += ' WHERE "time" >= now() - %s' % start
    query += ' AND "owner" = \'%s\' ' % auth_context.owner.id
    query += 'GROUP BY time(1d) fill(0)'

    # Request metering info.
    results = requests.get('%s&q=%s' % (url, query))
    if not results.ok:
        log.error('Failed to execute query "%s": %s', query, results.content)
        if results.status_code == 400:
            raise BadRequestError()
        raise ServiceUnavailableError()

    try:
        results = results.json()
        results = results['results'][0]['series'][0]
        columns = results['columns']
    except (KeyError, IndexError):
        log.error('Failed to parse results: %s', results)
        raise BadRequestError()

    data = []
    for value in results.get('values', []):
        usage = {k: v for k, v in zip(columns, value)}
        data.append({'date': usage.pop('time'), 'usage': usage})
    return data
