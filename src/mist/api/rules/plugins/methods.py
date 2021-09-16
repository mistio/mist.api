import logging
import requests

import mist.api.config as config


log = logging.getLogger(__name__)


class ResourceNotFoundError(Exception):
    pass


class EmptyResponseReturnedError(Exception):
    pass


class MultipleSeriesReturnedError(Exception):
    pass


class RequestedTargetMismatchError(Exception):
    pass


def compute(operator, aggregate, values, threshold):
    """Compare the `values` against the specified `threshold`."""
    if aggregate == 'avg':  # Apply avg aggregator before the operator.
        values = [float(sum(values)) / len(values)]

    if operator == 'gt':
        states = {value: value > float(threshold) for value in values}
    elif operator == 'lt':
        states = {value: value < float(threshold) for value in values}
    elif operator == 'eq':
        states = {value: value == float(threshold) for value in values}
    elif operator == 'ne':
        states = {value: value != float(threshold) for value in values}

    if aggregate == 'all':
        state = False not in list(states.values())
        if not state:  # If not triggered, find the retval from False values.
            values = [value for value, _state in list(states.items())
                      if not _state]
    else:
        state = True in list(states.values())

    if operator == 'gt':
        retval = max(values)
    elif operator == 'lt':
        retval = min(values)
    elif operator == 'eq':
        retval = threshold if state else values[0]
    elif operator == 'ne':
        retval = values[0] if state else threshold

    return state, retval


def send_trigger(rule_id, params):
    """Trigger the rule with id `rule_id` and the provided params over HTTP."""
    params.update({'rule_id': rule_id})  # TODO This should be part of the URL.
    resp = requests.put(
        '%s/api/v1/rule-triggered' % config.CILIA_TRIGGER_API,
        headers={'Cilia-Secret-Key': config.CILIA_SECRET_KEY}, params=params
    )
    if not resp.ok:
        log.error('mist.api.rules.plugins.methods:send_trigger failed with '
                  'status code %d: %s', resp.status_code, resp.text)
        if resp.status_code == 404:
            raise ResourceNotFoundError()
