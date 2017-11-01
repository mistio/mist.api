import logging
import requests

import mist.api.config as config


log = logging.getLogger(__name__)


def compute2(operator, aggregate, values, threshold):
    # Apply avg before operator.
    if aggregate == 'avg':
        values = [float(sum(values)) / len(values)]

    if operator == 'gt':
        retval = max(values)
        if aggregate == 'all':
            triggered = min(values) > threshold
        else:
            triggered = max(values) > threshold
    if operator == 'lt':
        retval = min(values)
        if aggregate == 'all':
            triggered = max(values) < threshold
        else:
            triggered = min(values) < threshold

    return triggered, retval


# TODO move to methods.py
def compute(operator, aggregate, values, threshold):
    if aggregate == 'avg':  # Apply avg before operator.
        values = [float(sum(values)) / len(values)]
    if operator == 'gt':
        states = {value: value > threshold for value in values}
    elif operator == 'lt':
        states = {value: value < threshold for value in values}
    if aggregate == 'all':
        state = False not in states.values()
        if not state:  # Find retval from false values.
            values = [value for value, _state in states.items() if not _state]
    else:
        state = True in states.values()
    if operator == 'gt':
        retval = max(values)
    elif operator == 'lt':
        retval = min(values)
    return state, retval


def send_trigger(rule_id, params):
    """"""
    resp = requests.put(
        '%s/api/v1/rules/%s/trigger'  % (config.CORE_URI, rule_id),
        headers={'Cilia-Secret-Key': config.CILIA_SECRET_KEY}, params=params
    )
    if not resp.ok:
        log.error('mist.api.rules.methods:send_trigger failed with '
                  'status code %d: %s', resp.status_code, resp.content)
    return resp.ok
