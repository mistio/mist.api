import logging

from pyramid.response import Response

from mist.api.helpers import view_config
from mist.api.helpers import get_datetime
from mist.api.helpers import params_from_request

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import UnauthorizedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.rules.models import Rule
from mist.api.machines.models import Machine


log = logging.getLogger(__name__)


@view_config(route_name='api_v1_rule_triggered', request_method='PUT')
def triggered(request):
    """
    Takes action based on a rule being triggered.
    ---
    machine_uuid: we need it to find the user
    machine_password: monitor authenticates to us using the same password the
                      machine uses to authenticate to collectd server
    notification_level: int declaring which time this is that the rule is
                being triggered
    triggered: True => Warning, False => back to normal
    since: state since this timestamp
    value: current value of condition metric

    """
    from ipdb import set_trace; set_trace()

    ## XXX SEC Do not publicly expose this API endpoint?
    #if config.GOCKY_SECRET_KEY != request.headers.get('Gocky-Secret-Key'):
    #    raise UnauthorizedError('Internal')

    rule_id = request.matchdict['rule']
    params = params_from_request(request)

    # Verify required parameters are present.
    keys = (
        'value',
        'incident',
        'resource',
        'triggered',
        'triggered_now',
        'firing_since',
        'pending_since',
        'resolved_since',
    )
    for key in keys:
        if key not in params:
            raise RequiredParameterMissingError(key)

    try:
        value = params['value']
        value = float(value)
    except (TypeError, ValueError) as err:
        pass
        #log.error()
        #raise BadRequestError()

    # Get resource and incidents ids.
    incident_id = str(params['incident'])
    resource_id = str(params['resource'])

    # Get timestamps.
    firing_since = str(params['firing_since'])
    pending_since = str(params['pending_since'])
    resolved_since = str(params['resolved_since'])

    def int_to_bool(param):
        try:
            return bool(int(param or 0))
        except (ValueError, TypeError) as err:
            log.error('Failed to cast int to bool: %r', err)
            raise BadRequestError('Failed to convert %s to boolean' % param)

    # Get flags indicating whether the incident has been (just) triggered.
    triggered = int_to_bool(params['triggered'])
    triggered_now = int_to_bool(params['triggered_now'])

    # FIXME For backwards compatibility.
    notification_level = 0 if triggered_now else 1
    try:
        timestamp = int(get_datetime(firing_since).strftime('%s'))
    except ValueError as err:
        log.error('Failed to cast datetime obj to unix timestamp: %r', err)
        raise BadRequestError(err)

    try:
        machine = Machine.objects.get(id=resource_id)  # missing_since=None?
    except Machine.DoesNotExist:
        raise NotFoundError('Machine with id %s does not exist' % machine_uuid)

    try:
        owner = machine.cloud.owner
    except AttributeError:
        raise NotFoundError('Machine with id %s does not exist' % machine_uuid)

    if machine.cloud.deleted:
        raise NotFoundError('Machine with id %s does not exist' % machine_uuid)

    if not machine.monitoring.hasmonitoring:
        raise NotFoundError('%s does not have monitoring enabled' % machine)

    try:
        rule = Rule.objects.get(id=rule_id, owner_id=machine.owner.id)
    except Rule.DoesNotExist:
        raise NotFoundError('Rule with id %s does not exist' % rule_id)

    try:
        from mist.core.methods import rule_triggered
    except ImportError:
        raise NotImplementedError()
    else:
        rule_triggered(
            machine.owner, machine.cloud.id, machine.machine_id, rule.title,
            value, triggered, timestamp, notification_level,
            incident_id=incident_id
        )
    return Response('OK', 200)
