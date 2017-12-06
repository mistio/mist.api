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

from mist.api import config


log = logging.getLogger(__name__)


@view_config(route_name='api_v1_rule_triggered', request_method='PUT')
def triggered(request):
    """Process a trigger sent by the alert service.

    Based on the parameters of the request, this method will initiate actions
    to mitigate the conditions that triggered the rule and notify the users.

    ---

      value:
        type: integer
        required: true
        description: >
          the value that triggered the rule by exceeding the threshold
      incident:
        type: string
        required: true
        description: the incident's UUID
      resource:
        type: string
        required: true
        description: the UUID of the resource for which the rule got triggered
      triggered:
        type: integer
        required: true
        description: 0 if the specified incident got resolved/untriggered
      triggered_now:
        type: integer
        required: true
        description: |
          0 in case this is not the first time the specified incident has
          raised an alert
      firing_since:
        type: datetime
        required: true
        description: |
          the time at which the rule raised an alert and sent a trigger to
          this API endpoint
      pending_since:
        type: datetime
        required: true
        description: |
          the time at which the rule evaluated to True and entered pending
          state. A rule can remain in pending state if a TriggerOffset has
          been configured
      resolved_since:
        type: datetime
        required: true
        description: >
          the time at which the incident with the specified UUID resolved

    """
    # FIXME Remove alongside the old alert service.
    if not config.CILIA_TRIGGER:
        return Response('OK', 200)

    # Do not publicly expose this API endpoint?
    if config.CILIA_SECRET_KEY != request.headers.get('Cilia-Secret-Key'):
        raise UnauthorizedError()

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

    # Get the rule's UUID.
    # TODO rule_id = request.matchdict['rule']
    rule_id = params['rule_id']

    # Get resource and incidents ids.
    incident_id = str(params['incident'])
    resource_id = str(params['resource'])

    # Get timestamps.
    firing_since = str(params['firing_since'])
    # pending_since = str(params['pending_since'])
    resolved_since = str(params['resolved_since'])

    try:
        value = params['value']
        value = float(value)
    except (TypeError, ValueError) as err:
        log.error('Failed to cast "%s" to float: %r', value, err)
        raise BadRequestError('Failed to convert %s to float' % value)

    def int_to_bool(param):
        try:
            return bool(int(param or 0))
        except (ValueError, TypeError) as err:
            log.error('Failed to cast int to bool: %r', err)
            raise BadRequestError('Failed to convert %s to boolean' % param)

    # Get flags indicating whether the incident has been (just) triggered.
    triggered = int_to_bool(params['triggered'])
    triggered_now = int_to_bool(params['triggered_now'])

    try:
        machine = Machine.objects.get(id=resource_id)  # missing_since=None?
    except Machine.DoesNotExist:
        raise NotFoundError('Machine with id %s does not exist' % resource_id)

    try:
        machine.cloud.owner
    except AttributeError:
        raise NotFoundError('Machine with id %s does not exist' % resource_id)

    if machine.cloud.deleted:
        raise NotFoundError('Machine with id %s does not exist' % resource_id)

    if not machine.monitoring.hasmonitoring:
        raise NotFoundError('%s does not have monitoring enabled' % machine)

    try:
        rule = Rule.objects.get(id=rule_id, owner_id=machine.owner.id)
    except Rule.DoesNotExist:
        raise NotFoundError('Rule with id %s does not exist' % rule_id)

    # FIXME For backwards compatibility.
    try:
        timestamp = resolved_since or firing_since
        timestamp = int(get_datetime(timestamp).strftime('%s'))
    except ValueError as err:
        log.error('Failed to cast datetime obj to unix timestamp: %r', err)
        raise BadRequestError(err)
    if triggered_now or not triggered:
        notification_level = 0
    else:
        import time
        notification_level = int((time.time() - timestamp) /
                                 rule.frequency.timedelta.total_seconds())
    # /

    try:
        from mist.core.methods import rule_triggered
    except ImportError:
        raise NotImplementedError()
    else:
        rule_triggered(machine, rule.title, value, triggered, timestamp,
                       notification_level, incident_id=incident_id)
    return Response('OK', 200)
