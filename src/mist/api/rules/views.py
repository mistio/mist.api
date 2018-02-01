import logging

from pyramid.response import Response

from mist.api.helpers import view_config
from mist.api.helpers import get_datetime
from mist.api.helpers import params_from_request
from mist.api.helpers import trigger_session_update
from mist.api.methods import rule_triggered

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import UnauthorizedError
from mist.api.exceptions import InternalServerError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.rules.models import Rule
from mist.api.rules.models import MachineMetricRule

from mist.api.auth.methods import auth_context_from_request

from mist.api.machines.models import Machine

from mist.api import config


log = logging.getLogger(__name__)


def _get_transformed_params(auth_context, params):
    # Sanitize reminder_offset.
    reminder_offset = params.get('reminder_offset') or 0
    try:
        reminder_offset = int(reminder_offset)
        if reminder_offset < 0:
            raise ValueError()
        reminder_offset -= reminder_offset % 60
    except (ValueError, TypeError):
        raise BadRequestError('Invalid value for mins: %r' % reminder_offset)

    # Sanitize threshold value.
    try:
        value = float(params.get('value') or 0)
    except ValueError:
        raise BadRequestError('Invalid value: %s' % params.get('value'))

    # Clean e-mail addresses.
    emails = params.get('emails') or []
    if not isinstance(emails, list):
        emails = [emails]
    emails = [e.strip() for e in emails if e.strip()]

    # Get list of user/team IDs.
    teams = params.get('users') or []
    users = params.get('teams') or []
    if not isinstance(teams, list):
        raise BadRequestError('"teams" must be a list of Team UUIDs')
    if not isinstance(users, list):
        raise BadRequestError('"users" must be a list of User UUIDs')

    # Get metric.
    metric = params.get('metric')
    metric = {
        'cpu': 'cpu.total.nonidle',
        'load': 'load.shortterm',
        'ram': 'memory.nonfree_percent',
        'disk-read': 'disk.total.disk_octets.read',
        'disk-write': 'disk.total.disk_octets.write',
        'network-rx': 'interface.total.if_octets.rx',
        'network-tx': 'interface.total.if_octets.tx',
    }.get(metric, metric)

    # Verify machine ownership.
    cloud_id = params.get('cloudId') or params.get('cloud')
    machine_id = params.get('machineId') or params.get('machine')
    try:
        machine = Machine.objects.get(owner=auth_context.owner, cloud=cloud_id,
                                      machine_id=machine_id)
    except Machine.DoesNotExist:
        raise NotFoundError('Machine %s does not exist' % machine_id)

    # Transform params.
    kwargs = {
        'queries': [{
            'target': metric,
            'operator': params.get('operator'),
            'threshold': value,
            'aggregation': params.get('aggregate', 'all'),
        }],
        'window': {
            'start': reminder_offset + 60,
            'period': 'seconds',
        },
        'frequency': {
            'every': reminder_offset + 60,
            'period': 'seconds',
        },
        'actions': [
            {
                'type': 'notification',
                'emails': emails,
                'users': users,
                'teams': teams,
            },
        ],
        'conditions': [
            {
                'type': 'machines',
                'ids': [machine.id],
            },
        ],
    }
    if params.get('action') == 'command':
        kwargs['actions'].append({'type': 'command',
                                  'command': params.get('command')})
    if params.get('action') in ('reboot', 'destroy', ):
        kwargs['actions'].append({'type': 'machine_action',
                                  'action': params.get('action')})
    return kwargs


@view_config(route_name='api_v1_rules', request_method='POST', renderer='json')
def add_rule(request):
    """Add a new rule

    READ permission required on cloud
    EDIT_RULES permission required on machine

    DEPRECATION WARNING This API endpoint is deprecated. A new JSON schema
    will soon be put in use in order to add new rules. Also, a discrete API
    endpoint will be introduced for updating existing rules.

    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)

    # Pyramid's `NestedMultiDict` is immutable.
    kwargs = _get_transformed_params(auth_context, dict(params.copy()))

    # FIXME Have a discrete API endpoint for updates.
    title = params.get('id')
    if title:
        try:
            rule = Rule.objects.get(owner_id=auth_context.owner.id,
                                    title=title)
            rule.ctl.set_auth_context(auth_context)
            rule.ctl.update(save=False, **kwargs)
        except Rule.DoesNotExist:
            raise NotFoundError()
    else:
        # Add new rule.
        rule = MachineMetricRule.add(auth_context, **kwargs)

        # FIXME Deprecated counter used for rules' titles.
        auth_context.owner.rule_counter += 1
        auth_context.owner.save()

    # FIXME Remove alongside the old alert service.
    if config.HAS_CORE:
        from mist.core.methods import _push_rule
        if not _push_rule(rule.owner, rule.title):
            if not title:
                rule.delete()
            raise InternalServerError()
    if title:
        rule.save()

    rdict = rule.as_dict_old()
    rdict['id'] = rule.rule_id

    trigger_session_update(auth_context.owner, ['monitoring'])
    return rdict


@view_config(route_name='api_v1_rule', request_method='DELETE')
def delete_rule(request):
    """Delete a rule given its UUID

    READ permission required on Cloud
    EDIT_RULES permission required on Machine

    ---

    rule:
      in: path
      type: string
      required: true
      description: the unique identifier of the rule to be deleted

    """
    auth_context = auth_context_from_request(request)
    rule_id = request.matchdict.get('rule')  # FIXME uuid, not title!
    try:
        rule = Rule.objects.get(owner_id=auth_context.owner.id, title=rule_id)
        rule.ctl.set_auth_context(auth_context)
        rule.ctl.delete()
    except Rule.DoesNotExist:
        raise NotFoundError()
    return Response('OK', 200)


@view_config(route_name='api_v1_rule_triggered', request_method='PUT')
def triggered(request):
    """Process a trigger sent by the alert service

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

    rule_triggered(machine, rule.title, value, triggered, timestamp,
                   notification_level, incident_id=incident_id)
    return Response('OK', 200)
