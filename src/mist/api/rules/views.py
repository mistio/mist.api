import logging

from pyramid.response import Response

from mist.api.helpers import view_config
from mist.api.helpers import get_datetime
from mist.api.helpers import params_from_request
from mist.api.methods import rule_triggered

from mist.api.exceptions import NotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import RuleNotFoundError
from mist.api.exceptions import UnauthorizedError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.rules.models import Rule
from mist.api.rules.models import MachineMetricRule

from mist.api.auth.methods import auth_context_from_request

from mist.api.machines.models import Machine

from mist.api.notifications.models import Notification

from mist.api import config


log = logging.getLogger(__name__)


# FIXME Deprecated!
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
    teams = params.get('teams') or []
    users = params.get('users') or []
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
        'selectors': [
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


@view_config(route_name='api_v1_rules', request_method='GET', renderer='json')
def get_rules(request):
    """
    Tags: rules
    ---
    Get a list of all rules
    """
    auth_context = auth_context_from_request(request)
    if not auth_context.is_owner():
        raise UnauthorizedError('Restricted to Owners')
    return [r.as_dict() for r in Rule.objects(owner_id=auth_context.owner.id)]


@view_config(route_name='api_v1_rules', request_method='POST', renderer='json')
def add_rule(request):
    """
    Tags: rules
    ---
    Add a new rule

    READ permission required on Cloud
    EDIT_RULES permission required on Machine

    ---

    queries:
      in: query
      required: true
      description: |
        a list of queries to be evaluated. Queries are chained together with a
        logical AND, meaning that all queries will have to evaluate to True in
        order for the rule to get triggered
      schema:
        type: array
        items:
          type: object
          properties:
            target:
              type: string
              required: true
              description: the metric's name, e.g. "load.shortterm"
            operator:
              type: string
              required: true
              description: |
                the operator used to compare the computed value with the given
                threshold
            threshold:
              type: string
              required: true
              description: the value over/under which an alert will be raised
            aggregation:
              type: string
              required: true
              description: |
                the function to be applied on the computed series. Must be one
                of: all, any, avg

    window:
      in: query
      required: true
      description: the time window of each query
      schema:
        type: object
        properties:
          start:
            type: integer
            required: true
            description: |
              a positive integer denoting the start of the search window in
              terms of "now() - start"
          stop:
            type: integer
            default: 0
            required: false
            description: |
              a positive integer, where stop < start, denoting the end of the
              search window. Defaults to now
          period:
            type: string
            required: true
            description: units of time, e.g. "seconds"

    frequency:
      in: query
      required: true
      description: the frequency of each evaluation
      schema:
        type: object
        properties:
          every:
            type: integer
            required: true
            description: >
              a positive integer denoting how often the rule must be evaluated
          period:
            type: string
            required: true
            description: units of time, e.g. "seconds"

    trigger_after:
      in: query
      required: false
      description: |
        an offset, which prevents an alert from actually being raised, unless
        the threshold is exceeded for "trigger_after" consecutive evaluations
      schema:
        type: object
        properties:
          offset:
            type: integer
            required: true
            description: a positive integer denoting the tolerance period
          period:
            type: string
            required: true
            description: units of time, e.g. "seconds"

    actions:
      in: query
      default: notification
      required: false
      description: |
        a list of actions to be executed once a rule is triggered. Defaults to
        sending a notification
      schema:
        type: array
        items:
          type: object
          properties:
            type:
              type: string
              required: true
              description: >
                the action's type: notification, machine_action, command
            users:
              type: array
              required: false
              description: |
                a list of user to be notified, denoted by their UUIDs. Can be
                used by a notification action (optional)
            teams:
              type: array
              required: false
              description: |
                a list of teams, denoted by their UUIDs, whose users will be
                notified. Can be used by a notification action (optional)
            emails:
              type: array
              required: false
              description: |
                a list of e-mails to send a notification to. Can be used by a
                notification action (optional)
            action:
              type: string
              required: false
              description: >
                the action to be performed. Required by machine_action type
            command:
              type: string
              required: false
              description: >
                the command to be executed. Required by the command type

    selectors:
      in: query
      required: false
      description: |
        a list of selectors to help match resources based on their UUIDs or
        assigned tags. In case of an empty selectors list, the rule will match
        all resources of the corresponding resource type, i.e. all machines
      schema:
        type: array
        items:
          type: object
          properties:
            type:
              type: string
              required: true
              description: one of "machines" or "tags"
            ids:
              type: array
              required: false
              description: a list of UUIDs in case type is "machines"
            tags:
              type: array
              required: false
              description: a list of tags in case type is "tags"

    """
    auth_context = auth_context_from_request(request)
    params = params_from_request(request)

    # Pyramid's `NestedMultiDict` is immutable.
    kwargs = dict(params.copy())
    # kwargs = _get_transformed_params(auth_context, dict(params.copy()))

    # FIXME Remove. Now there is a discrete API endpoint for updates.
    if params.get('id'):
        raise BadRequestError('POST to /api/v1/rules/<rule-id> for updates')

    # Add new rule.
    rule = MachineMetricRule.add(auth_context, **kwargs)

    # FIXME Keep this?
    auth_context.owner.rule_counter += 1
    auth_context.owner.save()

    return rule.as_dict()


@view_config(route_name='api_v1_rule', request_method='POST', renderer='json')
def update_rule(request):
    """
    Tags: rules
    ---
    Update a rule given its UUID

    The expected request body is the same as for the `add_rule` endpoint. The
    difference is that none of the parameters are required. Only the specified
    parameters will be updated, leaving the rest unchanged.

    READ permission required on cloud
    EDIT_RULES permission required on machine

    ---

    rule_id:
      in: path
      type: string
      required: true
      description: the UUID of the rule to be updated

    """
    auth_context = auth_context_from_request(request)
    params = dict(params_from_request(request).copy())
    rule_id = request.matchdict.get('rule')
    try:
        rule = Rule.objects.get(owner_id=auth_context.owner.id, id=rule_id)
        rule.ctl.set_auth_context(auth_context)
        rule.ctl.update(**params)
        Notification.objects(  # Delete related notifications.
            owner=auth_context.owner, rtype='rule', rid=rule_id
        ).delete()
    except Rule.DoesNotExist:
        raise RuleNotFoundError()
    return rule.as_dict()


@view_config(route_name='api_v1_rule', request_method='PUT')
def toggle_rule(request):
    """
    Tags: rules
    ---
    Enable or disable a rule

    Permits Owners to temporarily disable or re-enable a rule's evaluation

    ---

    rule:
      in: path
      type: string
      required: true
      description: the UUID of the rule to be updated

    action:
      in: query
      type: string
      required: true
      description: the action to perform (enable, disable)

    """
    auth_context = auth_context_from_request(request)
    action = params_from_request(request).get('action')
    rule_id = request.matchdict.get('rule')

    if not auth_context.is_owner():
        raise UnauthorizedError('Restricted to Owners')

    if not action:
        raise RequiredParameterMissingError('action')

    if action not in ('enable', 'disable', ):
        raise BadRequestError('Action must be one of (enable, disable)')

    try:
        rule = Rule.objects.get(owner_id=auth_context.owner.id, id=rule_id)
        getattr(rule.ctl, action)()
    except Rule.DoesNotExist:
        raise RuleNotFoundError()
    return Response('OK', 200)


@view_config(route_name='api_v1_rule', request_method='PATCH')
def rename_rule(request):
    """
    Tags: rules
    ---
    Rename a rule

    ---

    rule:
      in: path
      type: string
      required: true
      description: the UUID of the rule to be updated

    title:
      in: query
      type: string
      required: true
      description: the rule's new title

    """
    auth_context = auth_context_from_request(request)
    title = params_from_request(request).get('title')
    rule_id = request.matchdict.get('rule')

    if not auth_context.is_owner():
        raise UnauthorizedError('Restricted to Owners')

    if not title:
        raise RequiredParameterMissingError('title')

    try:
        rule = Rule.objects.get(owner_id=auth_context.owner.id, id=rule_id)
        rule.ctl.rename(title)
    except Rule.DoesNotExist:
        raise RuleNotFoundError()
    return Response('OK', 200)


@view_config(route_name='api_v1_rule', request_method='DELETE')
def delete_rule(request):
    """
    Tags: rules
    ---
    Delete a rule given its UUID.

    READ permission required on Cloud.
    EDIT_RULES permission required on Machine

    ---

    rule:
      in: path
      type: string
      required: true
      description: the unique identifier of the rule to be deleted

    """
    auth_context = auth_context_from_request(request)
    rule_id = request.matchdict.get('rule')
    try:
        rule = Rule.objects.get(owner_id=auth_context.owner.id, id=rule_id)
        rule.ctl.set_auth_context(auth_context)
        rule.ctl.delete()
        Notification.objects(  # Delete related notifications.
            owner=auth_context.owner, rtype='rule', rid=rule_id
        ).delete()
    except Rule.DoesNotExist:
        raise RuleNotFoundError()
    return Response('OK', 200)


@view_config(route_name='api_v1_rule_triggered', request_method='PUT')
def triggered(request):
    """
    Tags: rules
    ---
    Process a trigger sent by the alert service.

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
     type: string
     required: true
     description: |
       the time at which the rule raised an alert and sent a trigger to
       this API endpoint
    pending_since:
     type: string
     required: true
     description: |
       the time at which the rule evaluated to True and entered pending
       state. A rule can remain in pending state if a TriggerOffset has
       been configured. Datetime needed
    resolved_since:
     type: string
     required: true
     description: >
       the time at which the incident with the specified UUID resolved.\
       Datetime needed

    """
    # Do not publicly expose this API endpoint?
    if config.CILIA_SECRET_KEY != request.headers.get('Cilia-Secret-Key'):
        raise UnauthorizedError()

    params = params_from_request(request)

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

    if machine.missing_since:
        raise NotFoundError('Machine with id %s does not exist' % resource_id)

    if machine.state == 'terminated':
        raise NotFoundError('Machine with id %s is terminated' % resource_id)

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
