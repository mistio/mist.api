"""Definition of base classes for Schedules

This currently contains only BaseController. It includes basic functionality
for a given schedule.
Cloud specific controllers are in `mist.api.schedules.controllers`.
"""
import re
import logging
import datetime
import mongoengine as me

from mist.api.helpers import rtype_to_classpath
from mist.api.scripts.models import Script
from mist.api.exceptions import MistError
from mist.api.exceptions import InternalServerError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ScriptNotFoundError
from mist.api.exceptions import ScheduleOperationError
from mist.api.exceptions import ScheduleNameExistsError

from mist.api.exceptions import NotFoundError

from mist.api.selectors.models import FieldSelector, ResourceSelector
from mist.api.selectors.models import TaggingSelector, AgeSelector

import mist.api.schedules.models as schedules

from mist.api.auth.methods import AuthContext


log = logging.getLogger(__name__)


SELECTOR_CLS = {'tags': TaggingSelector,
                'resource': ResourceSelector,
                'field': FieldSelector,
                'age': AgeSelector}


def check_perm(auth_context, resource_type, action, resource=None):
    assert resource_type in rtype_to_classpath
    rid = resource.id if resource else None
    if resource_type == 'machine':
        if rid:
            # SEC require permission READ on cloud
            auth_context.check_perm("cloud", "read", resource.cloud.id)
        if action and action not in ['notify']:
            # SEC require permission ACTION on machine
            auth_context.check_perm(resource_type, action, rid)
        else:
            # SEC require permission RUN_SCRIPT on machine
            auth_context.check_perm(resource_type, "run_script", rid)
    else:
        raise NotImplementedError()


class BaseController(object):

    def __init__(self, schedule, auth_context=None):
        """Initialize schedule controller given a schedule

        Most times one is expected to access a controller from inside the
        schedule. Like this:

          schedule = mist.api.schedules.models.Schedule.objects.get(id=s_id)
          schedule.ctl.add()
        """
        self.schedule = schedule
        self._auth_context = auth_context

    def set_auth_context(self, auth_context):
        assert isinstance(auth_context, AuthContext)
        self._auth_context = auth_context

    @property
    def auth_context(self):
        if self._auth_context is None:
            raise Exception("Forgot to set auth_context")
        elif self._auth_context is False:
            return None
        return self._auth_context

    def add(self, **kwargs):
        """Add an entry to the database

        This is only to be called by `Schedule.add` classmethod to create
        a schedule. Fields `owner` and `name` are already populated in
        `self.schedule`. The `self.schedule` is not yet saved.

        """
        # check if required variables exist.
        if not (kwargs.get('script_id', '') or kwargs.get('action', '')):
            raise BadRequestError("You must provide script_id "
                                  "or resource's action")

        if not kwargs.get('selectors'):
            raise BadRequestError("You must provide a list of selectors, "
                                  "at least resource ids or tags")

        if kwargs.get('schedule_type') not in ['crontab', 'reminder',
                                               'interval', 'one_off']:
            raise BadRequestError('schedule type must be one of these '
                                  '(crontab, interval, one_off)]')

        if kwargs.get('schedule_type') in ['one_off', 'reminder'] and \
                not kwargs.get('schedule_entry', ''):
            raise BadRequestError('one_off schedule '
                                  'requires date given in schedule_entry')

        try:
            self.update(**kwargs)
        except (me.ValidationError, me.NotUniqueError) as exc:
            # Propagate original error.
            log.error("Error adding %s: %s", self.schedule.name,
                      exc.to_dict())
            raise
        log.info("Added schedule with name '%s'", self.schedule.name)
        self.schedule.owner.mapper.update(self.schedule)

    def update(self, **kwargs):
        """Edit an existing Schedule"""

        if self.auth_context is not None:
            auth_context = self.auth_context
        else:
            raise MistError("You are not authorized to update schedule")

        owner = auth_context.owner

        if kwargs.get('action'):
            if kwargs.get('action') not in ['reboot', 'destroy', 'notify',
                                            'start', 'stop']:
                raise BadRequestError("Action is not correct")

        script_id = kwargs.pop('script_id', '')
        if script_id:
            try:
                Script.objects.get(owner=owner, id=script_id, deleted=None)
            except me.DoesNotExist:
                raise ScriptNotFoundError('Script with id %s does not '
                                          'exist' % script_id)
            # SEC require permission RUN on script
            auth_context.check_perm('script', 'run', script_id)

        # for ui compatibility
        if kwargs.get('expires') == '':
            kwargs['expires'] = None
        if kwargs.get('max_run_count') == '':
            kwargs['max_run_count'] = None
        if kwargs.get('start_after') == '':
            kwargs['start_after'] = None
        # transform string to datetime
        if kwargs.get('expires'):
            try:
                if isinstance(kwargs['expires'], int):
                    if kwargs['expires'] > 5000000000:  # Timestamp in millis
                        kwargs['expires'] = kwargs['expires'] / 1000
                    kwargs['expires'] = datetime.datetime.fromtimestamp(
                        kwargs['expires'])
                else:
                    kwargs['expires'] = datetime.datetime.strptime(
                        kwargs['expires'], '%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                raise BadRequestError('Expiration date value was not valid')

        if kwargs.get('start_after'):
            try:
                if isinstance(kwargs['start_after'], int):
                    if kwargs['start_after'] > 5000000000:  # Timestamp in ms
                        kwargs['start_after'] = kwargs['start_after'] / 1000
                    kwargs['start_after'] = datetime.datetime.fromtimestamp(
                        kwargs['start_after']
                    )
                else:
                    kwargs['start_after'] = datetime.datetime.strptime(
                        kwargs['start_after'], '%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                raise BadRequestError('Start-after date value was not valid')

        now = datetime.datetime.now()
        if self.schedule.expires and self.schedule.expires < now:
            raise BadRequestError('Date of future task is in the past. '
                                  'Please contact Marty McFly')
        if self.schedule.start_after and self.schedule.start_after < now:
            raise BadRequestError('Date of future task is in the past. '
                                  'Please contact Marty McFly')
        # Schedule selectors pre-parsing.
        try:
            self._update__preparse_resources(auth_context, kwargs)
        except MistError as exc:
            log.error("Error while updating schedule %s: %r",
                      self.schedule.id, exc)
            raise
        except Exception as exc:
            log.exception("Error while preparsing kwargs on update %s",
                          self.schedule.id)
            raise InternalServerError(exc=exc)

        action = kwargs.pop('action', '')
        if action:
            self.schedule.task_type = schedules.ActionTask(action=action)
        elif script_id:
            self.schedule.task_type = schedules.ScriptTask(
                script_id=script_id, params=kwargs.pop('params', ''))

        schedule_type = kwargs.pop('schedule_type', '')

        if (schedule_type == 'crontab' or
                isinstance(self.schedule.schedule_type, schedules.Crontab)):
            schedule_entry = kwargs.pop('schedule_entry', {})

            if schedule_entry:
                for k in schedule_entry:
                    if k not in ['minute', 'hour', 'day_of_week',
                                 'day_of_month', 'month_of_year']:
                        raise BadRequestError("Invalid key given: %s" % k)

                self.schedule.schedule_type = schedules.Crontab(
                    **schedule_entry)

        elif (schedule_type == 'interval' or
                type(self.schedule.schedule_type) == schedules.Interval):
            schedule_entry = kwargs.pop('schedule_entry', {})

            if schedule_entry:
                for k in schedule_entry:
                    if k not in ['period', 'every']:
                        raise BadRequestError("Invalid key given: %s" % k)

                self.schedule.schedule_type = schedules.Interval(
                    **schedule_entry)

        elif (schedule_type in ['one_off', 'reminder'] or
                type(self.schedule.schedule_type) == schedules.OneOff):
            # implements Interval under the hood
            future_date = kwargs.pop('schedule_entry', '')

            if future_date:
                try:
                    if isinstance(future_date, int):
                        if future_date > 5000000000:  # Timestamp is in millis
                            future_date = future_date / 1000
                        future_date = datetime.datetime.fromtimestamp(
                            future_date)
                    else:
                        future_date = datetime.datetime.strptime(
                            future_date, '%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    raise BadRequestError('Date value was not valid')

                if future_date < now:
                    raise BadRequestError(
                        'Date of future task is in the past. '
                        'Please contact Marty McFly')

                delta = future_date - now
                notify_msg = kwargs.get('notify_msg', '')

                if schedule_type == 'reminder':
                    self.schedule.schedule_type = schedules.Reminder(
                        period='seconds',
                        every=delta.seconds,
                        entry=future_date,
                        message=notify_msg)
                else:
                    self.schedule.schedule_type = schedules.OneOff(
                        period='seconds',
                        every=delta.seconds,
                        entry=future_date)
                self.schedule.max_run_count = self.schedule.max_run_count or 1

                notify = kwargs.pop('notify', 0)
                if notify:
                    _delta = datetime.timedelta(0, notify)
                    notify_at = future_date - _delta
                    notify_at = notify_at.strftime('%Y-%m-%d %H:%M:%S')
                    params = {
                        'action': 'notify',
                        'schedule_type': 'reminder',
                        'description': 'Schedule expiration reminder',
                        'task_enabled': True,
                        'schedule_entry': notify_at,
                        'selectors': kwargs.get('selectors'),
                        'notify_msg': notify_msg
                    }
                    name = self.schedule.name + '-reminder'
                    if self.schedule.reminder:
                        self.schedule.reminder.delete()
                    from mist.api.schedules.models import Schedule
                    self.schedule.reminder = Schedule.add(
                        auth_context, name, **params)

        # set schedule attributes
        try:
            kwargs.pop('selectors')
        except KeyError:
            pass
        for key, value in kwargs.items():
            if key in self.schedule._fields:
                setattr(self.schedule, key, value)

        try:
            self.schedule.save()
        except me.ValidationError as e:
            log.error("Error updating %s: %s", self.schedule.name,
                      e.to_dict())
            raise BadRequestError({"msg": str(e), "errors": e.to_dict()})
        except me.NotUniqueError as exc:
            log.error("Schedule %s not unique error: %s", self.schedule, exc)
            raise ScheduleNameExistsError()
        except me.OperationError:
            raise ScheduleOperationError()

    def _update__preparse_resources(self, auth_context, kwargs):
        """Preparse resource arguments to `self.update`

        This is called by `self.update` when adding a new schedule,
        in order to apply pre processing to the given params. Any subclass
        that requires any special pre processing of the params passed to
        `self.update`, SHOULD override this method.

        Params:
        kwargs: A dict of the keyword arguments that will be set as attributes
            to the `Schedule` model instance stored in `self.schedule`.
            This method is expected to modify `kwargs` in place and set the
            specific field of each scheduler.

        Subclasses MAY override this method.

        """
        if kwargs.get('selectors'):
            self.schedule.selectors = []
        for selector in kwargs.get('selectors', []):
            sel_cls_key = selector.get('type')
            if not sel_cls_key:
                sel_cls_key = 'resource'
                assert self.schedule.resource_model_name in rtype_to_classpath
                selector['type'] = self.schedule.resource_model_name
            elif sel_cls_key in rtype_to_classpath:
                sel_cls_key = 'resource'
            if sel_cls_key not in SELECTOR_CLS:
                raise BadRequestError(
                    f'Valid selector types: {list(SELECTOR_CLS)}')
            if sel_cls_key == 'field':
                if selector['field'] not in ('created', 'state',
                                             'cost__monthly', 'name'):
                    raise BadRequestError()
                if selector.get('operator') == 'regex':
                    if selector['field'] != 'name':
                        raise BadRequestError(
                            'Supported regex fields: `name`.')
                    try:
                        re.compile(selector['value'])
                    except re.error:
                        raise BadRequestError(
                            f"{selector['value']} is not a valid regex.")
            sel = SELECTOR_CLS[sel_cls_key]()
            sel.update(**selector)
            self.schedule.selectors.append(sel)

        action = kwargs.get('action')

        # check permissions
        check = False
        resource_cls = self.schedule.selector_resource_cls
        resource_type = self.schedule.resource_model_name.rstrip('s')
        for selector in self.schedule.selectors:
            if isinstance(selector, ResourceSelector):
                if resource_type == 'machine':
                    query = dict(state__ne='terminated')
                    not_found_msg = 'Machine state is terminated.'
                else:
                    not_found_msg = 'Resource not found.'
                for rid in selector.ids:
                    try:
                        resource = resource_cls.objects.get(id=rid, **query)
                    except resource_cls.DoesNotExist:
                        raise NotFoundError(not_found_msg)
                    check_perm(
                        auth_context, resource_type, action, resource=resource)
                check = True
            elif selector.ctype == 'field':
                if selector.operator == 'regex':
                    resources = resource_cls.objects({
                        selector.field: re.compile(selector.value),
                        'state__ne': 'terminated'
                    })
                    for r in resources:
                        check_perm(
                            auth_context, resource_type, action, resource=r)
                    check = True
            elif selector.ctype == 'tags':
                check_perm(auth_context, resource_type, action)
                check = True
        if not check:
            raise BadRequestError("Specify at least resource ids or tags")

        return
