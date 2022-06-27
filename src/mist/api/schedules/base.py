"""Definition of base classes for Schedules

This currently contains only BaseController. It includes basic functionality
for a given schedule.
Cloud specific controllers are in `mist.api.schedules.controllers`.
"""
import re
import logging
import datetime
import ast
import mongoengine as me

from mist.api.helpers import rtype_to_classpath
from mist.api.scripts.models import Script
from mist.api.helpers import trigger_session_update
from mist.api.helpers import extract_selector_type
from mist.api.methods import _update__preparse_resources
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
import mist.api.when.models as When
import mist.api.actions.models as acts
from mist.api.actions.models import MachineAction, VolumeAction
from mist.api.actions.models import NetworkAction, ClusterAction

from mist.api.auth.methods import AuthContext


log = logging.getLogger(__name__)


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
        if not (kwargs.get('actions', '')) and not (kwargs.get('script_id', '') or kwargs.get('action', '')):
            raise BadRequestError("You must provide resource's actions")

        if len(kwargs.get('actions', [])) > 1:
            raise NotImplementedError()

        if not kwargs.get('selectors'):
            raise BadRequestError("You must provide a list of selectors, "
                                  "at least resource ids or tags")

        when_type = kwargs.get('when').get('schedule_type') if kwargs.get('when') else kwargs.get('schedule_type')

        if when_type not in ['crontab', 'interval', 'one_off']:
            raise BadRequestError('schedule type must be one of these '
                                  '(crontab, interval, one_off)]')

        entry = kwargs.get('when').get('datetime') if kwargs.get('when') else kwargs.get('schedule_entry')

        if when_type in ['one_off', 'reminder'] and not entry:
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
        selector_type = kwargs.get('selector_type', '')
        if not selector_type:
            selector_type = extract_selector_type(**kwargs)
        self.schedule.resource_model_name = selector_type

        actions = kwargs.get('actions')
        act = kwargs.get('action')
        if  (actions and len(actions) == 1) or act:
            action = kwargs.get('actions')[0].get('action_type', '') if not act else act
            if action == 'notify':
                raise NotImplementedError()
            elif action == 'run_script':
                script_type = kwargs.get('actions')[0].get('script_type')
                if script_type == 'existing':
                    script = kwargs.get('actions')[0].get('script')
                    script = ast.literal_eval(script)
                    script_id = script['script']
                    if script_id:
                        try:
                            # TODO List Resources insted of Script objects
                            Script.objects.get(owner=owner, id=script_id,
                                            deleted=None)
                        except me.DoesNotExist:
                            raise ScriptNotFoundError('Script with id %s does not '
                                                    'exist' % script_id)
                        # SEC require permission RUN on script
                        auth_context.check_perm('script', 'run', script_id)
            elif action == 'run script':
                script_id = kwargs.pop('script_id', '')
                if script_id:
                    try:
                        Script.objects.get(owner=owner, id=script_id, deleted=None)
                    except me.DoesNotExist:
                        raise ScriptNotFoundError('Script with id %s does not '
                                                'exist' % script_id)
                    # SEC require permission RUN on script
                    auth_context.check_perm('script', 'run', script_id)
        else:
            raise NotImplementedError()

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
        if kwargs.get('selectors'):
            try:
                _update__preparse_resources(self.schedule, auth_context, kwargs)
            except MistError as exc:
                log.error("Error while updating schedule %s: %r",
                          self.schedule.id, exc)
                raise
            except Exception as exc:
                log.exception("Error while preparsing kwargs on update %s",
                              self.schedule.id)
                raise InternalServerError(exc=exc)

        actions = kwargs.pop('actions', [])
        act = kwargs.pop('action', '')
        if (actions and len(actions) == 1) or act:
            action = actions[0]['action_type'] if not act else act
            if action == 'notify':
                raise NotImplementedError()
            elif action == 'run_script':
                script = ast.literal_eval(actions[0]['script'])
                script_id = script['script']
                params = script['params']
                if script_id:
                    self.schedule.actions[0] = acts.ScriptAction(
                        script=script_id, params=params)
            elif action == 'run script':
                if script_id:
                    self.schedule.actions[0] = acts.ScriptAction(
                        script=script_id, params=params)
            else:
                    self.schedule.actions[0] = globals()[f'{self.schedule.resource_model_name.title()}Action'](action=action)
        elif len(actions) == 0:
            raise BadRequestError("Action is required")
        else:
            raise NotImplementedError()

        schedule_type = ''
        when_type = kwargs.get('when').pop('schedule_type') if kwargs.get('when') else kwargs.pop('schedule_type')

        if when_type == 'crontab':
            schedule_entry = kwargs.pop('when', {}) if kwargs.get('when') else kwargs.pop('schedule_entry', {})

            if schedule_entry:
                for k in schedule_entry:
                    if k not in ['minute', 'hour', 'day_of_week',
                                 'day_of_month', 'month_of_year']:
                        raise BadRequestError("Invalid key given: %s" % k)

                self.schedule.when = When.Crontab(
                    **schedule_entry)

        elif when_type == 'interval':
            schedule_entry = kwargs.pop('when', {}) if kwargs.get('when') else kwargs.pop('schedule_entry', {})

            if schedule_entry:
                for k in schedule_entry:
                    if k not in ['period', 'every']:
                        raise BadRequestError("Invalid key given: %s" % k)

                self.schedule.when = When.Interval(
                    **schedule_entry)

        elif when_type in ['one_off', 'reminder']:
            # implements Interval under the hood
            future_date =  kwargs.pop('when').pop('datetime') if kwargs.get('when') else kwargs.pop('schedule_entry', '')

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

                if when_type == 'reminder':
                    self.schedule.when = When.Reminder(
                        period='seconds',
                        every=delta.seconds,
                        entry=future_date,
                        message=notify_msg)
                else:
                    self.schedule.when = When.OneOff(
                        period='seconds',
                        every=delta.seconds,
                        entry=future_date)
                self.schedule.max_run_count = self.schedule.max_run_count or 1

                if self.schedule.reminder:
                    self.schedule.reminder.delete()
                import ipdb; ipdb.set_trace()
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


    def delete(self):
        """ Delete a schedule

        By default the corresponding mongodb document is not actually
        deleted, but rather marked as deleted.

        """

        self.schedule.deleted = datetime.datetime.utcnow()
        self.schedule.save()
        trigger_session_update(self.schedule.owner, ['schedules'])
