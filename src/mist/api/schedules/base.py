"""Definition of base classes for Schedules

This currently contains only BaseController. It includes basic functionality
for a given schedule.
Cloud specific controllers are in `mist.api.schedules.controllers`.
"""
import logging
import datetime
import mongoengine as me
from mist.api.scripts.models import Script
from mist.api.exceptions import MistError
from mist.api.exceptions import InternalServerError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ScriptNotFoundError
from mist.api.exceptions import ScheduleOperationError
from mist.api.exceptions import ScheduleNameExistsError

from mist.api.machines.models import Machine
from mist.api.exceptions import NotFoundError

from mist.api.selectors.models import FieldSelector, GenericResourceSelector
from mist.api.selectors.models import TaggingSelector, MachinesAgeSelector

import mist.api.schedules.models as schedules

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
        if not (kwargs.get('script_id', '') or kwargs.get('action', '')):
            raise BadRequestError("You must provide script_id "
                                  "or machine's action")

        if not kwargs.get('selectors'):
            raise BadRequestError("You must provide a list of selectors, "
                                  "at least machine ids or tags")

        if kwargs.get('schedule_type') not in ['crontab',
                                               'interval', 'one_off']:
            raise BadRequestError('schedule type must be one of these '
                                  '(crontab, interval, one_off)]')

        if kwargs.get('schedule_type') == 'one_off' and not kwargs.get(
                'schedule_entry', ''):
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
            if kwargs.get('action') not in ['reboot', 'destroy',
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
                kwargs['expires'] = datetime.datetime.strptime(
                    kwargs['expires'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                raise BadRequestError('Expiration date value was not valid')

        if kwargs.get('start_after'):
            try:
                kwargs['start_after'] = datetime.datetime.strptime(
                    kwargs['start_after'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
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
            self._update__preparse_machines(auth_context, kwargs)
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

        elif (schedule_type == 'one_off' or
                type(self.schedule.schedule_type) == schedules.OneOff):
            # implements Interval under the hood
            future_date = kwargs.pop('schedule_entry', '')

            if future_date:
                try:
                    future_date = datetime.datetime.strptime(
                        future_date, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    raise BadRequestError('Date value was not valid')

                if future_date < now:
                    raise BadRequestError(
                        'Date of future task is in the past. '
                        'Please contact Marty McFly')

                delta = future_date - now

                one_off = schedules.OneOff(period='seconds',
                                           every=delta.seconds,
                                           entry=future_date)
                self.schedule.schedule_type = one_off
                self.schedule.max_run_count = 1

        # set schedule attributes
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

    def _update__preparse_machines(self, auth_context, kwargs):
        """Preparse machines arguments to `self.update`

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
        cond_cls = {'tags': TaggingSelector,
                    'machines': GenericResourceSelector,
                    'field': FieldSelector,
                    'age': MachinesAgeSelector}

        if kwargs.get('selectors'):
            self.schedule.selectors = []
        for selector in kwargs.pop('selectors', []):
            if selector.get('type') not in cond_cls:
                raise BadRequestError()
            if selector['type'] == 'field':
                if selector['field'] not in ('created', 'state',
                                              'cost__monthly'):
                    raise BadRequestError()
            sel = sel_cls[selector.pop('type')]()
            sel.update(**selector)
            self.schedule.selectors.append(sel)

        action = kwargs.get('action')

        # check permissions
        check = False
        for selector in self.schedule.selectors:
            if selector.ctype == 'machines':
                for mid in selector.ids:
                    try:
                        machine = Machine.objects.get(id=mid,
                                                      state__ne='terminated')
                    except Machine.DoesNotExist:
                        raise NotFoundError('Machine state is terminated')

                    # SEC require permission READ on cloud
                    auth_context.check_perm("cloud", "read", machine.cloud.id)

                    if action:
                        # SEC require permission ACTION on machine
                        auth_context.check_perm("machine", action, mid)
                    else:
                        # SEC require permission RUN_SCRIPT on machine
                        auth_context.check_perm("machine", "run_script", mid)
                check = True
            elif selector.ctype == 'tags':
                if action:
                    # SEC require permission ACTION on machine
                    auth_context.check_perm("machine", action, None)
                else:
                    # SEC require permission RUN_SCRIPT on machine
                    auth_context.check_perm("machine", "run_script", None)
                check = True
        if not check:
            raise BadRequestError("Specify at least machine ids or tags")

        return
