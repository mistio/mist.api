"""When entity model."""
import datetime
import logging

import mongoengine as me

log = logging.getLogger(__name__)

#: Authorized values for Interval.period
PERIODS = ('days', 'hours', 'minutes', 'seconds', 'microseconds')


class BaseWhenType(me.EmbeddedDocument):
    """Abstract Base class used as a common interface
    for scheduler types. There are three different types
    for now: Interval, Crontab and OneOff
    """
    meta = {'allow_inheritance': True}

    @property
    def schedule(self):
        raise NotImplementedError()

    @property
    def timedelta(self):
        raise NotImplementedError()

    def update(self, fail_on_error=True, **kwargs):
        for key, value in kwargs.items():
            if key not in type(self)._fields:
                if not fail_on_error:
                    continue
                raise me.ValidationError('Field "%s" does not exist on %s',
                                         key, type(self))
            setattr(self, key, value)


class Interval(BaseWhenType):
    meta = {'allow_inheritance': True}

    type = 'interval'
    every = me.IntField(min_value=0, default=0, required=True)
    period = me.StringField(choices=PERIODS)

    @property
    def period_singular(self):
        return self.period[:-1]

    @property
    def timedelta(self):
        return datetime.timedelta(**{self.period: self.every})

    def __unicode__(self):
        if self.every == 1:
            return 'Interval every {0.period_singular}'.format(self)
        return 'Interval every {0.every} {0.period}'.format(self)

    def as_dict(self):
        return {
            'every': self.every,
            'period': self.period
        }


class OneOff(Interval):
    type = 'one_off'
    entry = me.DateTimeField(required=True)

    @property
    def timedelta(self):
        raise NotImplementedError()

    def __unicode__(self):
        return 'OneOff date to run {0.entry}'.format(self)

    def as_dict(self):
        return {
            'entry': str(self.entry)
        }


class Reminder(OneOff):
    type = 'reminder'
    message = me.StringField()

    @property
    def timedelta(self):
        raise NotImplementedError()

    def as_dict(self):
        return {
            'message': self.message
        }


class Crontab(BaseWhenType):
    type = 'crontab'

    minute = me.StringField(default='*', required=True)
    hour = me.StringField(default='*', required=True)
    day_of_week = me.StringField(default='*', required=True)
    day_of_month = me.StringField(default='*', required=True)
    month_of_year = me.StringField(default='*', required=True)

    @property
    def timedelta(self):
        raise NotImplementedError()

    def __unicode__(self):

        def rfield(x):
            return str(x).replace(' ', '') or '*'

        return 'Crontab {0} {1} {2} {3} {4} (m/h/dom/mon/dow)'.format(
            rfield(self.minute), rfield(self.hour),
            rfield(self.day_of_month), rfield(self.month_of_year),
            rfield(self.day_of_week),
        )

    def as_dict(self):
        return {
            'minute': self.minute,
            'hour': self.hour,
            'day_of_week': self.day_of_week,
            'day_of_month': self.day_of_month,
            'month_of_year': self.month_of_year
        }

    def as_cron(self):
        def rfield(x):
            return str(x).replace(' ', '') or '*'

        return '{0} {1} {2} {3} {4}'.format(
            rfield(self.minute), rfield(self.hour),
            rfield(self.day_of_month), rfield(self.month_of_year),
            rfield(self.day_of_week),
        )


class TriggerOffset(BaseWhenType):
    """An optional period of tolerance-like behavior for an alert.

    Associates a trigger offset with an alert, which will prevent
    the alert from firing, unless the defined threshold exceeds X
    for T periods of time.

    The offset must be a multiple of the resource's interval frequency.

    """

    offset = me.IntField(min_value=0, default=0, required=True)
    period = me.StringField(choices=PERIODS)

    @property
    def timedelta(self):
        return datetime.timedelta(**{self.period: self.offset})

    @property
    def period_singular(self):
        return self.period[:-1]

    def clean(self):
        if self.offset:
            super(TriggerOffset, self).clean()
            q, r = divmod(self.timedelta.total_seconds(),
                          self._instance.when.timedelta.total_seconds())
            if not q or r:
                raise me.ValidationError("The trigger offset must be a"
                                         " multiple of the rule's frequency")

    def as_dict(self):
        return {'offset': self.offset, 'period': self.period}

    def __str__(self):
        if self.offset == 0:
            return 'Trigger offset is 0'
        if self.offset == 1:
            return 'Trigger offset of 1 %s' % self.period_singular
        return 'Trigger offset %s %s' % (self.offset, self.period)
