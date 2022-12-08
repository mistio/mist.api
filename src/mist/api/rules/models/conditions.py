import datetime
import mongoengine as me


OPERATORS = (
    ('eq', '='),
    ('ne', '!='),
    ('gt', '>'),
    ('lt', '<'),
)


class QueryFilter(me.EmbeddedDocument):
    """A selector used to further filter a dataset.

    This type of selector/filter may be used by any non-arbitrary rule type.
    However, a QueryFilter is not the same as a resource condition, found in
    mist.api.conditions.models. For instance, trying to use a QueryFilter in
    order to apply filtering based on tags might give weird results. Instead,
    use a QueryFilter in order to filter data, such as time series, based on
    the dataset's own metadata.

    For example, `QueryFilter(key='name', value='sda', operator='eq')` could
    return the time series corresponding to a specific disk partition.

    """

    key = me.StringField(required=True)
    value = me.DynamicField(required=True)
    operator = me.StringField(required=True, choices=OPERATORS)

    def as_dict(self):
        return {
            'key': self.key,
            'value': self.value,
            'operator': self.operator
        }

    def __str__(self):
        return '%s %s %s' % (self.key, self.get_operator_display(), self.value)


class QueryCondition(me.EmbeddedDocument):
    """The main condition of a Rule.

    The QueryCondition is the main condition type required in order to setup a
    Rule. A QueryCondition allows users to specify the query to be executed by
    providing the metric's name, an aggregation function, as well as threshold
    type and value. Additional filters may also be specified in order to limit
    down a query's results.

    In case of arbitrary rules the `target` has to store the entire query as a
    single string, aggregation function and selectors included.

    """

    target = me.StringField(required=True)
    operator = me.StringField(required=True, choices=OPERATORS)
    threshold = me.DynamicField(required=True)

    filters = me.EmbeddedDocumentListField(QueryFilter, default=lambda: [])

    aggregation = me.StringField(default='all', choices=('all', 'any',
                                                         'avg', 'count'))

    meta = {'allow_inheritance': True}

    @property
    def filters_string(self):
        """Return `self.filters` as a string."""
        return ', '.join([str(f) for f in self.filters])

    def as_dict(self):
        return {
            'target': self.target,
            'operator': self.operator,
            'threshold': self.threshold,
            'aggregation': self.aggregation,
            'filters': [f.as_dict() for f in self.filters],
        }

    def __str__(self):
        return '%s(%s){%s} %s %s' % (self.aggregation.upper(),
                                     self.target or '',
                                     self.filters_string,
                                     self.get_operator_display(),
                                     self.threshold)


class BasePeriodType(me.EmbeddedDocument):
    """Base abstract class for various period|interval related documents."""

    period = me.StringField(choices=('days', 'hours', 'minutes', 'seconds', ))

    meta = {'allow_inheritance': True}

    @property
    def period_singular(self):
        return self.period[:-1]

    @property
    def period_short(self):
        return self.period[0]

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

    def clean(self):
        if self.timedelta.total_seconds() < 60:
            raise me.ValidationError("%s's timedelta cannot be less than "
                                     "a minute" % self.__class__.__name__)


class Window(BasePeriodType):

    start = me.IntField(min_value=0, default=0, required=True)
    stop = me.IntField(min_value=0, default=0, required=True)

    @property
    def timedelta(self):
        return datetime.timedelta(**{self.period: self.start - self.stop})

    def as_dict(self):
        return {'start': self.start, 'stop': self.stop, 'period': self.period}

    def __str__(self):
        if not self.stop:
            return 'Time window from -%d to now' % self.start
        return 'Time window from -%d to now-%d' % (self.start, self.stop)


class Frequency(BasePeriodType):

    every = me.IntField(min_value=0, required=True)

    @property
    def timedelta(self):
        return datetime.timedelta(**{self.period: self.every})

    def as_dict(self):
        return {'every': self.every, 'period': self.period}

    def __str__(self):
        if self.every == 1:
            return 'Frequency every %s' % self.period_singular
        return 'Frequency every %s %s' % (self.every, self.period)


class TriggerOffset(BasePeriodType):
    """An optional period of tolerance-like behavior for an alert.

    Associates a trigger offset with an alert, which will prevent
    the alert from firing, unless the defined threshold exceeds X
    for T periods of time.

    The offset must be a multiple of the rule's frequency.

    """

    offset = me.IntField(min_value=0, default=0, required=True)

    @property
    def timedelta(self):
        return datetime.timedelta(**{self.period: self.offset})

    def clean(self):
        if self.offset:
            super(TriggerOffset, self).clean()
            q, r = divmod(self.timedelta.total_seconds(),
                          self._instance.frequency.timedelta.total_seconds())
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
