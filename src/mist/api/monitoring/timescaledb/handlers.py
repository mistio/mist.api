import logging
import psycopg2
from mist.api.config import POSTGRES_CONNSTR
from mist.api.helpers import iso_to_seconds

from mist.api.exceptions import BadRequestError

from mist.api.machines.models import Machine
log = logging.getLogger(__name__)


class BasicHandler(object):
    """A generic handler for querying InfluxDB and processing series."""
    def __init__(self, machine):
        """Initialize self bound to `machine`."""
        self.machine = machine
        self.column = None
        self.measurement = None

    def parse_path(self, metric):
        """Parse metric to extract the measurement, column, and tags.

        This method must be invoked by get_stats, before constructing the
        InfluxDB query, in order to extract the necessary information from
        the given metric, which is in the following format:

            <measurement>.<tags>.<column>

        where <tags> (optional) must be in "key=value" format and delimited
        by ".".

        This method should set `self.measurement` and `self.column` to the
        pure values extracted from `metric`, before any further processing
        takes place.

        Subclasses may override this method in order to edit the resulting
        measurement or column and apply functions to aggregate, select, and
        transform data.

        """
        # Measurement.
        measurement, fields = metric.split('.', 1)
        if not (measurement and fields):
            raise BadRequestError('Invalid metric: %s' % metric)

        # Column.
        fields = fields.split('.')
        column = fields[-1]

        # Tags.
        if isinstance(self.machine, Machine):
            tags = {'machine_id': self.machine.id}
        else:
            tags = {'machine_id': self.machine}

        if len(fields) > 1:
            for tag in fields[:-1]:
                tag = tag.split('=')
                if len(tag) is not 2:
                    log.error('%s got unexpected tag: %s',
                              self.__class__.__name__, tag)
                    continue
                tags[tag[0]] = tag[1]

        return measurement, column, tags

    def get_stats(self, start=None, stop=None, metric=None):
        log.info("Get Stats with args: start=%s,stop=%s,metrics=%s ",
                 repr(start), repr(stop), repr(metric))
        measurement, field, _ = self.parse_path(metric)

        metric = {}
        metric['priority'] = 0
        metric['min_value'] = None
        metric['name'] = measurement.upper() + ' ' + field
        metric['measurement'] = measurement
        metric['column'] = field
        metric['max_value'] = None
        metric['datapoints'] = query_field(measurement, field, self.machine.id)
        metric['unit'] = ''

        result = {}
        result[measurement + '.' + field] = metric

        return result


def get_query_executor():
    "Returns a postgres client executor"
    try:
        ps_client = psycopg2.connect(POSTGRES_CONNSTR)
    except Exception:
        log.critical("Unable to make client for postgres")
    return ps_client.cursor()


def query_field(measurement, field, machine_id):
    """Get metrics for a specific field,
       return a datapoint list for the field"""
    # Construct Query
    # TODO include tags in query (machine in tags could be an issue)
    query = """ SELECT fields->%s, time
                FROM metrics
                WHERE fields ? %s AND name=%s
                AND tags->>'machine_id'=%s """
    cur = get_query_executor()
    cur.execute(query, [field, field, measurement, machine_id])
    rows = cur.fetchall()

    result = []
    for row in rows:
        result.append((float(row[0]), iso_to_seconds(row[1])))
    return result
