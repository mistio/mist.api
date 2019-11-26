import logging
import requests

from mist.api.exceptions import ForbiddenError
from mist.api import config
import urllib.parse


log = logging.getLogger(__name__)


def get_stats(machine, start="", stop="", step="", metrics=None):
    data = {}

    if not isinstance(machine, str):
        machine = machine.id

    # If no metrics are specified, then we get all of them
    if not metrics:
        metrics = [".*"]

    for metric in metrics:
        # processed_metric = "%s.%s" % (machine.id, metric)
        query = metric.format(id=machine, start=start, stop=stop, step=step)
        """query = 'fetch("%s", start="%s", stop="%s", step="%s")' % (
            processed_metric,
            start,
            stop,
            step,
        )"""
        raw_machine_data = requests.get(
            "%s/v1/datapoints?query=%s"
            % (config.TSFDB_URI, urllib.parse.quote(query))
        ).json()

        if "series" not in raw_machine_data:
            log.error(raw_machine_data)
            return {}

        raw_metrics = list(raw_machine_data["series"].keys())
        for raw_metric in raw_metrics:
            # We use as key the metric name without the machine id
            # e.g "id.system.load1 => system.load1"
            returned_metric = raw_metric.split(".", 1)[1]
            data.update(
                {
                    returned_metric: {
                        "name": returned_metric,
                        "datapoints": raw_machine_data["series"][raw_metric],
                    }
                }
            )

    return data


def get_load(machines, start, stop, step):
    data = {}
    for machine in machines:
        metric = "%s.system.load1" % machine
        query = 'fetch("%s", start="%s", stop="%s", step="%s")' % (
            metric,
            start,
            stop,
            step,
        )
        raw_machine_data = requests.get(
            "%s/v1/datapoints?query=%s" % (config.TSFDB_URI, query)
        ).json()

        if "series" not in raw_machine_data:
            log.error(raw_machine_data)
            return {}

        data.update(
            {
                machine: {
                    "name": machine,
                    "datapoints": raw_machine_data["series"][metric],
                }
            }
        )

    return data


def find_metrics(machine):
    if not machine.monitoring.hasmonitoring:
        raise ForbiddenError("Machine doesn't have monitoring enabled.")
    # return get_metrics(machine.id)
