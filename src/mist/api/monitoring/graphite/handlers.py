"""Set of handlers used to query Graphite

Code originally taken from:

https://github.com/mistio/mist.monitor/blob/master/src/mist/monitor/graphite.py

"""

import re
import time
import calendar
import logging
import requests
import html.parser

from future.utils import string_types

import mist.api.config as config
from functools import reduce


log = logging.getLogger(__name__)


def summarize(series, interval, function="avg"):
    return r"""
aliasSub(
summarize(%(series)s, '%(interval)s', '%(function)s'),
'summarize\((.*), "%(interval)s", "%(function)s"\)',
"\1"
)""".replace('\n', '') % {'series': series, 'interval': interval,
                          'function': function}


def sum_series(series_list):
    return "sumSeries(%s)" % series_list


def as_percent(series_list, total=None):
    if total:
        return "asPercent(%s,%s)" % (series_list, total)
    else:
        return "asPercent(%s)" % series_list


def per_second(series_list):
    return "delay(perSecond(%s),-1)" % (series_list, )


def exclude(series_list, regex):
    return "exclude(%s,'%s')" % (series_list, regex)


def alias(series_list, name):
    return "alias(%s,'%s')" % (series_list, name)


class GenericHandler(object):
    def __init__(self, uuid, telegraf=False, telegraf_since=None):
        self.uuid = uuid
        self.telegraf = telegraf
        self.telegraf_since = telegraf and telegraf_since

    def head(self):
        return "bucky.%s" % self.uuid

    def get_data(self, targets, start="", stop="", interval_str=""):
        if isinstance(targets, string_types):
            targets = [targets]
        clean_targets = []
        real_to_requested = {}
        for target in targets:
            requested_target = target
            target, _alias = self.target_alias(target)
            if target:
                _target = target
                if interval_str:
                    target = summarize(target, interval_str)
                if _alias != _target:
                    # if alias different than target use alias to not screw
                    # with the return target
                    target = alias(target, _alias)
                real_to_requested[_alias] = requested_target
                clean_targets.append(target % {'head': self.head()})
        url = self.get_graphite_render_url(clean_targets,
                                           start=start, stop=stop)
        resp = self.graphite_request(url)
        data = resp.json()
        for item in data:
            item.update(self.decorate_target(item['target']))
            item['_requested_target'] = real_to_requested.get(item['alias'])
        return data

    def get_graphite_render_url(self, targets, start="", stop="",
                                resp_format="json"):
        params = [('target', target) for target in targets]
        params += [('from', start or None),
                   ('until', stop or None),
                   ('format', resp_format or None)]
        return requests.Request('GET', "%s/render" % config.GRAPHITE_URI,
                                params=params).prepare().url

    def graphite_request(self, url):
        """Issue a request to graphite."""

        try:
            log.info("Querying graphite uri: '%s'.", url)
            resp = requests.get(url)
        except Exception as exc:
            log.error("Error sending request to graphite: %r", exc)
            raise

        if not resp.ok:
            # try to parse error message from graphite's HTML error response
            reason = ""
            try:
                search = re.search("(?:Exception|TypeError): (.*)", resp.text)
                if search:
                    reason = search.groups()[0]
                    reason = html.parser.HTMLParser().unescape(reason)
            except:
                pass
            if reason == "reduce() of empty sequence with no initial value":
                # This happens when graphite tries to perform certain
                # calculation on an empty series. I think it is caused when
                # using asPercent or divideSeries. The series is empty if it
                # invalid, ie the graphite doesn't know of the underlying
                # raw data series. This could be due to a typo in the target
                # like saying oooctets instead of octets but since we have
                # tested our targets and know they don't have any typos, the
                # only other explanation is that the machine uuid (which is
                # the top level identifier for a graphite series) is wrong.
                # Practically, this happens if graphite has never received
                # any data for this machine so it doesn't have any subseries
                # registered. It happens when a machine has never sent data
                # to graphite (perhaps collecd deployment went wrong) and
                # we try to get the CpuUtilization or MemoryUtilization metric.
                # If we try to get another metric, say Load, on such a target,
                # we will get a 200 OK response but the asked target will be
                # missing from the response body.
                if self.check_head():
                    reason = ("Trying to do division with empty series, "
                              "the target must be wrong.")
                else:
                    reason = ("Trying to do division with empty series, cause "
                              "the machine never sent Graphite any data.")
            log.error("Got error response from graphite: [%d] %s",
                      resp.status_code, reason or resp.text)
            raise Exception(reason)
        return resp

    def target_alias(self, name):
        """Given a metric identifier, return the correct target and alias"""
        target = name.replace("%s." % self.head(), "%(head)s.")
        derivative = re.match(r'derivative\((.*)\)', target)
        if derivative:
            target = derivative.groups()[0]
        if not target.startswith('%(head)s.'):
            target = "%(head)s." + target
        if derivative:
            target = per_second(target)
        return target, target

    def decorate_target(self, target):
        """Returns a dict with metadata about the target"""
        target, alias = self.target_alias(target)
        name = target.replace("%(head)s.", "").replace(".", " ").capitalize()
        return {
            'target': target,
            'alias': alias,
            'name': name,
            'unit': "",
            'max_value': None,
            'min_value': None,
            'priority': 100,
        }

    def _find_metrics(self, query):
        url = "%s/metrics?query=%s" % (config.GRAPHITE_URI, query)
        resp = self.graphite_request(url)
        return resp.json()

    def find_metrics(self, plugin=""):
        def find_leaves(query):
            leaves = []
            for metric in self._find_metrics(query):
                if metric['leaf']:
                    leaves.append(metric['id'])
                elif metric['allowChildren']:
                    # or metric['expandable']
                    leaves += find_leaves(metric['id'] + ".*")
            return leaves

        query = self.head()
        if plugin:
            query += ".%s" % plugin
        metrics = [self.decorate_target(leaf) for leaf in find_leaves(query)]
        return metrics

    def check_head(self):
        return bool(self._find_metrics(self.head()))


class CustomHandler(GenericHandler):
    plugin = ""

    def find_metrics(self, plugin=""):
        if not plugin:
            plugin = self.plugin
        return super(CustomHandler, self).find_metrics(plugin=plugin)

    def parse_target(self, target):
        """Return list of target parts"""
        parts = target.split(".")
        if parts[0] == "%(head)s" and parts[1] == self.plugin:
            return parts[2:]
        log.error("%s() got invalid target: '%s'.",
                  self.__class__.__name__, target)

    def get_data(self, targets, start="", stop="", interval_str=""):
        data = super(CustomHandler, self).get_data(targets, start, stop,
                                                   interval_str)
        # Set as null datapoints before telegraf activation
        if self.telegraf_since and self.plugin in ['disk', 'interface']:
            telegraf_since = calendar.timegm(self.telegraf_since.timetuple())
            for target in data:
                for datapoint in target['datapoints']:
                    if datapoint[1] < telegraf_since:
                        datapoint[0] = None
                    else:
                        break
        return data


class LoadHandler(CustomHandler):
    plugin = "load"

    def parse_target(self, target):
        """Returl list of single element 'load period'."""
        parts = super(LoadHandler, self).parse_target(target)
        if parts is not None:
            if len(parts) == 1:
                period = parts[0]
                # period is in ('shortterm', 'midterm', 'longterm')
                return [period]
        log.error("%s() got invalid target: '%s'.",
                  self.__class__.__name__, target)

    def decorate_target(self, target):
        metric = super(LoadHandler, self).decorate_target(target)
        parts = self.parse_target(metric['alias'])
        if parts is not None:
            if parts[0] == 'percent':  # collectm in windows server
                metric['name'] = "Load (%)"
                metric['min_value'] = 0
                metric['max_value'] = 100
            else:
                period = parts[0]
                minutes = {'shortterm': 1, 'midterm': 5, 'longterm': 15}
                if period in minutes:
                    if minutes[period] > 1:
                        metric['name'] = "Load (%d mins)" % minutes[period]
                    else:
                        metric['name'] = "Load"
                metric['min_value'] = 0
            metric['priority'] = 0
        return metric


class DiskHandler(CustomHandler):
    plugin = "disk"

    def parse_target(self, target):
        parts = super(DiskHandler, self).parse_target(target)
        if parts is not None:
            if len(parts) == 3:
                disk, kind, direction = parts
                return disk, kind, direction
        log.error("%s() got invalid target: '%s'.",
                  self.__class__.__name__, target)

    def decorate_target(self, target):
        metric = super(DiskHandler, self).decorate_target(target)
        parts = self.parse_target(metric['alias'])
        if parts is not None:
            disk, kind, direction = parts
            if kind.startswith("disk_"):
                kind = kind[5:]
            if kind == "octets":
                if disk == "total":
                    metric['name'] = "Disks %s" % direction.capitalize()
                else:
                    metric['name'] = "Disk %s %s" % (disk,
                                                     direction.capitalize())
                metric['unit'] = "B/s"
                metric['min_value'] = 0
                metric['max_value'] = 750000000  # 6Gbps (SATA3)
                metric['priority'] = 0
            else:
                if disk == "total":
                    metric['name'] = "Disks %s %s" % (direction.capitalize(),
                                                      kind.capitalize())
                else:
                    metric['name'] = "Disk %s %s %s" % (
                        disk, direction.capitalize(), kind.capitalize()
                    )
                metric['priority'] = 50
        return metric

    def find_metrics(self, plugin=""):
        metrics = super(DiskHandler, self).find_metrics()
        kinds = set()
        directions = set()
        for metric in metrics:
            parts = self.parse_target(metric['alias'])
            if parts is not None:
                disk, kind, direction = parts
                kinds.add(kind)
                directions.add(direction)
        for kind in kinds:
            for direction in directions:
                target = "%(head)s." + "disk.total.%s.%s" % (kind, direction)
                metrics.append(self.decorate_target(target))
        return metrics

    def target_alias(self, name):
        target, alias = super(DiskHandler, self).target_alias(name)
        parts = self.parse_target(target)
        if parts is not None:
            disk, kind, direction = parts
            if disk == "total":
                target = sum_series(
                    "%(head)s." + "disk.*.%s.%s" % (kind, direction)
                )
            if self.telegraf:
                target = per_second(target)
        return target, alias


class InterfaceHandler(CustomHandler):
    plugin = "interface"

    def parse_target(self, target):
        parts = super(InterfaceHandler, self).parse_target(target)
        if parts is not None:
            if len(parts) == 3:
                iface, kind, direction = parts
                return iface, kind, direction
        log.error("%s() got invalid target: '%s'.",
                  self.__class__.__name__, target)

    def decorate_target(self, target):
        metric = super(InterfaceHandler, self).decorate_target(target)
        parts = self.parse_target(metric['alias'])
        if parts is not None:
            iface, kind, direction = parts
            if kind.startswith("if_"):
                kind = kind[3:]
            if kind == "octets":
                if iface == "total":
                    metric['name'] = "Ifaces %s" % direction.capitalize()
                else:
                    metric['name'] = "Iface %s %s" % (iface,
                                                      direction.capitalize())
                metric['unit'] = "B/s"
                metric['min_value'] = 0
                metric['max_value'] = 1250000000  # 10Gbps (10 gigabit eth)
                metric['priority'] = 0
            else:
                if iface == "total":
                    metric['name'] = "Ifaces %s %s" % (direction.capitalize(),
                                                       kind.capitalize())
                else:
                    metric['name'] = "Iface %s %s %s" % (
                        iface, direction.capitalize(), kind.capitalize()
                    )
                metric['priority'] = 50
            if iface.startswith("lo"):
                metric['priority'] += 10
        return metric

    def find_metrics(self, plugin=""):
        metrics = super(InterfaceHandler, self).find_metrics()
        kinds = set()
        directions = set()
        for metric in metrics:
            parts = self.parse_target(metric['alias'])
            if parts is not None:
                iface, kind, direction = parts
                kinds.add(kind)
                directions.add(direction)
        for kind in kinds:
            for direction in directions:
                target = "interface.total.%s.%s" % (kind, direction)
                metrics.append(self.decorate_target("%(head)s." + target))
        return metrics

    def target_alias(self, name):
        target, alias = super(InterfaceHandler, self).target_alias(name)
        parts = self.parse_target(target)
        if parts is not None:
            iface, kind, direction = parts
            if iface == "total":
                target = sum_series(
                    "%(head)s." + "interface.*.%s.%s" % (kind, direction)
                )
            if self.telegraf:
                target = per_second(target)
        return target, alias


class CpuHandler(CustomHandler):
    plugin = "cpu"

    def parse_target(self, target):
        parts = super(CpuHandler, self).parse_target(target)
        if parts is not None:
            if len(parts) == 2:
                core, kind = parts
                return core, kind
        log.error("%s() got invalid target: '%s'.",
                  self.__class__.__name__, target)

    def decorate_target(self, target):
        metric = super(CpuHandler, self).decorate_target(target)
        parts = self.parse_target(metric['alias'])
        if parts is not None:
            core, kind = parts
            if core == "total":
                metric['name'] = "CPU %s" % kind
                metric['unit'] = "%"
                metric['min_value'] = 0
                metric['max_value'] = 100
                metric['priority'] = 0
                if kind == "nonidle":
                    metric['name'] = "CPU"
                    metric['priority'] -= 1
            else:
                metric['name'] = "CPU %s %s" % (core, kind)
                metric['unit'] = "jiffies"
                metric['min_value'] = 0
                metric['max_value'] = None
                metric['priority'] = 50
        return metric

    def find_metrics(self, plugin=""):
        metrics = super(CpuHandler, self).find_metrics()
        kinds = set()
        for metric in metrics:
            parts = self.parse_target(metric['alias'])
            if parts is not None:
                core, kind = parts
                kinds.add(kind)
        kinds.add("nonidle")
        for kind in kinds:
            target = "%(head)s.cpu.total." + kind
            metrics.append(self.decorate_target(target))
        return metrics

    def target_alias(self, name):
        target, alias = super(CpuHandler, self).target_alias(name)
        parts = self.parse_target(target)
        if parts is not None:
            core, kind = parts
            if core == "total":
                if kind == "*":
                    target = r'aliasSub(asPercent(sumSeriesWithWildcards(exclude(%(head)s.cpu.*.*,"idle"),3),sumSeries(%(head)s.cpu.*.*)), "^.*\.cpu\.([a-z]*),.*", "%(head)s.cpu.total.\1")'  # noqa
                    alias = target
                else:
                    if kind != "nonidle":
                        base_target = "%(head)s.cpu.*." + kind
                    else:
                        base_target = exclude("%(head)s.cpu.*.*", "idle")
                    target = as_percent(
                        sum_series(base_target),
                        sum_series("%(head)s.cpu.*.*")
                    )
        return target, alias


class MemoryHandler(CustomHandler):
    plugin = "memory"

    def parse_target(self, target):
        parts = super(MemoryHandler, self).parse_target(target)
        if parts is not None:
            if len(parts) == 1:
                kind = parts[0]
                percent = False
                if kind.endswith("_percent"):
                    kind = kind[:-8]
                    percent = True
                return kind, percent
        log.error("%s() got invalid target: '%s'.",
                  self.__class__.__name__, target)

    def decorate_target(self, target):
        metric = super(MemoryHandler, self).decorate_target(target)
        parts = self.parse_target(metric['alias'])
        if parts is not None:
            kind, percent = parts
            if kind == "nonfree":
                metric['name'] = "RAM"
            else:
                metric['name'] = "RAM %s" % kind
            if percent:
                metric['unit'] = "%"
                metric['min_value'] = 0
                metric['max_value'] = 100
                metric['priority'] = 0
            else:
                metric['unit'] = "B"
                metric['min_value'] = 0
                metric['max_value'] = 34359738368  # 32 GiB
                metric['priority'] = 30
        return metric

    def find_metrics(self, plugin=""):
        metrics = super(MemoryHandler, self).find_metrics()
        metrics.append(self.decorate_target("%(head)s.memory.nonfree"))
        kinds = set()
        for metric in metrics:
            parts = self.parse_target(metric['alias'])
            if parts is not None:
                kind = parts[0]
                kinds.add(kind)
        for kind in kinds:
            target = "%(head)s." + "memory.%s_percent" % kind
            metrics.append(self.decorate_target(target))
        return metrics

    def target_alias(self, name):
        target, alias = super(MemoryHandler, self).target_alias(name)
        parts = self.parse_target(target)
        if parts is not None:
            kind, percent = parts
            if percent:
                if kind != "nonfree":
                    base_target = "%(head)s.memory." + kind
                else:
                    base_target = sum_series(
                        exclude("%(head)s.memory.*", 'free')
                    )
                target = as_percent(
                    base_target, sum_series("%(head)s.memory.*")
                )
            elif kind == 'nonfree':
                target = sum_series(exclude("%(head)s.memory.*", 'free'))
        return target, alias


class PingHandler(CustomHandler):
    plugin = "ping"

    def parse_target(self, target):
        parts = super(PingHandler, self).parse_target(target)
        if parts is not None:
            if len(parts) == 2:
                kind, host = parts
                if kind.startswith("ping_"):
                    kind = kind[5:]
                return kind, host.replace("_", ".")
            elif len(parts) == 1:
                host = parts[0]
                return "rtt", host.replace("_", ".")
        log.error("%s() got invalid target: '%s'.",
                  self.__class__.__name__, target)

    def decorate_target(self, target):
        metric = super(PingHandler, self).decorate_target(target)
        parts = self.parse_target(metric['alias'])
        if parts is not None:
            kind, host = parts
            metric['name'] = "Ping %s %s" % (kind, host)
            if kind == "rtt":
                metric['unit'] = 'ms'
            metric['priority'] = 0
        return metric


class MultiHandler(GenericHandler):
    def __init__(self, uuid, telegraf=False, telegraf_since=None):
        super(MultiHandler, self).__init__(uuid, telegraf=telegraf,
                                           telegraf_since=telegraf_since)
        self.handlers = {
            'generic': GenericHandler,
            'interface': InterfaceHandler,
            'disk': DiskHandler,
            'load': LoadHandler,
            'cpu': CpuHandler,
            'memory': MemoryHandler,
            'ping': PingHandler,
        }
        self.vtargets = []

    def get_handler(self, target=""):
        plugin = "generic"
        if target in self.handlers:
            plugin = target
        else:
            parts = self.target_alias(target)[0].split(".")
            if len(parts) > 1 and parts[0] == "%(head)s":
                if parts[1] in self.handlers:
                    plugin = parts[1]
        log.debug("get_handler plugin: %s", plugin)
        return self.handlers[plugin](self.uuid, telegraf=self.telegraf,
                                     telegraf_since=self.telegraf_since)

    def find_metrics(self, plugin=""):
        if plugin:
            plugins = [plugin]
        else:
            query = "%s.*" % self.head()
            top_level_metrics = self._find_metrics(query)
            plugins = [metric['id'].split(".")[-1]
                       for metric in top_level_metrics]
        metrics = []
        for plugin in plugins:
            handler = self.get_handler(plugin)
            metrics += handler.find_metrics(plugin=plugin)
        return metrics

    def get_data(self, targets, start="", stop="", interval_str=""):
        if isinstance(targets, string_types):
            targets = [targets]
        current_handlers = {}
        for target in targets:
            handler = self.get_handler(target)
            if handler not in current_handlers:
                current_handlers[handler] = []
            current_handlers[handler].append(target)
        max_targets = 5  # max targets per http request
        started_at = time.time()
        run_args = []
        for handler, targets in list(current_handlers.items()):
            while targets:
                run_args.append((handler.get_data, targets[:max_targets]))
                targets = targets[max_targets:]

        def _run(xxx_todo_changeme):
            (func, targets) = xxx_todo_changeme
            try:
                return func(targets, start=start, stop=stop,
                            interval_str=interval_str)
            except Exception as exc:
                log.warning("Multihandler got response: %r", exc)
                return []

        # TODO This should be implemented using `gevent.Pool`, if needed. For
        # now, only one target is specified at a time.
        # pool = ThreadPool(10)
        # parts = pool.map(_run, run_args)
        # data = reduce(lambda x, y: x + y, parts)
        # pool.terminate()

        parts = list(map(_run, run_args))
        data = reduce(lambda x, y: x + y, parts)

        log.info("Multihandler get_data completed in: %.2f secs",
                 time.time() - started_at)

        # align start/stop
        starts = set()
        stops = set()
        for item in data:
            starts.add(item['datapoints'][0][1])
            stops.add(item['datapoints'][-1][1])
        start = max(starts) if len(starts) > 1 else 0
        stop = min(stops) if len(stops) > 1 else 0
        if start or stop:
            log.debug("%s %s %s %s", starts, start, stops, stop)
            for item in data:
                if start:
                    for i in range(len(item['datapoints'])):
                        if item['datapoints'][i][1] >= start:
                            if i:
                                item['datapoints'] = item['datapoints'][i:]
                            break
                if stop:
                    for i in range(len(item['datapoints'])):
                        if item['datapoints'][-(i + 1)][1] <= stop:
                            if i:
                                item['datapoints'] = item['datapoints'][:-i]
                            break
        return data

    def decorate_target(self, target):
        return self.get_handler(target).decorate_target(target)


def get_multi_uuid(uuids, target, start="", stop="", interval_str=""):
    """Get the same metric for multiple uuids

    uuids should be a list of uuids
    target should be a string containing '%(uuid)s'
    """
    target = target % {'uuid': '{' + ','.join(uuids) + '}'}
    if interval_str:
        target = summarize(target, interval_str)
    params = [('target', target),
              ('from', start or None),
              ('until', stop or None),
              ('format', 'json')]
    resp = requests.post('%s/render' % config.GRAPHITE_URI, data=params)
    if not resp.ok:
        log.error(resp.text)
        raise Exception(str(resp))
    return resp.json()
