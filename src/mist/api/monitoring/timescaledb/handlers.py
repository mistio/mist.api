import logging
log = logging.getLogger(__name__)


def dummy_handler(start=None, stop=None, metrics=None):
    log.info("Dummy handler with args: start=%s,stop=%s,metrics=%s ",
             repr(start),repr(stop),repr(metrics))
    dummy_result = {}
    load1= {}
    load1['priority'] = 0
    load1['min_value'] = None
    load1['name'] = 'SYSTEM load1'
    load1['measurement'] = 'system'
    load1['column'] = 'load1'
    load1['max_value'] = None
    load1['datapoints'] = [(0.73, '1540461445'), (0.67, '1540461450'), 
                           (0.94, '1540461455'), (0.86, '1540461460'), 
                           (0.79, '1540461465'), (0.73, '1540461470'), 
                           (0.83, '1540461475'), (0.85, '1540461480')]
    load1['unit'] = ''
    dummy_result['system.load1'] = load1

    return dummy_result