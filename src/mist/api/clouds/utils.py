import logging
import ssl

from libcloud.common.types import LibcloudError, InvalidCredsError
from libcloud.common.types import MalformedResponseError
from libcloud.common.exceptions import BaseHTTPError, RateLimitReachedError

from mist.api.exceptions import CloudUnauthorizedError, CloudUnavailableError
from mist.api.exceptions import RateLimitError, BadRequestError


log = logging.getLogger(__name__)


def tags_to_dict(tags):
    """Return a dict with each key/value tag being a dict item

    This will handle:
    - dict {key1: value1, key2: value2, ...}
    - lists of {key: value} pairs
    - lists of {"key": key, "value": value} pairs, value field is optional

    It will return:
    dict {key1: value1, key2: value2, ...}

    """

    if isinstance(tags, dict):
        return tags
    tdict = {}
    for tag in tags:
        if isinstance(tag, dict):
            if len(tag) == 1:
                key = list(tag.keys())[0]
                tdict[tag] = tag[key]
            elif 'key' in tag:
                tdict[tag['key']] = tag.get('value')
    return tdict


class LibcloudExceptionHandler(object):
    def __init__(self, exception_class):
        self.exception_class = exception_class

    def __call__(self, func, *args, **kwargs):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except InvalidCredsError as exc:
                log.error("Invalid creds on running %: %s", func.__name__, exc)
                raise CloudUnauthorizedError(exc=exc, msg=str(exc))
            except ssl.SSLError as exc:
                log.error("SSLError on running %s: %s", func.__name__, exc)
                raise CloudUnavailableError(exc=exc, msg=str(exc))
            except MalformedResponseError as exc:
                log.error("MalformedResponseError on running %s: %s", exc)
                raise exc
            except RateLimitReachedError as exc:
                log.error("Rate limit error on running %s: %s", func.__name__,
                          exc)
                raise RateLimitError(exc=exc, msg=str(exc))
            # Libcloud errors caused by invalid parameters are raised as this
            # exception class
            except BaseHTTPError as exc:
                log.error("Bad request on running %s: %s", func.__name__, exc)
                if 'unauthorized' in str(exc).lower():
                    raise CloudUnauthorizedError(exc=exc, msg=str(exc))
                raise BadRequestError(exc=exc,
                                      msg=str(exc))
            except LibcloudError as exc:
                log.error("Error on running %s: %s", func.__name__, exc)
                raise self.exception_class(exc=exc, msg=str(exc))

        return wrapper
