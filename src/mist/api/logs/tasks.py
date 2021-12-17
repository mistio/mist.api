import logging
import requests

from mist.api.dramatiq_app import dramatiq

from mist.api import config
from datetime import datetime

log = logging.getLogger(__name__)

__all__ = [
    'elasticsearch_cleanup'
]

first_log_year = 2010

indices_to_delete = [
    'machines_inventory-{year}*', 'exceptions-{year}*',
    'cloudify-metrics-{year}*'
]

indices_to_forcemerge = [
    'machines_inventory-{year}*', 'exceptions-{year}*',
    'cloudify-metrics-{year}*', 'portals-{year}',
    'app-logs-{year}', 'ui-logs-{year}'
]

delete_policy = {
    "default": (first_log_year, datetime.now().year - 1)
}

forcemerge_policy = {
    "default": (datetime.now().year - 1, datetime.now().year)
}


def delete(index):
    method = 'https' if config.ELASTICSEARCH['elastic_use_ssl'] else 'http'
    result = requests.delete(
        (f"{method}://{config.ELASTICSEARCH['elastic_host']}"
            f":{config.ELASTICSEARCH['elastic_port']}/{index}"),
        params={"timeout": "1m"}, auth=(
            config.ELASTICSEARCH['elastic_username'],
            config.ELASTICSEARCH['elastic_password']),
        verify=config.ELASTICSEARCH['elastic_verify_certs'])
    print(f"* Delete index '{index}': {result.json()}")


def forcemerge(index):
    method = 'https' if config.ELASTICSEARCH['elastic_use_ssl'] else 'http'
    result = requests.post(
        (f"{method}://{config.ELASTICSEARCH['elastic_host']}"
            f":{config.ELASTICSEARCH['elastic_port']}/{index}/_forcemerge"),
        params={"max_num_segments": "1", "flush": "true"},
        auth=(
            config.ELASTICSEARCH['elastic_username'],
            config.ELASTICSEARCH['elastic_password']
        ),
        verify=config.ELASTICSEARCH['elastic_verify_certs'])
    print(f"* Force merge for index '{index}': {result.json()}")


def merge_stats():
    method = 'https' if config.ELASTICSEARCH['elastic_use_ssl'] else 'http'
    result = requests.get(
        (f"{method}://{config.ELASTICSEARCH['elastic_host']}"
            f":{config.ELASTICSEARCH['elastic_port']}/_stats/merge"),
        auth=(
            config.ELASTICSEARCH['elastic_username'],
            config.ELASTICSEARCH['elastic_password']
        ),
        verify=config.ELASTICSEARCH['elastic_verify_certs'])
    print(f"* Stats: {(result.json())['_all']['total']}")


@dramatiq.actor
def elasticsearch_cleanup():
    for index in indices_to_delete:
        for year in range(
                *delete_policy.get(index, delete_policy["default"])):
            delete(index.format(year=year))

    for index in indices_to_forcemerge:
        for year in range(
                *forcemerge_policy.get(index, forcemerge_policy["default"])):
            forcemerge(index.format(year=year))
