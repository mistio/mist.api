import logging
import asyncio
import json
import datetime
import requests

from mist.api import config

from mist.api.helpers import requests_retry_session
from mist.api.helpers import get_victoriametrics_write_uri
from mist.api.helpers import get_victoriametrics_uri
log = logging.getLogger(__name__)


def update_metering_data(cloud, resource_type, cached_resources_map, resources_map):  # noqa
    # Generate promql queries to fetch the last metering values
    # of metrics of type counter. This is required in order to calculate
    # the new values of the counter metrics since Prometheus doesn't
    # natively support the ability to increment counter metrics.

    assert resource_type in ("machine", "volume")

    config_metering_metrics = config.METERING_METRICS.get(resource_type, {})

    read_queries, metering_metrics = generate_metering_queries(
        cloud, resource_type, config_metering_metrics,
        cached_resources_map, resources_map)

    client = PrometheusMeteringClient(cloud, resource_type)

    # Fetch the last metering values for counter metrics.
    last_metering_data = fetch_metering_data(
        client, read_queries, resources_map)

    # Generate Prometheus remote write compatible payload.
    fresh_metering_data = generate_fresh_metering_data(
        client, cached_resources_map, resources_map,
        last_metering_data, metering_metrics)

    # Send metrics payload.
    client.send_metering_data(fresh_metering_data)


def get_resource_metering_metrics(
        resource_id, resources_map, metering_metrics):
    resource_owner = resources_map[resource_id].owner.id
    resource_provider = resources_map[resource_id].cloud.provider

    if metering_metrics.get(resource_owner):
        return metering_metrics[resource_owner]

    if metering_metrics.get(resource_provider):
        return metering_metrics[resource_provider]

    if metering_metrics.get("default"):
        return metering_metrics["default"]

    return {}


def populate_metering_metrics_map(config_metering_metrics, resources_map):
    """
    Populates a dict where it maps owner id, cloud provider
    or default to the appropriate metering metrics. This
    helps us later on to choose which metrics we should generate
    for each resource.
    """
    if not config_metering_metrics:
        return {}
    metering_metrics = {}
    for resource_id, _ in resources_map.items():
        resource_owner = resources_map[resource_id].owner.id
        resource_cloud_provider = resources_map[resource_id].cloud.provider

        owner_metrics = config_metering_metrics.get(resource_owner, {})
        provider_metrics = config_metering_metrics.get(
            resource_cloud_provider, {})
        default_metrics = config_metering_metrics.get(
            "default", {})

        if owner_metrics and not metering_metrics.get(resource_owner):
            metering_metrics[resource_owner] = default_metrics
            metering_metrics[resource_owner].update(provider_metrics)
            metering_metrics[resource_owner].update(owner_metrics)

        if provider_metrics and not metering_metrics.get(resource_cloud_provider):  # noqa
            metering_metrics[resource_cloud_provider] = default_metrics
            metering_metrics[resource_cloud_provider].update(
                provider_metrics)

        if default_metrics and not metering_metrics.get("default"):
            metering_metrics["default"] = default_metrics

    return metering_metrics


def group_resources_by_timestamp(cached_resources_map, resources_map):
    """
    Group the resources by timestamp
    """
    grouped_resources_by_dt = {}
    for resource_id, _ in resources_map.items():
        if not cached_resources_map.get(resource_id):
            continue
        cached_resource = cached_resources_map[resource_id]
        dt = None

        # Use either the last_seen or missing_since timestamp
        # to get the last value of the counter
        if cached_resource.get("last_seen"):
            dt = cached_resource["last_seen"]
        elif cached_resource.get("missing_since"):
            dt = cached_resource["missing_since"]

        if not dt:
            continue

        if not grouped_resources_by_dt.get(dt):
            grouped_resources_by_dt[dt] = []

        # Group the resources by timestamp
        grouped_resources_by_dt[dt].append(resource_id)

    return grouped_resources_by_dt


def group_resources_by_type(config_metering_metrics, resources_map, grouped_resources_by_dt):  # noqa
    """
    Further group down the resources into metric categories
    (owner id, cloud provider or default). This means that
    queries are grouped by timestamp, metric_category.
    """
    grouped_resources = {}
    for dt, resource_ids in grouped_resources_by_dt.items():
        for resource_id in resource_ids:
            resource_owner = resources_map[resource_id].owner.id
            resource_cloud_provider = resources_map[resource_id].cloud.provider

            if config_metering_metrics.get(resource_owner):
                if not grouped_resources.get((dt, resource_owner)):
                    grouped_resources[(dt, resource_owner)] = []

                grouped_resources[(dt, resource_owner)].append(resource_id)

            elif config_metering_metrics.get(resource_cloud_provider):
                if not grouped_resources.get((dt, resource_cloud_provider)):
                    grouped_resources[(dt, resource_cloud_provider)] = []

                grouped_resources[(dt, resource_cloud_provider)
                                  ].append(resource_id)

            elif config_metering_metrics.get("default"):
                if not grouped_resources.get((dt, "default")):
                    grouped_resources[(dt, "default")] = []

                grouped_resources[(dt, "default")].append(
                    resource_id)
    return grouped_resources


def generate_metering_queries(cloud, resource_type, config_metering_metrics, cached_resources_map, resources_map):  # noqa
    """
    Generate metering promql queries while grouping queries together
    to limit the number of requests to the DB
    """
    if not resources_map or not config_metering_metrics:
        return {}, {}

    metering_metrics = populate_metering_metrics_map(
        config_metering_metrics, resources_map)

    if not metering_metrics:
        return {}, {}

    grouped_resources_by_dt = group_resources_by_timestamp(
        cached_resources_map, resources_map)

    grouped_resources = group_resources_by_type(
        config_metering_metrics, resources_map, grouped_resources_by_dt)

    # Generate Prometheus queries which fetch metering data for multiple
    # resources at once when they share the same timestamp and metrics.
    read_queries = {}
    for key, resource_ids in grouped_resources.items():
        dt, metrics_category = key

        metering_metrics_list = "|".join(
            metric_name
            for metric_name, properties in metering_metrics[
                metrics_category].items()
            if properties['type'] == "counter")

        resources_ids_list = "|".join(resource_ids)
        read_queries[(dt, metrics_category)] = (
            f"{{__name__=~\"{metering_metrics_list}\""
            f",org=\"{cloud.owner.id}\","
            f"{resource_type}_id=~\"{resources_ids_list}\""
            f",metering=\"true\"}}")

    return read_queries, metering_metrics


async def async_fetch_metering_data(client, read_queries, loop):
    metering_data_list = [loop.run_in_executor(
        None, client.fetch_query, key[0], query)
        for key, query in read_queries.items()]

    return await asyncio.gather(*metering_data_list)


def fetch_metering_data(client, read_queries, resources_map):
    if not read_queries or not resources_map:
        return {}
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError('loop is closed')
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    asyncio.set_event_loop(loop)

    # Fetch queries
    queries_result = loop.run_until_complete(
        async_fetch_metering_data(client, read_queries, loop))
    loop.close()

    # Combine metering data from multiple queries and group it
    # by resource id
    metering_data = {}
    for resource_id, _ in resources_map.items():
        metering_data[resource_id] = {}

        for query_result in queries_result:
            if not query_result.get(resource_id):
                continue

            metering_data[resource_id].update(
                query_result[resource_id])

    return metering_data


def calculate_metering_data(client, resource_id, resource,
                            new_dt, old_dt, metric_name,
                            properties, last_metering_data):
    current_value = None
    if properties["type"] == "counter":
        old_value = last_metering_data.get(
            resource_id, {}).get(metric_name)
        if old_value:
            current_value = float(old_value)
            # Calculate the new counter by
            # taking into account the time range
            # between now and the last time the counter
            # was saved. Ignore it in case the resource
            # was missing.
            if old_dt:
                delta_in_hours = (
                    new_dt - old_dt).total_seconds() / (60 * 60)
                current_value += properties["value"](
                    resource, delta_in_hours)
        else:
            # When we can't find the last counter value,
            # in order to avoid counter resets, we check
            # again for the last counter up to
            # METERING_PROMQL_LOOKBACK time in the past
            current_value = client.find_old_counter_value(
                metric_name, resource_id, properties)
    elif properties["type"] == "gauge":
        current_value = properties["value"](resource)
    else:
        log.warning(
            f"Unknown metric type: {properties['type']}"
            f" on metric: {metric_name}"
            f" with {client.resource_type}_id: {resource_id}")
    if current_value is not None:
        return (
            f"{metric_name}{{org=\"{client.org}\""
            f",{client.resource_type}_id=\"{resource_id}\",metering=\"true\""
            f",value_type=\"{properties['type']}\"}}"
            f" {current_value} "
            f"{int(datetime.datetime.timestamp(new_dt))}\n")
    else:
        log.warning(
            f"None value on metric: "
            f"{metric_name} with {client.resource_type}_id: {resource_id}")
    return ""


async def async_generate_fresh_metering_data(client, resources_map,
                                             cached_resources_map,
                                             metering_metrics,
                                             last_metering_data, loop):
    metering_data_list = []
    for resource_id, resource in resources_map.items():
        if not resource.last_seen:
            continue
        new_dt = resource.last_seen
        old_dt = None
        cached_resource = cached_resources_map.get(resource_id)
        if cached_resource and cached_resource.get("last_seen"):
            old_dt = datetime.datetime.strptime(
                cached_resource["last_seen"], '%Y-%m-%d %H:%M:%S.%f')
        metering_data_list.extend(
            loop.run_in_executor(
                None, calculate_metering_data, client, resource_id,
                resource, new_dt, old_dt, metric_name, properties,
                last_metering_data
            )
            for metric_name, properties in get_resource_metering_metrics(
                resource_id, resources_map, metering_metrics).items()
        )

    return await asyncio.gather(*metering_data_list)


def generate_fresh_metering_data(
        client, cached_resources_map, resources_map,
        last_metering_data, metering_metrics):
    if not resources_map or not metering_metrics:
        return ""

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError('loop is closed')
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    asyncio.set_event_loop(loop)

    # Generate fresh metering data with asyncio
    # to avoid slowdowns. This is required since
    # queries to the timeseries DB may be required.
    metering_data_list = loop.run_until_complete(
        async_generate_fresh_metering_data(client, resources_map,
                                           cached_resources_map,
                                           metering_metrics,
                                           last_metering_data,
                                           loop))
    loop.close()
    return "".join(metering_data_list)


def report_metering_error(error_msg, error_details):
    from mist.api.methods import notify_admin
    log_entry = f"{error_msg}, {error_details}"
    log.warning(log_entry)
    if not config.METERING_NOTIFICATIONS_WEBHOOK:
        notify_admin(error_msg, message=error_details)
        return
    try:
        response = requests_retry_session(retries=2).post(
            config.METERING_NOTIFICATIONS_WEBHOOK, data=json.dumps(
                {'text': f'{config.CORE_URI}: {log_entry}'}),
            headers={'Content-Type': 'application/json'}, timeout=5)

    except requests.exceptions.RequestException as e:
        log.error(f'Request to slack returned an error {str(e)}')
        notify_admin(error_msg, message=error_details)
        return
    if response and response.status_code not in (200, 429):
        log.error(
            f"Request to slack returned an error {response.status_code}"
            f", the response is:\n{response.text}"
        )
        notify_admin(error_msg, message=error_details)


class PrometheusMeteringClient:
    def __init__(self, cloud, resource_type):
        self.write_uri = (f"{get_victoriametrics_write_uri(cloud.owner)}"
                          f"/api/v1/import/prometheus")
        self.read_uri = f"{get_victoriametrics_uri(cloud.owner)}/api/v1/query"
        self.org = cloud.owner.id
        self.resource_type = resource_type

    def send_metering_data(self, fresh_metering_data):
        if not fresh_metering_data:
            return
        error_msg = "Could not send metering data"
        result = None
        try:
            result = requests_retry_session(retries=1).post(
                self.write_uri, data=fresh_metering_data, timeout=10)
        except requests.exceptions.RequestException as e:
            error_details = str(e)
            report_metering_error(error_msg, error_details)
        if result and not result.ok:
            error_details = (f"code: {result.status_code}"
                             f" response: {result.text}")
            report_metering_error(error_msg, error_details)

    def find_old_counter_value(self, metric_name, resource_id, properties):
        query = (
            f"last_over_time("
            f"{metric_name}{{org=\"{self.org}\""
            f",{self.resource_type}_id=\"{resource_id}\",metering=\"true\""
            f",value_type=\"{properties['type']}\"}}"
            f"[{config.METERING_PROMQL_LOOKBACK}])"
        )
        error_msg = f"Could not fetch old counter value with query: {query}"
        try:
            data = requests_retry_session(retries=1).post(
                self.read_uri, data={"query": query}, timeout=10)
        except requests.exceptions.RequestException as e:
            error_details = str(e)
            report_metering_error(error_msg, error_details)
            return None
        if data and not data.ok:
            error_details = f"code: {data.status_code} response: {data.text}"
            report_metering_error(error_msg, error_details)
            return None

        data = data.json()
        results = data.get("data", {}).get("result", [])
        if len(results) > 1:
            log.warning("Returned more series than expected")
        if len(results) == 0:
            return 0
        return results[0]["value"][1]

    def fetch_query(self, dt, query):
        dt = int(datetime.datetime.timestamp(
            datetime.datetime.strptime(dt, '%Y-%m-%d %H:%M:%S.%f')))
        error_msg = f"Could not fetch metering data with query: {query}"

        try:
            data = requests_retry_session(retries=1).post(
                self.read_uri, data={"query": query, "time": dt},
                timeout=10
            )
        except requests.exceptions.RequestException as e:
            error_details = str(e)
            report_metering_error(error_msg, error_details)
            return {}
        if data and not data.ok:
            error_details = (f"code: {data.status_code}"
                             f" response: {data.text}")
            report_metering_error(error_msg, error_details)
            return {}

        data = data.json()

        metering_data = {}

        # Parse payload and group metrics data by resource id
        for result in data.get("data", {}).get("result", []):
            metric_name = result["metric"]["__name__"]
            resource_id = result["metric"][f"{self.resource_type}_id"]
            value = result["value"][1]

            if not metering_data.get(resource_id):
                metering_data[resource_id] = {}

            metering_data[resource_id].update({metric_name: value})

        return metering_data
