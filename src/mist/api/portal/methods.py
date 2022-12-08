import datetime
import requests
import dns.resolver

from mist.api.exceptions import InternalServerError

from mist.api import config


def active_websocket_sessions():
    hosts = []
    entries = dns.resolver.query(config.INTERNAL_SOCKJS_HOST, "A")
    for entry in entries:
        hosts.append(entry.address)

    users = {}
    for h in hosts:
        host = '%s:8081' % h
        try:
            resp = requests.get('http://' + host)
            if not resp.ok:
                print("Error response from host '%s': %s" % (host, resp.body))
                raise
            res = resp.json()
        except Exception as exc:
            raise InternalServerError("Error querying host '%s': %r" % (
                host, exc))
        for channel in res.keys():
            for entry in res[channel]:
                if entry['user'] not in users:
                    users[entry['user']] = {

                        'sessions': []
                    }
                users[entry['user']]['sessions'].append((channel, entry))
                if entry['last_rcv'] > users[entry['user']].get('last_rcv', 0):
                    users[entry['user']]['last_rcv'] = entry['last_rcv']

    return users


def should_task_exist_for_cloud(task, cloud):
    """
    Return whether a given cloud should have the specified scheduled task.
    """
    if (task == "list_zones" and cloud.dns_enabled is False) or \
       (task == "list_buckets" and cloud.object_storage_enabled is False) or \
       (task == "list_clusters" and cloud.container_enabled is False) or \
       (task == "list_networks" and getattr(
        cloud.ctl, "network", None) is None) or \
       (task == "list_volumes" and getattr(
        cloud.ctl, "storage", None) is None) or  \
       (task == "list_sizes" and cloud._cls == "Cloud.LibvirtCloud") or \
       (task != "list machines" and cloud._cls == "Cloud.OtherCloud"):
        return False
    return True


def check_task_threshold(cloud, task, acceptable_timedelta):
    """
    Check whether the specific task for the provided cloud was scheduled
    within the acceptable timelimit, irregardless of the tasks success or
    failure.

    If the task was not scheduled within the timedelta an error message
    is returned indicating when the task was last run.
    """
    from mist.api.concurrency.models import PeriodicTaskInfo

    if should_task_exist_for_cloud(task, cloud) is False:
        return None

    FMT = f"cloud:{task}:{cloud.id}"
    try:
        task_info = PeriodicTaskInfo.objects.get(
            key=FMT.format(task=task, cloud_id=cloud.id))
    except PeriodicTaskInfo.DoesNotExist:
        return f"Periodic task {task} does not exist for cloud {cloud}"

    last_success_td = datetime.datetime.now(
    ) - task_info.last_success if task_info.last_success else None

    last_failure_td = datetime.datetime.now(
    ) - task_info.last_failure if task_info.last_failure else None

    if last_success_td is None and last_failure_td is None:
        return f"Periodic task {task} for cloud {cloud} has never run"
    elif last_success_td and last_failure_td:
        if min(last_success_td, last_failure_td) > acceptable_timedelta:
            return f"Periodic task {task} was last run before {min(last_success_td, last_failure_td)} for cloud {cloud}"  # noqa: E501
    else:
        last_run = last_success_td or last_failure_td
        if last_run > acceptable_timedelta:
            return f"Periodic task {task} was last run before {last_run} for cloud {cloud}"  # noqa: E501
