import time
import uuid
import logging
from random import randrange
import mongoengine as me
import dramatiq
from dramatiq.errors import Retry

from libcloud.compute.types import NodeState
from libcloud.container.base import Container

from mist.api.clouds.models import Cloud, DockerCloud
from mist.api.machines.models import Machine
from mist.api.users.models import Owner
from mist.api.schedules.models import Schedule
from mist.api.keys.models import Key
from mist.api.dns.models import RECORDS

from mist.api.exceptions import MachineCreationError

from mist.api.methods import connect_provider
from mist.api.methods import notify_user, notify_admin
from mist.api.auth.methods import AuthContext
from mist.api.logs.methods import log_event
from mist.api.tag.methods import resolve_id_and_set_tags
from mist.api.monitoring.methods import enable_monitoring

from mist.api import config
from mist.api.shell import Shell
from mist.api.dramatiq_app import broker


logging.basicConfig(
    level=config.PY_LOG_LEVEL,
    format=config.PY_LOG_FORMAT,
    datefmt=config.PY_LOG_FORMAT_DATE,
)
log = logging.getLogger(__name__)


def tmp_log(msg, *args):
    log.error("Post deploy: %s" % msg, *args)


@dramatiq.actor(queue_name="dramatiq_create_machine", broker=broker)
def dramatiq_create_machine_async(
    auth_context_serialized, job_id, plan, job=None
):

    auth_context = AuthContext.deserialize(auth_context_serialized)
    cloud = Cloud.objects.get(id=plan["cloud"])
    try:
        node = cloud.ctl.compute.create_machine(plan)
    except MachineCreationError:
        # TODO Handle creation, linode might throw exception and still
        # create the machine, causing the task to be retried and as a result
        # creating multiple machines
        pass
    for i in range(0, 10):
        try:
            machine = Machine.objects.get(cloud=cloud, machine_id=node.id)
            break
        except me.DoesNotExist:
            if i < 6:
                time.sleep(i * 10)
                continue
            try:
                cloud.ctl.compute._list_machines()
            except Exception as e:
                if i > 8:
                    raise (e)
                else:
                    continue

    machine.assign_to(auth_context.user)
    if plan["expiration"]:
        params = {
            "schedule_type": "one_off",
            "description": "Scheduled to run when machine expires",
            "schedule_entry": plan["expiration"].get("date"),
            "action": plan["expiration"].get("action"),
            "selectors": [{"type": "machines", "ids": [machine.id]}],
            "task_enabled": True,
            "notify": plan["expiration"].get("notify", ""),
            "notify_msg": plan["expiration"].get("notify_msg", ""),
        }
        name = machine.name + "-expiration-" + str(randrange(1000))
        machine.expiration = Schedule.add(auth_context, name, **params)
        machine.save()
    # Associate key.
    if plan["key"] is not None:
        key = Key.objects.get(id=plan["key"])
        username = node.extra.get("username", "")
        machine.ctl.associate_key(
            key, username=username, port=22, no_connect=True
        )
    if plan["tags"]:
        resolve_id_and_set_tags(
            auth_context.owner,
            "machine",
            node.id,
            plan["tags"],
            cloud_id=cloud.id,
        )

    dramatiq_post_deploy.send(
        auth_context_serialized,
        auth_context.owner.id,
        cloud.id,
        machine.id,
        node.id,
        plan,
        job_id=job_id,
        job=job,
    )


@dramatiq.actor(queue_name="dramatiq_post_deploy_steps")
def dramatiq_post_deploy(
    auth_context_serialized,
    owner_id,
    cloud_id,
    machine_id,
    external_id,
    plan,
    job_id=None,
    job=None,
):
    # TODO check how dramatiq handles different
    # num of retries based on some conditions
    owner = Owner.objects.get(id=owner_id)
    job_id = job_id or uuid.uuid4().hex

    tmp_log(
        "Entering post deploy steps for %s %s %s",
        owner.id,
        cloud_id,
        external_id,
    )

    node = None
    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        conn = connect_provider(cloud)

        if isinstance(cloud, DockerCloud):
            nodes = conn.list_containers()
        else:
            nodes = conn.list_nodes()  # TODO: use cache
        for n in nodes:
            if n.id == external_id:
                node = n
                break
        msg = "Cloud:\n  Name: %s\n  Id: %s\n" % (cloud.title, cloud_id)
        msg += "Machine:\n  Name: %s\n  Id: %s\n" % (node.name, node.id)
        tmp_log("Machine found, proceeding to post deploy steps\n%s" % msg)
    except Exception as exc:
        tmp_log("Got exception %s, retrying" % str(exc))
        raise Retry(delay=10000)

    if node and isinstance(node, Container):
        node = cloud.ctl.compute.inspect_node(node)

    if node:
        # filter out IPv6 addresses
        ips = [
            ip for ip in node.public_ips + node.private_ips if ":" not in ip
        ]
        if not ips:
            tmp_log("ip not found, retrying")
            raise Retry(delay=60000)
        host = ips[0]
        tmp_log("Host Found, %s" % host)
    else:
        tmp_log("ip not found, retrying")
        raise Retry(delay=60000)

    if node.state != NodeState.RUNNING:
        tmp_log("not running state")
        # raise Retry(delay=120000)
        raise Retry(delay=60000)
    # auth_context = AuthContext.deserialize(auth_context_serialized)
    log_dict = {
        "owner_id": owner.id,
        "event_type": "job",
        "cloud_id": cloud_id,
        "machine_id": machine_id,
        "external_id": external_id,
        "job_id": job_id,
        "job": job,
        "host": host,
        "key_id": plan.get("key"),
    }
    # TODO chain tasks
    pipe = (
        dramatiq_add_schedules.message_with_options(
            args=(auth_context_serialized, external_id, machine_id, log_dict),
            kwargs={"schedule": plan.get("schedules")},
            options={"pipe_ignore": True},
        )
        | dramatiq_add_dns_record.message_with_options(
            args=(auth_context_serialized, host, log_dict),
            # kwargs={"fqdn": plan.get("fqdn")},
            kwargs={"fqdn": ''},
            options={"pipe_ignore": True},
        )
        | dramatiq_enable_monitoring.message_with_options(
            args=(
                auth_context_serialized,
                cloud_id,
                job_id,
                external_id,
                log_dict,
            ),
            kwargs={
                "monitoring": plan.get("monitoring", False),
                "plugins": None,
            },
            options={"pipe_ignore": True},
        )
    )
    pipe.run()


@dramatiq.actor(queue_name="dramatiq_add_schedules")
def dramatiq_add_schedules(
    auth_context_serialized, external_id, machine_id, log_dict, schedule=None
):
    # TODO Handle multiple schedules
    auth_context = AuthContext.deserialize(auth_context_serialized)
    if schedule and schedule.get("name"):  # ugly hack to prevent dupes
        try:
            name = (
                schedule.get("action")
                + "-"
                + schedule.pop("name")
                + "-"
                + external_id[:4]
            )
            tmp_log("Add scheduler entry %s", name)
            schedule["selectors"] = [{"type": "machines", "ids": [machine_id]}]
            schedule_info = Schedule.add(auth_context, name, **schedule)
            tmp_log("A new scheduler was added")
            log_event(
                action="Add scheduler entry",
                scheduler=schedule_info.as_dict(),
                **log_dict
            )
        except Exception as e:
            print(repr(e))
            error = repr(e)
            notify_user(
                auth_context.owner,
                "add scheduler entry failed for " "machine %s" % external_id,
                repr(e),
                error=error,
            )
            log_event(
                action="Add scheduler entry failed", error=error, **log_dict
            )


@dramatiq.actor(queue_name="dramatiq_add_dns_record")
def dramatiq_add_dns_record(
    auth_context_serialized, host, log_dict, fqdn=None
):
    if fqdn:
        kwargs = {}
        auth_context = AuthContext.deserialize(auth_context_serialized)
        try:
            kwargs["name"] = fqdn
            kwargs["type"] = "A"
            kwargs["data"] = host
            kwargs["ttl"] = 3600

            dns_cls = RECORDS[kwargs["type"]]
            dns_cls.add(owner=auth_context.owner, **kwargs)
            log_event(action="Create_A_record", hostname=fqdn, **log_dict)
        except Exception as exc:
            log_event(
                action="Create_A_record",
                hostname=fqdn,
                error=str(exc),
                **log_dict
            )


@dramatiq.actor(queue_name="dramatiq_enable_monitoring")
def dramatiq_enable_monitoring(
    auth_context_serialized,
    cloud_id,
    job_id,
    external_id,
    log_dict,
    monitoring=False,
    plugins=None,
):
    if monitoring:
        auth_context = AuthContext.deserialize(auth_context_serialized)
        try:
            enable_monitoring(
                auth_context.owner,
                cloud_id,
                external_id,
                no_ssh=False,
                dry=False,
                job_id=job_id,
                plugins=plugins,
                deploy_async=False,
            )
        except Exception as e:
            print(repr(e))
            notify_user(
                auth_context.owner,
                "Enable monitoring failed for machine %s" % external_id,
                repr(e),
            )
            notify_admin(
                "Enable monitoring on creation failed for "
                "user %s machine %s: %r"
                % (str(auth_context.owner), external_id, e)
            )
            log_event(
                action="enable_monitoring_failed", error=repr(e), **log_dict
            )
