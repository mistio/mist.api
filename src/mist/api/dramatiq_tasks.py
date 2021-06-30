import time
import datetime
import uuid
import logging
import importlib

import secrets
import dramatiq

import mongoengine as me

from dramatiq import actor
from dramatiq.errors import Retry

from paramiko.ssh_exception import SSHException

from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine
from mist.api.schedules.models import Schedule
from mist.api.keys.models import Key
from mist.api.dns.models import RECORDS

from mist.api.exceptions import MachineNotFoundError
from mist.api.exceptions import ServiceUnavailableError
from mist.api.exceptions import MachineUnavailableError

from mist.api import config
from mist.api.dramatiq_app import broker
from mist.api.methods import probe_ssh_only
from mist.api.methods import notify_user, notify_admin
from mist.api.helpers import trigger_session_update
from mist.api.auth.methods import AuthContext
from mist.api.logs.methods import log_event
from mist.api.tag.methods import resolve_id_and_set_tags
from mist.api.monitoring.methods import enable_monitoring
from mist.api.shell import Shell
from mist.api.tasks import run_script
from mist.api.helpers import trigger_session_update
from mist.api.poller.models import ListMachinesPollingSchedule


logging.basicConfig(
    level=config.PY_LOG_LEVEL,
    format=config.PY_LOG_FORMAT,
    datefmt=config.PY_LOG_FORMAT_DATE,
)
log = logging.getLogger(__name__)

task_modules = [
    # 'mist.api.tasks',
    # 'mist.api.auth.tasks',
    # 'mist.api.metering.tasks',
    # 'mist.api.portal.tasks',
    # 'mist.api.poller.tasks',
    # 'mist.api.rules.tasks',
    # 'mist.api.monitoring.tasks'
]
task_map = {
    module: (lambda x: getattr(importlib.import_module(x), '__all__'))(module)
    for module in task_modules
}

actors = {}

print('Loading task modules')
for task_module in task_map.keys():
    print(' * %s:' % task_module)
    for task_name in task_map[task_module]:
        actors[task_name] = getattr(
            importlib.import_module(task_module), task_name)
        # actors[task_name] = actor(
        #     task,
        #     actor_name=task_name,
        #     time_limit=task.time_limit or 5 * 60 * 1000,  # 5 minutes
        #     max_retries=task.max_retries,
        #     broker=broker,
        #     queue_name='dramatiq_schedules'
        # )
        print('  - %s' % task_name)


def tmp_log_error(msg, *args):
    log.error("Post deploy: %s" % msg, *args)


def tmp_log(msg, *args):
    log.info("Post deploy: %s" % msg, *args)


@actor(queue_name="dramatiq_mappings", broker=broker)
def dramatiq_async_session_update(owner, sections=None):
    if sections is None:
        sections = [
            'org', 'user', 'keys', 'clouds', 'stacks',
            'scripts', 'schedules', 'templates', 'monitoring'
        ]
    trigger_session_update(owner, sections)


@actor(queue_name="dramatiq_create_machine", broker=broker, max_retries=0)
def dramatiq_multicreate_async(
    auth_context_serialized, plan, job_id=None, job=None
):
    job_id = job_id or uuid.uuid4().hex
    auth_context = AuthContext.deserialize(auth_context_serialized)
    log_event(auth_context.owner.id, 'job', 'async_machine_creation_started',
              user_id=auth_context.user.id, job_id=job_id, job=job,
              **plan)

    messages = []
    name = plan['machine_name']
    quantity = plan['quantity']

    if quantity == 1:
        messages.append(dramatiq_create_machine_async.message(
            auth_context_serialized, plan, job_id, job))
    else:
        for _ in range(quantity):
            temp_plan = plan.copy()
            temp_plan['machine_name'] = name + '-' + secrets.token_hex(5)
            messages.append(dramatiq_create_machine_async.message(
                auth_context_serialized, temp_plan, job_id, job))

    dramatiq.group(messages, broker=broker).run()


@actor(queue_name="dramatiq_create_machine",
       broker=broker,
       max_retries=0)
def dramatiq_create_machine_async(
    auth_context_serialized, plan, job_id=None, job=None
):

    job_id = job_id or uuid.uuid4().hex
    auth_context = AuthContext.deserialize(auth_context_serialized)
    cloud = Cloud.objects.get(id=plan["cloud"]["id"])

    log_event(
        auth_context.owner.id, 'job', 'sending_create_machine_request',
        job=job, job_id=job_id, cloud_id=plan['cloud']['id'],
        machine_name=plan['machine_name'], user_id=auth_context.user.id,)

    try:
        node = cloud.ctl.compute.create_machine(plan)
    except Exception as exc:
        error = f"Machine creation failed with exception: {str(exc)}"
        tmp_log_error(error)
        log_event(
            auth_context.owner.id, 'job', 'machine_creation_finished',
            job=job, job_id=job_id, cloud_id=plan['cloud']['id'],
            machine_name=plan['machine_name'], user_id=auth_context.user.id,
            error=error
        )
        raise

    tmp_log('Overriding default polling interval')
    schedule = ListMachinesPollingSchedule.objects.get(
        cloud=plan['cloud']['id'])
    schedule.add_interval(10, ttl=600)
    schedule.save()

    for i in range(1, 11):
        try:
            machine = Machine.objects.get(cloud=cloud, machine_id=node.id)
            break
        except me.DoesNotExist:
            time.sleep(i * 10)
    else:
        error = f"Machine with external_id: {node.id} was not found"
        tmp_log_error(error)
        log_event(
            auth_context.owner.id, 'job', 'machine_creation_finished',
            job=job, job_id=job_id, cloud_id=plan['cloud']['id'],
            machine_name=plan['machine_name'], external_id=node.id,
            user_id=auth_context.user.id, error=error
        )
        raise MachineNotFoundError

    machine.assign_to(auth_context.user)

    if plan.get('expiration'):
        try:
            add_expiration_for_machine(auth_context, plan['expiration'],
                                       machine)
        except Exception as exc:
            tmp_log_error('Got exception %s while adding expiration'
                          % str(exc))
    # Associate key.
    if plan.get('key'):
        try:
            key = Key.objects.get(id=plan["key"]["id"])
            username = (plan['key'].get('user') or
                        plan.get('user') or
                        node.extra.get("username", ""))
            # TODO port could be something else
            machine.ctl.associate_key(
                key, username=username, port=22, no_connect=True
            )
        except Exception as exc:
            tmp_log_error('Got exception %s in key association'
                          % str(exc))

    if plan.get('tags'):
        resolve_id_and_set_tags(auth_context.owner, 'machine', node.id,
                                plan['tags'], cloud_id=cloud.id)

    machine = Machine.objects.get(cloud=cloud, machine_id=node.id)

    # first_run is set to True becase poller has already
    # logged an observation event for this machine
    # and we don't want to send it again.
    cloud.ctl.compute.produce_and_publish_patch({},
                                                [machine],
                                                first_run=True
                                                )

    log_event(
        auth_context.owner.id, 'job', 'machine_creation_finished',
        job=job, job_id=job_id, cloud_id=plan['cloud']['id'],
        machine_name=plan['machine_name'], external_id=node.id,
        user_id=auth_context.user.id
    )

    dramatiq_post_deploy.send(auth_context_serialized, cloud.id, machine.id,
                              node.id, plan, job_id=job_id, job=job)


@actor(queue_name="dramatiq_post_deploy_steps",
       broker=broker,
       throws=(me.DoesNotExist, MachineUnavailableError))
def dramatiq_post_deploy(auth_context_serialized, cloud_id,
                         machine_id, external_id, plan,
                         job_id=None, job=None):

    auth_context = AuthContext.deserialize(auth_context_serialized)
    job_id = job_id or uuid.uuid4().hex

    tmp_log(
        "Entering post deploy steps for %s %s %s",
        auth_context.owner.id,
        cloud_id,
        machine_id,
    )

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                                  deleted=None)
    except Cloud.DoesNotExist:
        tmp_log_error("Cloud %s not found. Exiting", cloud_id)
        raise me.DoesNotExist from None

    try:
        machine = Machine.objects.get(cloud=cloud, machine_id=external_id)
    except Machine.DoesNotExist:
        tmp_log_error("Machine %s not found.Exiting", machine_id)
        raise me.DoesNotExist from None

    msg = "Cloud:\n  Name: %s\n  Id: %s\n" % (cloud.title, cloud_id)
    msg += "Machine:\n  Name: %s\n  Id: %s\n" % (machine.name, machine.id)
    tmp_log("Machine found, proceeding to post deploy steps\n%s" % msg)

    if machine.state == 'terminated':
        tmp_log_error("Machine %s terminated. Exiting", machine_id)
        raise MachineUnavailableError
    elif machine.state != 'running':
        tmp_log_error("not running state")
        raise Retry(delay=60000)

    ips = [
        ip for ip in machine.public_ips + machine.private_ips if ":" not in ip
    ]
    try:
        host = ips[0]
    except IndexError:
        tmp_log_error("ip not found, retrying")
        raise Retry(delay=60000) from None

    log_dict = {
        "owner_id": auth_context.owner.id,
        "event_type": "job",
        "cloud_id": cloud_id,
        "machine_id": machine_id,
        "external_id": external_id,
        "job_id": job_id,
        "job": job,
        "host": host,
        "key_id": plan.get("key", {}).get("id"),
    }

    add_schedules(auth_context, machine, log_dict, plan.get("schedules"))

    add_dns_record(auth_context, host, log_dict, plan.get("fqdn"))

    dramatiq_ssh_tasks.send(auth_context_serialized, cloud_id,
                            plan.get("key", {}).get("id"), host, external_id,
                            machine.name, machine_id, plan.get('scripts'),
                            log_dict, monitoring=plan.get('monitoring', False),
                            plugins=None, job_id=job_id,
                            username=None, password=None, port=22)


@actor(queue_name="dramatiq_ssh_tasks", broker=broker)
def dramatiq_ssh_tasks(auth_context_serialized, cloud_id, key_id, host,
                       external_id, machine_name, machine_id, scripts,
                       log_dict, monitoring=False, plugins=None,
                       job_id=None, username=None, password=None, port=22):

    auth_context = AuthContext.deserialize(auth_context_serialized)
    try:
        shell = Shell(host)
        cloud_post_deploy(auth_context, cloud_id, shell, key_id, external_id,
                          machine_name, username=username, password=password,
                          port=port)
        create_key_association(auth_context, shell, cloud_id, key_id,
                               machine_id, host, log_dict, username=username,
                               password=password, port=port)
        run_scripts(auth_context, shell, scripts, cloud_id, host, machine_id,
                    machine_name, log_dict, job_id)
        shell.disconnect()
    except (ServiceUnavailableError, SSHException) as exc:
        tmp_log_error(repr(exc))
        raise Retry(delay=60000)

    if monitoring:
        try:
            enable_monitoring(auth_context.owner, cloud_id, external_id,
                              no_ssh=False, dry=False, job_id=job_id,
                              plugins=plugins, deploy_async=False)
        except Exception as e:
            print(repr(e))
            notify_user(
                auth_context.owner,
                "Enable monitoring failed for machine %s" % machine_id,
                repr(e)
            )
            notify_admin('Enable monitoring on creation failed for '
                         'user %s machine %s: %r'
                         % (str(auth_context.owner), machine_id, e))
            log_event(action='enable_monitoring_failed', error=repr(e),
                      **log_dict)
    log_event(action='post_deploy_finished', error=False, **log_dict)


def add_expiration_for_machine(auth_context, expiration, machine):
    if expiration.get('notify'):
        # convert notify value from datetime str to seconds
        notify = datetime.datetime.strptime(expiration['date'],
                                            '%Y-%m-%d %H:%M:%S') \
            - datetime.datetime.strptime(expiration['notify'],
                                         '%Y-%m-%d %H:%M:%S')
        expiration['notify'] = int(notify.total_seconds())
    params = {
        "schedule_type": "one_off",
        "description": "Scheduled to run when machine expires",
        "schedule_entry": expiration.get("date"),
        "action": expiration.get("action"),
        "selectors": [{"type": "machines", "ids": [machine.id]}],
        "task_enabled": True,
        "notify": expiration.get("notify", ""),
        "notify_msg": expiration.get("notify_msg", ""),
    }
    name = (f'{machine.name}-expiration-{machine.machine_id[:4]}'
            f'-{secrets.token_hex(3)}')
    machine.expiration = Schedule.add(auth_context, name, **params)
    machine.save()


def add_schedules(auth_context, machine, log_dict, schedules):
    schedules = schedules or []
    for schedule in schedules:
        type_ = schedule.get('action') or 'script'
        try:
            name = (f'{machine.name}-{type_}-'
                    f'{machine.machine_id[:4]}-{secrets.token_hex(3)}')
            tmp_log("Add scheduler entry %s", name)
            schedule["selectors"] = [{"type": "machines",
                                      "ids": [machine.id]}]
            schedule_info = Schedule.add(auth_context, name, **schedule)
            tmp_log("A new scheduler was added")
            log_event(
                action="add_schedule_entry",
                scheduler=schedule_info.as_dict(),
                **log_dict
            )
        except Exception as e:
            tmp_log_error("Exception occured %s", repr(e))
            error = repr(e)
            notify_user(
                auth_context.owner,
                "Add scheduler entry failed for machine %s"
                % machine.machine_id,
                repr(e),
                error=error,
            )
            log_event(
                action="add_schedule_entry", error=error,
                **log_dict
            )


def add_dns_record(auth_context, host, log_dict, fqdn):
    if fqdn:
        kwargs = {}
        try:
            kwargs["name"] = fqdn
            kwargs["type"] = "A"
            kwargs["data"] = host
            kwargs["ttl"] = 3600

            dns_cls = RECORDS[kwargs["type"]]
            dns_cls.add(owner=auth_context.owner, **kwargs)
            log_event(action="create_A_record", hostname=fqdn, **log_dict)
            tmp_log("Added A Record, fqdn: %s IP: %s", fqdn, host)
        except Exception as exc:
            log_event(action="create_A_record", hostname=fqdn,
                      error=str(exc), **log_dict)


def cloud_post_deploy(auth_context, cloud_id, shell, key_id, external_id,
                      machine_name, username=None, password=None, port=22):
    try:
        cloud_post_deploy_steps = config.CLOUD_POST_DEPLOY.get(
            cloud_id, [])
    except AttributeError:
        cloud_post_deploy_steps = []
    for post_deploy_step in cloud_post_deploy_steps:
        predeployed_key_id = post_deploy_step.get('key')
        if predeployed_key_id and key_id:
            # Use predeployed key to deploy the user selected key
            shell.autoconfigure(
                auth_context.owner, cloud_id, external_id,
                predeployed_key_id,
                username, password, port
            )
            retval, output = shell.command(
                'echo %s >> ~/.ssh/authorized_keys'
                % Key.objects.get(id=key_id).public)
            if retval > 0:
                notify_admin('Deploy user key failed for machine %s'
                             % machine_name)
        command = post_deploy_step.get('script', '').replace(
            '${node.name}', machine_name)
        if command and key_id:
            tmp_log('Executing cloud post deploy cmd: %s' % command)
            shell.autoconfigure(
                auth_context.owner, cloud_id, machine_name,
                key_id, username, password, port
            )
            retval, output = shell.command(command)
            if retval > 0:
                notify_admin('Cloud post deploy command `%s` failed '
                             'for machine %s' % (command, machine_name))


def create_key_association(auth_context, shell, cloud_id, key_id, machine_id,
                           host, log_dict, username=None, password=None,
                           port=22):
    if key_id:
        # connect with ssh even if no command, to create association
        # to be able to enable monitoring
        tmp_log('attempting to connect to shell')
        key_id, ssh_user = shell.autoconfigure(
            auth_context.owner, cloud_id, machine_id, key_id, username,
            password, port
        )
        tmp_log('connected to shell')
        result = probe_ssh_only(auth_context.owner, cloud_id, machine_id,
                                host=None, key_id=key_id,
                                ssh_user=ssh_user, shell=shell)

        log_dict['ssh_user'] = ssh_user
        log_event(action='probe', result=result, **log_dict)


def run_scripts(auth_context, shell, scripts, cloud_id, host, machine_id,
                machine_name, log_dict, job_id):
    scripts = scripts or []
    for script in scripts:
        if script.get('id'):
            tmp_log('will run script_id %s', script['id'])
            params = script.get('params', '')
            ret = run_script.run(
                auth_context.owner, script['id'], machine_id,
                params=params, host=host, job_id=job_id
            )
            tmp_log('executed script_id %s', script['id'])
        elif script.get('inline'):
            tmp_log('will run inline script')
            log_event(action='script_started', command=script,
                      **log_dict)
            start_time = time.time()
            retval, output = shell.command(script['inline'])
            tmp_log('executed script')
            execution_time = time.time() - start_time
            title = "Deployment script %s" % ('failed' if retval
                                              else 'succeeded')
            notify_user(auth_context.owner, title, cloud_id=cloud_id,
                        machine_id=machine_id, machine_name=machine_name,
                        command=script, output=output, duration=execution_time,
                        retval=retval, error=retval > 0)
            log_event(action='script_finished',
                      error=retval > 0, return_value=retval,
                      command=script, stdout=output,
                      **log_dict)
