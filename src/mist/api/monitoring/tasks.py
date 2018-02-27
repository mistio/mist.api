import uuid
import time
import logging

from mist.api.celery_app import app

import mist.api.shell

from mist.api.helpers import trigger_session_update
from mist.api.exceptions import MistError
from mist.api.logs.methods import log_event

from mist.api.users.models import Organization
from mist.api.clouds.models import Cloud
from mist.api.machines.models import Machine

from mist.api.monitoring.commands import unix_install, unix_uninstall
from mist.api.monitoring.traefik import reset_config, _get_config


log = logging.getLogger(__name__)


@app.task(soft_time_limit=480, time_limit=600)
def install_telegraf(owner_id, cloud_id, machine_id, job=None, job_id=None):
    """Deploy Telegraf over SSH."""
    owner = Organization.objects.get(id=owner_id)
    cloud = Cloud.objects.get(owner=owner, id=cloud_id)
    machine = Machine.objects.get(cloud=cloud, machine_id=machine_id)
    machine.monitoring.installation_status.state = 'installing'
    machine.save()

    trigger_session_update(owner, ['monitoring'])

    _log = {
        'owner_id': owner.id,
        'event_type': 'job',
        'cloud_id': cloud_id,
        'machine_id': machine_id,
        'job_id': job_id or uuid.uuid4().hex, 'job': job,
    }
    log_event(action='telegraf_deployment_started', **_log)

    # FIXME: Use an optimized method returning the first found hostname or IP.
    host = machine.hostname
    if not host:
        for host in (machine.public_ips or []) + (machine.private_ips or []):
            if ':' not in host:  # Filter out IPv6 addresses.
                break
        else:
            raise MistError('Failed to determine hostname or IP address')
    key = None
    try:
        shell = mist.api.shell.Shell(host)
        key, user = shell.autoconfigure(owner, cloud.id, machine.machine_id)
        exit_code, stdout, stderr = shell.command(unix_install(machine), False)
        stdout = stdout.encode('utf-8', 'ignore')
        stdout = stdout.replace('\r\n', '\n').replace('\r', '\n')
    except Exception as err:
        log.error('Error during Telegraf installation: %s', repr(err))
    else:
        err = exit_code or None
    finally:
        # Close the SSH connection.
        shell.disconnect()

        # Update Machine's InstallationStatus.
        if exit_code:
            machine.monitoring.installation_status.state = 'failed'
        else:
            machine.monitoring.installation_status.state = 'succeeded'
        machine.monitoring.installation_status.finished_at = time.time()
        machine.monitoring.installation_status.stdout = stdout
        machine.monitoring.installation_status.error_msg = str(err)
        machine.save()

        # Trigger UI update.
        trigger_session_update(owner, ['monitoring'])

        # Log deployment's outcome.
        _log.update({
            'key_id': key,
            'ssh_user': user,
            'exit_code': exit_code, 'stdout': stdout,
        })
        log_event(action='telegraf_deployment_finished', error=err, **_log)


@app.task(soft_time_limit=480, time_limit=600)
def uninstall_telegraf(owner_id, cloud_id, machine_id, job=None, job_id=None):
    """Undeploy Telegraf."""
    owner = Organization.objects.get(id=owner_id)
    cloud = Cloud.objects.get(owner=owner, id=cloud_id)
    machine = Machine.objects.get(cloud=cloud, machine_id=machine_id)

    _log = {
        'owner_id': owner.id,
        'cloud_id': cloud_id,
        'machine_id': machine_id,
        'job_id': job_id or uuid.uuid4().hex,
        'job': job,
    }
    log_event(action='telegraf_undeployment_started', event_type='job', **_log)

    # FIXME: Use an optimized method returning the first found hostname or IP.
    host = machine.hostname
    if not host:
        for host in (machine.public_ips or []) + (machine.private_ips or []):
            if ':' not in host:  # Filter out IPv6 addresses.
                break
        else:
            raise MistError('Failed to determine hostname or IP address')
    key = None
    try:
        shell = mist.api.shell.Shell(host)
        key, user = shell.autoconfigure(owner, cloud_id, machine_id)
        exit_code, stdout = shell.command(unix_uninstall())
        stdout = stdout.encode('utf-8', 'ignore')
        stdout = stdout.replace('\r\n', '\n').replace('\r', '\n')
    except Exception as err:
        log.error('Error during Telegraf undeployment: %s', repr(err))
    else:
        err = exit_code or None
    finally:
        # Close the SSH connection.
        shell.disconnect()

        # Update Machine's monitoring status.
        machine.monitoring.hasmonitoring = False
        machine.save()

        # Trigger UI update.
        trigger_session_update(owner, ['monitoring'])

        # Log undeployment's outcome.
        _log.update({
            'key_id': key,
            'ssh_user': user,
            'exit_code': exit_code,
            'stdout': stdout
        })
        log_event(action='telegraf_undeployment_finished',
                  event_type='job', error=err, **_log)


@app.task
def reset_traefik_config():
    try:
        _get_config()
    except Exception as exc:
        log.error(exc)
        reset_config()
