import uuid
import time
import logging

from mist.api.celery_app import app

import mist.api.shell

from mist.api.helpers import trigger_session_update
from mist.api.logs.methods import log_event

from mist.api.machines.models import Machine

from mist.api.monitoring.commands import unix_install, unix_uninstall, fetch
from mist.api.monitoring.traefik import reset_config, _get_config


log = logging.getLogger(__name__)


@app.task(soft_time_limit=480, time_limit=600)
def install_telegraf(machine_id, job=None, job_id=None, plugins=None):
    """Deploy Telegraf over SSH."""
    machine = Machine.objects.get(id=machine_id)
    machine.monitoring.installation_status.state = 'installing'
    machine.save()

    trigger_session_update(machine.owner, ['monitoring'])

    _log = {
        'owner_id': machine.owner.id,
        'cloud_id': machine.cloud.id,
        'machine_id': machine.machine_id,
        'event_type': 'job', 'job_id': job_id or uuid.uuid4().hex, 'job': job,
    }
    log_event(action='telegraf_deployment_started', **_log)

    try:
        shell = mist.api.shell.Shell(machine.ctl.get_host())
        key, user = shell.autoconfigure(machine.owner, machine.cloud.id,
                                        machine.machine_id)
    except Exception as err:
        log.error('Error during Telegraf installation: %r', err)
        stdout = ''
    else:
        exit_code, stdout = shell.command(fetch(unix_install(machine)))
        shell.disconnect()  # Close the SSH connection.

        err = exit_code or ''
        stdout = stdout.replace('\r\n', '\n').replace('\r', '\n')
        _log.update({'key_id': key, 'ssh_user': user, 'exit_code': exit_code,
                     'stdout': stdout.encode('utf-8', 'ignore')})

    # Update Machine's InstallationStatus.
    if err:
        machine.monitoring.installation_status.state = 'failed'
    else:
        machine.monitoring.installation_status.state = 'succeeded'
    machine.monitoring.installation_status.finished_at = time.time()
    machine.monitoring.installation_status.stdout = stdout
    machine.monitoring.installation_status.error_msg = str(err)
    machine.save()

    # Deploy custom scripts for metrics' collection.
    if not err and plugins:
        failed = []
        # FIXME Imported here due to circular dependency issues.
        from mist.api.scripts.models import Script
        for script_id in plugins:
            try:
                s = Script.objects.get(owner=machine.owner, id=script_id,
                                       deleted=None)
                ret = s.ctl.deploy_and_assoc_python_plugin_from_script(machine)
            except Exception as exc:
                failed.append(script_id)
                log_event(action='deploy_telegraf_script', script_id=script_id,
                          error=str(exc), **_log)
            else:
                log_event(action='deploy_telegraf_script', script_id=script_id,
                          metrics=ret['metrics'], stdout=ret['stdout'], **_log)
        if not err and failed:
            err = 'Deployment of scripts with IDs %s failed' % ','.join(failed)

    # Log deployment's outcome.
    log_event(action='telegraf_deployment_finished', error=str(err), **_log)

    # Trigger UI update.
    trigger_session_update(machine.owner, ['monitoring'])


@app.task(soft_time_limit=480, time_limit=600)
def uninstall_telegraf(machine_id, job=None, job_id=None):
    """Undeploy Telegraf."""
    machine = Machine.objects.get(id=machine_id)
    error = None

    _log = {
        'owner_id': machine.owner.id,
        'cloud_id': machine.cloud.id,
        'machine_id': machine.machine_id,
        'event_type': 'job', 'job_id': job_id or uuid.uuid4().hex, 'job': job,
    }
    log_event(action='telegraf_undeployment_started', **_log)

    try:
        shell = mist.api.shell.Shell(machine.ctl.get_host())
        key, user = shell.autoconfigure(machine.owner, machine.cloud.id,
                                        machine.machine_id)
        exit_code, stdout = shell.command(fetch(unix_uninstall()))
        stdout = stdout.replace('\r\n', '\n').replace('\r', '\n')
    except Exception as err:
        log.error('Error during Telegraf undeployment: %r', err)
        error = err
    else:
        error = exit_code or None
        _log.update({'key_id': key, 'ssh_user': user, 'exit_code': exit_code,
                     'stdout': stdout.encode('utf-8', 'ignore')})
    finally:
        # Close the SSH connection.
        shell.disconnect()

        # Update Machine's monitoring status.
        machine.monitoring.hasmonitoring = False
        machine.save()

        # Log undeployment's outcome.
        log_event(action='telegraf_undeployment_finished', error=error, **_log)

        # Trigger UI update.
        trigger_session_update(machine.owner, ['monitoring'])


@app.task
def reset_traefik_config():
    try:
        _get_config()
    except Exception as exc:
        log.error(exc)
        reset_config()
