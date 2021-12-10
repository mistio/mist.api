import uuid
import time
import logging
import datetime

from mist.api.dramatiq_app import dramatiq

import mist.api.shell

from mist.api.helpers import trigger_session_update
from mist.api.logs.methods import log_event

from mist.api.machines.models import Machine

from mist.api.monitoring.commands import unix_install, unix_uninstall, fetch
from mist.api.monitoring.commands import check_sudo
from mist.api.monitoring.traefik import reset_config, _get_config


log = logging.getLogger(__name__)


__all__ = [
    'install_telegraf',
    'uninstall_telegraf',
    'reset_traefik_config',
]


@dramatiq.actor(queue_name='dramatiq_scripts',
                time_limit=600_000,
                max_retries=1)
def install_telegraf(machine_id, job=None, job_id=None, plugins=None):
    """Deploy Telegraf over SSH."""
    machine = Machine.objects.get(id=machine_id)
    machine.monitoring.installation_status.state = 'installing'
    machine.save()

    trigger_session_update(machine.owner, ['monitoring'])

    _log = {
        'owner_id': machine.owner.id,
        'cloud_id': machine.cloud.id,
        'machine_id': machine.id,
        'event_type': 'job', 'job_id': job_id or uuid.uuid4().hex, 'job': job,
    }
    log_event(action='telegraf_deployment_started', **_log)

    error = None
    try:
        shell = mist.api.shell.Shell(machine.ctl.get_host())
        key, user = shell.autoconfigure(machine.owner, machine.cloud.id,
                                        machine.id)
    except Exception as err:
        log.error('Error during Telegraf installation: %r', err)
        stdout = ''
        error = err
    else:
        exit_code, stdout = shell.command(
            check_sudo(fetch(unix_install(machine))))
        shell.disconnect()  # Close the SSH connection.

        error = exit_code or ''
        stdout = stdout.replace('\r\n', '\n').replace('\r', '\n')
        _log.update({'key_id': key, 'ssh_user': user, 'exit_code': exit_code,
                     'stdout': stdout.encode('utf-8', 'ignore')})

    # Update Machine's InstallationStatus.
    if error:
        machine.monitoring.installation_status.state = 'failed'
    else:
        machine.monitoring.installation_status.state = 'succeeded'
    machine.monitoring.installation_status.finished_at = time.time()
    machine.monitoring.installation_status.stdout = stdout
    machine.monitoring.installation_status.error_msg = str(error)
    machine.save()

    # Deploy custom scripts for metrics' collection.
    if not error and plugins:
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
        if not error and failed:
            error = 'Deployment of scripts with IDs %s failed' % ','.join(
                failed)

    # Log deployment's outcome.
    log_event(action='telegraf_deployment_finished', error=str(error), **_log)

    # Trigger UI update.
    trigger_session_update(machine.owner, ['monitoring'])


@dramatiq.actor(queue_name='dramatiq_scripts',
                time_limit=600_000,
                max_retries=1)
def uninstall_telegraf(machine_id, job=None, job_id=None):
    """Undeploy Telegraf."""
    machine = Machine.objects.get(id=machine_id)
    error = None

    _log = {
        'owner_id': machine.owner.id,
        'cloud_id': machine.cloud.id,
        'machine_id': machine.id,
        'event_type': 'job', 'job_id': job_id or uuid.uuid4().hex, 'job': job,
    }
    log_event(action='telegraf_undeployment_started', **_log)

    try:
        shell = mist.api.shell.Shell(machine.ctl.get_host())
        key, user = shell.autoconfigure(machine.owner, machine.cloud.id,
                                        machine.id)
        exit_code, stdout = shell.command(
            check_sudo(fetch(unix_uninstall())))
        stdout = stdout.replace('\r\n', '\n').replace('\r', '\n')
    except Exception as err:
        log.error('Error during Telegraf undeployment: %r', err)
        error = repr(err)
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


@dramatiq.actor(time_limit=60_000, max_retries=1)
def reset_traefik_config():
    try:
        _get_config()
    except Exception as exc:
        log.error(exc)
        reset_config()


@dramatiq.actor(time_limit=60_000, max_retries=1)
def set_activated_at():
    from mist.api.monitoring.methods import get_stats, disable_monitoring
    machines = Machine.objects(
        monitoring__hasmonitoring=True,
        monitoring__installation_status__activated_at=None,
        missing_since=None
    )
    log.warn("Found %d monitored machines that remain unactivated" %
             len(machines))
    for machine in machines:
        stats = get_stats(machine, start="-2min", metering=False)
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
        started_at = datetime.datetime.fromtimestamp(
            machine.monitoring.installation_status.started_at)
        if started_at < cutoff and \
                not stats:
            disable_monitoring(machine.org, machine.cloud.id, machine.id)
