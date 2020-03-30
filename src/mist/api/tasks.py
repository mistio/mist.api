import os
import re
import uuid
import logging
import datetime
import mongoengine as me

from time import time

import paramiko

from libcloud.compute.types import NodeState
from libcloud.container.base import Container

from celery.exceptions import SoftTimeLimitExceeded

from paramiko.ssh_exception import SSHException

from mist.api.exceptions import MistError
from mist.api.exceptions import ServiceUnavailableError
from mist.api.shell import Shell

from mist.api.users.models import Owner, Organization
from mist.api.clouds.models import Cloud, DockerCloud, CloudLocation, CloudSize
from mist.api.networks.models import Network
from mist.api.dns.models import Zone
from mist.api.volumes.models import Volume
from mist.api.machines.models import Machine
from mist.api.images.models import CloudImage
from mist.api.scripts.models import Script
from mist.api.schedules.models import Schedule
from mist.api.dns.models import RECORDS

from mist.api.rules.models import NoDataRule

from mist.api.poller.models import PollingSchedule
from mist.api.poller.models import ListMachinesPollingSchedule
from mist.api.poller.models import ListNetworksPollingSchedule
from mist.api.poller.models import ListZonesPollingSchedule
from mist.api.poller.models import ListVolumesPollingSchedule
from mist.api.poller.models import FindCoresMachinePollingSchedule
from mist.api.poller.models import PingProbeMachinePollingSchedule
from mist.api.poller.models import SSHProbeMachinePollingSchedule
from mist.api.poller.models import ListLocationsPollingSchedule
from mist.api.poller.models import ListSizesPollingSchedule
from mist.api.poller.models import ListImagesPollingSchedule

from mist.api.helpers import send_email as helper_send_email
from mist.api.helpers import trigger_session_update

from mist.api.auth.methods import AuthContext

from mist.api.logs.methods import log_event

from mist.api import config

from mist.api.celery_app import app


logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)


@app.task
def ssh_command(owner_id, cloud_id, machine_id, host, command,
                key_id=None, username=None, password=None, port=22):

    owner = Owner.objects.get(id=owner_id)
    shell = Shell(host)
    key_id, ssh_user = shell.autoconfigure(owner, cloud_id, machine_id,
                                           key_id, username, password, port)
    retval, output = shell.command(command)
    shell.disconnect()
    if retval:
        from mist.api.methods import notify_user
        notify_user(owner, "Async command failed for machine %s (%s)" %
                    (machine_id, host), output)


@app.task(bind=True, default_retry_delay=3 * 60)
def post_deploy_steps(self, owner_id, cloud_id, machine_id, monitoring,
                      key_id=None, username=None, password=None, port=22,
                      script_id='', script_params='', job_id=None, job=None,
                      hostname='', plugins=None, script='',
                      post_script_id='', post_script_params='', schedule={}):
    # TODO: break into subtasks
    from mist.api.methods import connect_provider, probe_ssh_only
    from mist.api.methods import notify_user, notify_admin
    from mist.api.keys.models import Key
    from mist.api.monitoring.methods import enable_monitoring

    job_id = job_id or uuid.uuid4().hex
    owner = Owner.objects.get(id=owner_id)

    def tmp_log(msg, *args):
        log.error('Post deploy: %s' % msg, *args)
    tmp_log('Entering post deploy steps for %s %s %s',
            owner.id, cloud_id, machine_id)
    try:
        # find the node we're looking for and get its hostname
        node = None
        try:
            cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
            conn = connect_provider(cloud)

            if isinstance(cloud, DockerCloud):
                nodes = conn.list_containers()
            else:
                nodes = conn.list_nodes()  # TODO: use cache
            for n in nodes:
                if n.id == machine_id:
                    node = n
                    break
            msg = "Cloud:\n  Name: %s\n  Id: %s\n" % (cloud.title, cloud_id)
            msg += "Machine:\n  Name: %s\n  Id: %s\n" % (node.name, node.id)
            tmp_log('Machine found, proceeding to post deploy steps\n%s' % msg)
        except:
            raise self.retry(exc=Exception(), countdown=10, max_retries=10)

        if node and isinstance(node, Container):
            node = cloud.ctl.compute.inspect_node(node)

        if node:
            # filter out IPv6 addresses
            ips = [ip for ip in node.public_ips + node.private_ips
                   if ':' not in ip]
            if not ips:
                raise self.retry(exc=Exception(), countdown=60, max_retries=20)
            host = ips[0]
        else:
            tmp_log('ip not found, retrying')
            raise self.retry(exc=Exception(), countdown=60, max_retries=20)

        if node.state != NodeState.RUNNING:
            tmp_log('not running state')
            raise self.retry(exc=Exception(), countdown=120, max_retries=30)

        machine = Machine.objects.get(cloud=cloud, machine_id=machine_id,
                                      state__ne='terminated')

        log_dict = {
            'owner_id': owner.id,
            'event_type': 'job',
            'cloud_id': cloud_id,
            'machine_id': machine.id,
            'external_id': machine_id,
            'job_id': job_id,
            'job': job,
            'host': host,
            'key_id': key_id,
        }
        if schedule and schedule.get('name'):  # ugly hack to prevent dupes
            try:
                name = (schedule.get('action') + '-' + schedule.pop('name') +
                        '-' + machine_id[:4])

                auth_context = AuthContext.deserialize(
                    schedule.pop('auth_context'))
                tmp_log('Add scheduler entry %s', name)
                schedule['conditions'] = [{
                    'type': 'machines',
                    'ids': [machine.id]
                }]
                schedule_info = Schedule.add(auth_context, name, **schedule)
                tmp_log("A new scheduler was added")
                log_event(action='Add scheduler entry',
                          scheduler=schedule_info.as_dict(), **log_dict)
            except Exception as e:
                print(repr(e))
                error = repr(e)
                notify_user(owner, "add scheduler entry failed for "
                                   "machine %s" % machine_id, repr(e),
                            error=error)
                log_event(action='Add scheduler entry failed',
                          error=error, **log_dict)

        try:
            if hostname:
                try:
                    kwargs = {}
                    kwargs['name'] = hostname
                    kwargs['type'] = 'A'
                    kwargs['data'] = host
                    kwargs['ttl'] = 3600

                    dns_cls = RECORDS[kwargs['type']]
                    dns_cls.add(owner=owner, **kwargs)
                    log_event(action='Create_A_record', hostname=hostname,
                              **log_dict)
                except Exception as exc:
                    log_event(action='Create_A_record', hostname=hostname,
                              error=str(exc), **log_dict)

            from mist.api.shell import Shell
            shell = Shell(host)
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
                        owner, cloud_id, node.id, predeployed_key_id, username,
                        password, port
                    )
                    retval, output = shell.command(
                        'echo %s >> ~/.ssh/authorized_keys' % Key.objects.get(
                            id=key_id).public)
                    if retval > 0:
                        notify_admin('Deploy user key failed for machine %s'
                                     % node.name)
                command = post_deploy_step.get('script', '').replace(
                    '${node.name}', node.name)
                if command and key_id:
                    tmp_log('Executing cloud post deploy cmd: %s' % command)
                    shell.autoconfigure(
                        owner, cloud_id, node.id, key_id, username, password,
                        port
                    )
                    retval, output = shell.command(command)
                    if retval > 0:
                        notify_admin('Cloud post deploy command `%s` failed '
                                     'for machine %s' % (command, node.name))

            if key_id:
                # connect with ssh even if no command, to create association
                # to be able to enable monitoring
                tmp_log('attempting to connect to shell')
                key_id, ssh_user = shell.autoconfigure(
                    owner, cloud_id, machine.id, key_id, username, password,
                    port
                )
                tmp_log('connected to shell')
                result = probe_ssh_only(owner, cloud_id, machine.id, host=None,
                                        key_id=key_id, ssh_user=ssh_user,
                                        shell=shell)
                log_dict = {
                    'owner_id': owner.id,
                    'event_type': 'job',
                    'cloud_id': cloud_id,
                    'machine_id': machine.id,
                    'external_id': machine_id,
                    'job_id': job_id,
                    'job': job,
                    'host': host,
                    'key_id': key_id,
                    'ssh_user': ssh_user,
                }
                log_event(action='probe', result=result, **log_dict)

            error = False
            if script_id:
                tmp_log('will run script_id %s', script_id)
                ret = run_script.run(
                    owner, script_id, machine.id,
                    params=script_params, host=host, job_id=job_id
                )
                error = ret['error']
                tmp_log('executed script_id %s', script_id)
            elif script:
                tmp_log('will run script')
                log_event(action='deployment_script_started', command=script,
                          **log_dict)
                start_time = time()
                retval, output = shell.command(script)
                tmp_log('executed script %s', script)
                execution_time = time() - start_time
                output = output.decode('utf-8', 'ignore')
                title = "Deployment script %s" % ('failed' if retval
                                                  else 'succeeded')
                error = retval > 0
                notify_user(owner, title,
                            cloud_id=cloud_id,
                            machine_id=machine_id,
                            machine_name=node.name,
                            command=script,
                            output=output,
                            duration=execution_time,
                            retval=retval,
                            error=retval > 0)
                log_event(action='deployment_script_finished',
                          error=retval > 0,
                          return_value=retval,
                          command=script,
                          stdout=output,
                          **log_dict)

            shell.disconnect()

            if monitoring:
                try:
                    enable_monitoring(
                        owner, cloud_id, node.id,
                        no_ssh=False, dry=False, job_id=job_id,
                        plugins=plugins, deploy_async=False,
                    )
                except Exception as e:
                    print(repr(e))
                    error = True
                    notify_user(
                        owner,
                        "Enable monitoring failed for machine %s" % machine_id,
                        repr(e)
                    )
                    notify_admin('Enable monitoring on creation failed for '
                                 'user %s machine %s: %r'
                                 % (str(owner), machine_id, e))
                    log_event(action='enable_monitoring_failed', error=repr(e),
                              **log_dict)

            if post_script_id:
                tmp_log('will run post_script_id %s', post_script_id)
                ret = run_script.run(
                    owner, post_script_id, machine.id,
                    params=post_script_params, host=host, job_id=job_id,
                    action_prefix='post_',
                )
                error = ret['error']
                tmp_log('executed post_script_id %s', post_script_id)

            log_event(action='post_deploy_finished', error=error, **log_dict)

        except (ServiceUnavailableError, SSHException) as exc:
            tmp_log(repr(exc))
            raise self.retry(exc=exc, countdown=60, max_retries=15)
    except Exception as exc:
        tmp_log(repr(exc))
        if str(exc).startswith('Retry'):
            raise
        notify_admin("Deployment script failed for machine %s in cloud %s by "
                     "user %s" % (machine_id, cloud_id, str(owner)), repr(exc))
        log_event(
            owner.id,
            event_type='job',
            action='post_deploy_finished',
            cloud_id=cloud_id,
            machine_id=machine_id,
            enable_monitoring=bool(monitoring),
            command=script,
            error="Couldn't connect to run post deploy steps.",
            job_id=job_id,
            job=job
        )


@app.task(bind=True, default_retry_delay=2 * 60)
def openstack_post_create_steps(self, owner_id, cloud_id, machine_id,
                                monitoring, key_id, username, password,
                                public_key, script='',
                                script_id='', script_params='', job_id=None,
                                job=None, hostname='', plugins=None,
                                post_script_id='', post_script_params='',
                                networks=[], schedule={}):
    from mist.api.methods import connect_provider
    owner = Owner.objects.get(id=owner_id)

    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        conn = connect_provider(cloud)
        nodes = conn.list_nodes()
        node = None

        for n in nodes:
            if n.id == machine_id:
                node = n
                break

        if node and node.state == 0 and len(node.public_ips):
            post_deploy_steps.delay(
                owner.id, cloud_id, machine_id, monitoring, key_id,
                script=script, script_id=script_id,
                script_params=script_params, job_id=job_id, job=job,
                hostname=hostname, plugins=plugins,
                post_script_id=post_script_id,
                post_script_params=post_script_params, schedule=schedule,
            )
        else:
            try:
                conn = connect_provider(cloud)
                floating_ips = conn.ex_list_floating_ips()

                # From the already created floating ips try to find one
                # that is not associated to a node
                unassociated_floating_ip = None
                for ip in floating_ips:
                    if ip.status == "DOWN":
                        unassociated_floating_ip = ip
                        break

                # Find the ports which are associated to the machine
                # (e.g. the ports of the private ips)
                # and use one to associate a floating ip
                ports = conn.ex_list_ports()
                machine_port_id = None
                for port in ports:
                    if port.extra.get('device_id') == node.id:
                        machine_port_id = port.id
                        break

                if unassociated_floating_ip:
                    log.info("Associating floating "
                             "ip with machine: %s" % node.id)
                    conn.ex_associate_floating_ip_to_node(
                        unassociated_floating_ip.id, machine_port_id)
                else:
                    # Find the external network
                    log.info("Create and associating floating ip with "
                             "machine: %s" % node.id)
                    ext_net_id = networks['public'][0]['network_id']
                    conn.ex_create_floating_ip(ext_net_id, machine_port_id)

                post_deploy_steps.delay(
                    owner.id, cloud_id, machine_id, monitoring, key_id,
                    script=script,
                    script_id=script_id, script_params=script_params,
                    job_id=job_id, job=job, hostname=hostname, plugins=plugins,
                    post_script_id=post_script_id,
                    post_script_params=post_script_params,
                )

            except:
                raise self.retry(exc=Exception(), max_retries=20)
    except Exception as exc:
        if str(exc).startswith('Retry'):
            raise


@app.task(bind=True, default_retry_delay=2 * 60)
def azure_post_create_steps(self, owner_id, cloud_id, machine_id, monitoring,
                            key_id, username, password, public_key, script='',
                            script_id='', script_params='', job_id=None,
                            job=None, hostname='', plugins=None,
                            post_script_id='', post_script_params='',
                            schedule={}):
    from mist.api.methods import connect_provider

    owner = Owner.objects.get(id=owner_id)
    try:
        # find the node we're looking for and get its hostname
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        conn = connect_provider(cloud)
        nodes = conn.list_nodes()
        node = None
        for n in nodes:
            if n.id == machine_id:
                node = n
                break
        if node and node.state == NodeState.RUNNING and len(node.public_ips):
            # filter out IPv6 addresses
            ips = [ip for ip in node.public_ips if ':' not in ip]
            host = ips[0]
        else:
            raise self.retry(exc=Exception(), max_retries=20)

        try:
            # login with user, password. Deploy the public key, enable sudo
            # access for username, disable password authentication
            # and reload ssh.
            # After this is done, call post_deploy_steps if deploy script
            # or monitoring is provided
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password,
                        timeout=None, allow_agent=False, look_for_keys=False)

            ssh.exec_command('mkdir -p ~/.ssh && '
                             'echo "%s" >> ~/.ssh/authorized_keys && '
                             'chmod -R 700 ~/.ssh/' % public_key)

            chan = ssh.get_transport().open_session()
            chan.get_pty()
            chan.exec_command(
                'sudo su -c \'echo "%s ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers\' ' %  # noqa
                username)
            chan.send('%s\n' % password)

            check_sudo_command = 'sudo su -c \'whoami\''

            chan = ssh.get_transport().open_session()
            chan.get_pty()
            chan.exec_command(check_sudo_command)
            output = chan.recv(1024)

            if not output.startswith('root'):
                raise
            cmd = 'sudo su -c \'sed -i "s|[#]*PasswordAuthentication yes|PasswordAuthentication no|g" /etc/ssh/sshd_config &&  /etc/init.d/ssh reload; service ssh reload\' '  # noqa
            ssh.exec_command(cmd)

            ssh.close()

            post_deploy_steps.delay(
                owner.id, cloud_id, machine_id, monitoring, key_id,
                script=script,
                script_id=script_id, script_params=script_params,
                job_id=job_id, job=job, hostname=hostname, plugins=plugins,
                post_script_id=post_script_id,
                post_script_params=post_script_params, schedule=schedule,
            )

        except Exception as exc:
            raise self.retry(exc=exc, countdown=10, max_retries=15)
    except Exception as exc:
        if str(exc).startswith('Retry'):
            raise


@app.task(bind=True, default_retry_delay=2 * 60)
def rackspace_first_gen_post_create_steps(
        self, owner_id, cloud_id, machine_id, monitoring, key_id, password,
        public_key, username='root', script='', script_id='', script_params='',
        job_id=None, job=None, hostname='', plugins=None, post_script_id='',
        post_script_params='', schedule={}):
    from mist.api.methods import connect_provider

    owner = Owner.objects.get(id=owner_id)
    try:
        # find the node we're looking for and get its hostname
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        conn = connect_provider(cloud)
        nodes = conn.list_nodes()
        node = None
        for n in nodes:
            if n.id == machine_id:
                node = n
                break

        if node and node.state == 0 and len(node.public_ips):
            # filter out IPv6 addresses
            ips = [ip for ip in node.public_ips if ':' not in ip]
            host = ips[0]
        else:
            raise self.retry(exc=Exception(), max_retries=20)

        try:
            # login with user, password and deploy the ssh public key.
            # Disable password authentication and reload ssh.
            # After this is done, call post_deploy_steps
            # if deploy script or monitoring
            # is provided
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password,
                        timeout=None, allow_agent=False, look_for_keys=False)

            ssh.exec_command('mkdir -p ~/.ssh && '
                             'echo "%s" >> ~/.ssh/authorized_keys && '
                             'chmod -R 700 ~/.ssh/' % public_key)

            cmd = 'sudo su -c \'sed -i "s|[#]*PasswordAuthentication yes|PasswordAuthentication no|g" /etc/ssh/sshd_config &&  /etc/init.d/ssh reload; service ssh reload\' '  # noqa
            ssh.exec_command(cmd)

            ssh.close()

            post_deploy_steps.delay(
                owner.id, cloud_id, machine_id, monitoring, key_id,
                script=script,
                script_id=script_id, script_params=script_params,
                job_id=job_id, job=job, hostname=hostname, plugins=plugins,
                post_script_id=post_script_id,
                post_script_params=post_script_params, schedule=schedule,
            )

        except Exception as exc:
            raise self.retry(exc=exc, countdown=10, max_retries=15)
    except Exception as exc:
        if str(exc).startswith('Retry'):
            raise


@app.task
def create_machine_async(
    auth_context_serialized, cloud_id, key_id, machine_name, location_id,
    image_id, size, image_extra, disk,
    image_name, size_name, location_name, ips, monitoring,
    storage_account, machine_password, resource_group, storage_account_type,
    networks, subnetwork, docker_env, docker_command, script='',
    script_id='', script_params='',
    post_script_id='', post_script_params='',
    quantity=1, persist=False, job_id=None, job=None,
    docker_port_bindings={}, docker_exposed_ports={},
    azure_port_bindings='', hostname='', plugins=None,
    disk_size=None, disk_path=None, cloud_init='', subnet_id='',
    associate_floating_ip=False,
    associate_floating_ip_subnet=None, project_id=None,
    tags=None, schedule={}, bare_metal=False, hourly=True,
    softlayer_backend_vlan_id=None, machine_username='',
    folder=None, datastore=None,
    ephemeral=False, lxd_image_source=None,
    volumes=[], ip_addresses=[], expiration={}, sec_group='', vnfs=[],
    description=''
):
    from multiprocessing.dummy import Pool as ThreadPool
    from mist.api.machines.methods import create_machine
    from mist.api.exceptions import MachineCreationError
    log.warn('MULTICREATE ASYNC %d' % quantity)

    # Re-construct AuthContext.
    auth_context = AuthContext.deserialize(auth_context_serialized)

    job_id = job_id or uuid.uuid4().hex

    names = []
    if quantity == 1:
        names = [machine_name]
    else:
        names = []
        for i in range(1, quantity + 1):
            names.append('%s-%d' % (machine_name, i))

    log_event(auth_context.owner.id, 'job', 'async_machine_creation_started',
              user_id=auth_context.user.id, job_id=job_id, job=job,
              cloud_id=cloud_id, script=script, script_id=script_id,
              script_params=script_params, monitoring=monitoring,
              persist=persist, quantity=quantity, key_id=key_id,
              machine_names=names, volumes=volumes)

    THREAD_COUNT = 5
    pool = ThreadPool(THREAD_COUNT)
    specs = []
    for name in names:
        specs.append((
            (auth_context, cloud_id, key_id, name, location_id, image_id,
             size, image_extra, disk, image_name, size_name,
             location_name, ips, monitoring, storage_account,
             machine_password, resource_group, storage_account_type, networks,
             subnetwork, docker_env, docker_command, 22, script, script_id,
             script_params, job_id, job),
            {'hostname': hostname, 'plugins': plugins,
             'post_script_id': post_script_id,
             'post_script_params': post_script_params,
             'azure_port_bindings': azure_port_bindings,
             'associate_floating_ip': associate_floating_ip,
             'cloud_init': cloud_init,
             'disk_size': disk_size,
             'disk_path': disk_path,
             'project_id': project_id,
             'tags': tags,
             'schedule': schedule,
             'softlayer_backend_vlan_id': softlayer_backend_vlan_id,
             'bare_metal': bare_metal,
             'hourly': hourly,
             'machine_username': machine_username,
             'volumes': volumes,
             'ip_addresses': ip_addresses,
             'expiration': expiration,
             'ephemeral': ephemeral,
             'lxd_image_source': lxd_image_source,
             'sec_group': sec_group,
             'vnfs': vnfs,
             'description': description
             }
        ))

    def create_machine_wrapper(args_kwargs):
        args, kwargs = args_kwargs
        error = False
        node = {}
        try:
            node = create_machine(*args, **kwargs)
        except MachineCreationError as exc:
            error = str(exc)
        except Exception as exc:
            error = repr(exc)
        finally:
            name = args[3]
            log_event(
                auth_context.owner.id, 'job', 'machine_creation_finished',
                job=job, job_id=job_id, cloud_id=cloud_id, machine_name=name,
                error=error, external_id=node.get('id', ''),
                user_id=auth_context.user.id
            )

    pool.map(create_machine_wrapper, specs)
    pool.close()
    pool.join()


@app.task(bind=True, default_retry_delay=5, max_retries=3)
def send_email(self, subject, body, recipients, sender=None, bcc=None,
               html_body=None):
    if not helper_send_email(subject, body, recipients,
                             sender=sender, bcc=bcc, attempts=1,
                             html_body=html_body):
        raise self.retry()
    return True


@app.task
def group_machines_actions(owner_id, action, name, machines_uuids):
    """
    Accepts a list of lists in form  cloud_id,machine_id and pass them
    to run_machine_action like a group

    :param owner_id:
    :param action:
    :param name:
    :param machines_uuids:
    :return: log_dict
    """

    schedule = Schedule.objects.get(owner=owner_id, name=name, deleted=None)

    log_dict = {
        'schedule_id': schedule.id,
        'schedule_name': schedule.name,
        'description': schedule.description or '',
        'schedule_type': str(schedule.schedule_type or ''),
        'owner_id': owner_id,
        'machines_match': schedule.get_ids(),
        'machine_action': action,
        'expires': str(schedule.expires or ''),
        'task_enabled': schedule.task_enabled,
        'run_immediately': schedule.run_immediately,
        'event_type': 'job',
        'error': False,
    }
    log_event(action='schedule_started', **log_dict)
    log.info('Schedule action started: %s', log_dict)

    for machine_uuid in machines_uuids:
        found = False
        _action = action
        try:
            machine = Machine.objects.get(id=machine_uuid)
            found = True
        except me.DoesNotExist:
            log_dict['error'] = "Machine with id %s does not \
                exist." % machine_uuid

        if found:
            if _action in ['destroy'] and config.SAFE_EXPIRATION and \
               machine.expiration == schedule and machine.state != 'stopped':
                from mist.api.machines.methods import machine_safe_expire
                machine_safe_expire(owner_id, machine)
                # change action to be executed now
                _action = 'stop'

            try:
                run_machine_action.s(owner_id, _action, name,
                                     machine_uuid)()
            except Exception as exc:
                log_dict['error'] = log_dict.get('error', '') + str(exc) + '\n'

    log_dict.update({'last_run_at': str(schedule.last_run_at or ''),
                    'total_run_count': schedule.total_run_count or 0,
                     'error': log_dict['error']}
                    )
    log_event(action='schedule_finished', **log_dict)
    if log_dict['error']:
        log.info('Schedule action failed: %s', log_dict)
    else:
        log.info('Schedule action succeeded: %s', log_dict)
    owner = Owner.objects.get(id=owner_id)
    trigger_session_update(owner, ['schedules'])
    return log_dict


@app.task(soft_time_limit=3600, time_limit=3630)
def run_machine_action(owner_id, action, name, machine_uuid):
    """
    Calls specific action for a machine and log the info
    :param owner_id:
    :param action:
    :param name:
    :param cloud_id:
    :param machine_id:
    :return:
    """

    schedule = Schedule.objects.get(owner=owner_id, name=name, deleted=None)

    log_dict = {
        'owner_id': owner_id,
        'event_type': 'job',
        'machine_uuid': machine_uuid,
        'schedule_id': schedule.id,
    }

    external_id = ''
    cloud_id = ''
    owner = Owner.objects.get(id=owner_id)
    started_at = time()
    try:
        machine = Machine.objects.get(id=machine_uuid, state__ne='terminated')
        cloud_id = machine.cloud.id
        external_id = machine.machine_id
        log_dict.update({'cloud_id': cloud_id,
                         'machine_id': machine_uuid,
                         'external_id': external_id})
    except me.DoesNotExist:
        log_dict['error'] = "Resource with that id does not exist."
        msg = action + ' failed'
        log_event(action=msg, **log_dict)
    except Exception as exc:
        log_dict['error'] = str(exc)
        msg = action + ' failed'
        log_event(action=msg, **log_dict)

    if not log_dict.get('error'):
        if action in ('start', 'stop', 'reboot', 'destroy', 'notify'):
            # call list machines here cause we don't have another way
            # to update machine state if user isn't logged in
            from mist.api.machines.methods import list_machines
            from mist.api.machines.methods import destroy_machine
            # TODO change this to compute.ctl.list_machines
            list_machines(owner, cloud_id)

            if action == 'start':
                log_event(action='Start', **log_dict)
                try:
                    machine.ctl.start()
                except Exception as exc:
                    log_dict['error'] = '%s Machine in %s state' % (
                        exc, machine.state)
                    log_event(action='Start failed', **log_dict)
                else:
                    log_event(action='Start succeeded', **log_dict)
            elif action == 'stop':
                log_event(action='Stop', **log_dict)
                try:
                    machine.ctl.stop()
                except Exception as exc:
                    log_dict['error'] = '%s Machine in %s state' % (
                        exc, machine.state)
                    log_event(action='Stop failed', **log_dict)
                else:
                    log_event(action='Stop succeeded', **log_dict)
            elif action == 'reboot':
                log_event(action='Reboot', **log_dict)
                try:
                    machine.ctl.reboot()
                except Exception as exc:
                    log_dict['error'] = '%s Machine in %s state' % (
                        exc, machine.state)
                    log_event(action='Reboot failed', **log_dict)
                else:
                    log_event(action='Reboot succeeded', **log_dict)
            elif action == 'destroy':
                log_event(action='Destroy', **log_dict)
                try:
                    destroy_machine(owner, cloud_id, external_id)
                except Exception as exc:
                    log_dict['error'] = '%s Machine in %s state' % (
                        exc, machine.state)
                    log_event(action='Destroy failed', **log_dict)
                else:
                    log_event(action='Destroy succeeded', **log_dict)
            elif action == 'notify':
                mails = []
                for _user in [machine.owned_by, machine.created_by]:
                    if _user:
                        mails.append(_user.email)
                for mail in list(set(mails)):
                    if mail == machine.owned_by.email:
                        user = machine.owned_by
                    else:
                        user = machine.created_by
                    subject = config.MACHINE_EXPIRE_NOTIFY_EMAIL_SUBJECT
                    if schedule.schedule_type.type == 'reminder' and \
                       schedule.schedule_type.message:
                        custom_msg = '\n%s\n' % schedule.schedule_type.message
                    else:
                        custom_msg = ''
                    machine_uri = config.CORE_URI + \
                        '/machines/%s' % machine.id
                    main_body = config.MACHINE_EXPIRE_NOTIFY_EMAIL_BODY
                    sch_entry = machine.expiration.schedule_type.entry
                    body = main_body % ((user.first_name + " " +
                                        user.last_name).strip(),
                                        machine.name,
                                        sch_entry,
                                        machine_uri + '/expiration',
                                        custom_msg, config.CORE_URI)
                    log.info('About to send email...')
                    if not helper_send_email(subject, body, user.email):
                        raise ServiceUnavailableError("Could not send "
                                                      "notification email "
                                                      "about machine that "
                                                      "is about to expire.")

    if action != 'notify' and log_dict.get('error'):
        # TODO markos asked this
        log_dict['started_at'] = started_at
        log_dict['finished_at'] = time()
        title = "Execution of '%s' action " % action
        title += "failed" if log_dict.get('error') else "succeeded"
        from mist.api.methods import notify_user
        notify_user(
            owner, title,
            cloud_id=cloud_id,
            machine_id=external_id,
            duration=log_dict['finished_at'] - log_dict['started_at'],
            error=log_dict.get('error'),
        )


@app.task
def group_run_script(owner_id, script_id, name, machines_uuids, params=''):
    """
    Accepts a list of lists in form  cloud_id,machine_id and pass them
    to run_machine_action like a group

    :param owner_id:
    :param script_id:
    :param name
    :param cloud_machines_pairs:
    :return:
    """
    job_id = uuid.uuid4().hex
    schedule = Schedule.objects.get(owner=owner_id, name=name, deleted=None)

    log_dict = {
        'schedule_id': schedule.id,
        'schedule_name': schedule.name,
        'description': schedule.description or '',
        'schedule_type': str(schedule.schedule_type or ''),
        'owner_id': owner_id,
        'machines_match': schedule.get_ids(),
        'script_id': script_id,
        'expires': str(schedule.expires or ''),
        'task_enabled': schedule.task_enabled,
        'run_immediately': schedule.run_immediately,
        'event_type': 'job',
        'error': False,
        'job': 'schedule',
        'job_id': job_id,
    }

    log_event(action='schedule_started', **log_dict)
    log.info('Schedule started: %s', log_dict)

    for machine_uuid in machines_uuids:
        try:
            run_script.s(owner_id, script_id, machine_uuid,
                         params=params,
                         job_id=job_id, job='schedule')()
        except Exception as exc:
            log_dict['error'] = log_dict.get('error', '') + str(exc) + '\n'

    log_dict.update({'last_run_at': str(schedule.last_run_at or ''),
                     'total_run_count': schedule.total_run_count or 0,
                     'error': log_dict['error']}
                    )
    log_event(action='schedule_finished', **log_dict)
    if log_dict['error']:
        log.info('Schedule run_script failed: %s', log_dict)
    else:
        log.info('Schedule run_script succeeded: %s', log_dict)
    owner = Owner.objects.get(id=owner_id)
    trigger_session_update(owner, ['schedules'])
    return log_dict


@app.task(soft_time_limit=3600, time_limit=3630)
def run_script(owner, script_id, machine_uuid, params='', host='',
               key_id='', username='', password='', port=22, job_id='', job='',
               action_prefix='', su=False, env=""):
    import mist.api.shell
    from mist.api.methods import notify_admin, notify_user
    from mist.api.machines.methods import list_machines

    if not isinstance(owner, Owner):
        owner = Owner.objects.get(id=owner)

    ret = {
        'owner_id': owner.id,
        'job_id': job_id or uuid.uuid4().hex,
        'job': job,
        'script_id': script_id,
        # 'cloud_id': cloud_id,
        'machine_id': machine_uuid,
        'params': params,
        'env': env,
        'su': su,
        'host': host,
        'key_id': key_id,
        'ssh_user': username,
        'port': port,
        'command': '',
        'stdout': '',
        'exit_code': '',
        'wrapper_stdout': '',
        'extra_output': '',
        'error': False,
    }
    started_at = time()
    machine_name = ''
    cloud_id = ''

    try:
        machine = Machine.objects.get(id=machine_uuid, state__ne='terminated')
        cloud_id = machine.cloud.id
        external_id = machine.machine_id
        ret.update({'cloud_id': cloud_id, 'external_id': external_id})
        # cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
        script = Script.objects.get(owner=owner, id=script_id, deleted=None)

        if not host:
            # FIXME machine.cloud.ctl.compute.list_machines()
            for machine in list_machines(owner, cloud_id):
                if machine['machine_id'] == external_id:
                    ips = [ip for ip in machine['public_ips'] if ':' not in ip]
                    # get private IPs if no public IP is available
                    if not ips:
                        ips = [ip for ip in machine['private_ips']
                               if ':' not in ip]
                    if ips:
                        host = ips[0]
                        ret['host'] = host
                    machine_name = machine['name']
                    break
        if not host:
            raise MistError("No host provided and none could be discovered.")
        shell = mist.api.shell.Shell(host)
        ret['key_id'], ret['ssh_user'] = shell.autoconfigure(
            owner, cloud_id, machine['id'], username, password, port
        )
        # FIXME wrap here script.run_script
        path, params, wparams = script.ctl.run_script(shell,
                                                      params=params,
                                                      job_id=ret.get('job_id'))

        with open(os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)
            )))),
            'run_script', 'run.py'
        )) as fobj:
            wscript = fobj.read()

        # check whether python exists

        exit_code, wstdout = shell.command("command -v python")

        if exit_code > 0:
            command = "chmod +x %s && %s %s" % (path, path, params)
        else:
            command = "python - %s << EOF\n%s\nEOF\n" % (wparams, wscript)
        if su:
            command = 'sudo ' + command
        ret['command'] = command
    except Exception as exc:
        ret['error'] = str(exc)
    log_event(event_type='job', action=action_prefix + 'script_started', **ret)
    log.info('Script started: %s', ret)
    if not ret['error']:
        try:
            exit_code, wstdout = shell.command(command)
            shell.disconnect()
            wstdout = wstdout.replace('\r\n', '\n').replace('\r', '\n')
            ret['wrapper_stdout'] = wstdout
            ret['exit_code'] = exit_code
            ret['stdout'] = wstdout
            try:
                parts = re.findall(
                    r'-----part-([^-]*)-([^-]*)-----\n(.*?)-----part-end-\2-----\n',  # noqa
                    wstdout, re.DOTALL)
                if parts:
                    randid = parts[0][1]
                    for part in parts:
                        if part[1] != randid:
                            raise Exception('Different rand ids')
                    for part in parts:
                        if part[0] == 'script':
                            ret['stdout'] = part[2]
                        elif part[0] == 'outfile':
                            ret['extra_output'] = part[2]
            except Exception as exc:
                pass
            if exit_code > 0:
                ret['error'] = 'Script exited with return code %s' % exit_code
        except SoftTimeLimitExceeded:
            ret['error'] = 'Script execution time limit exceeded'
        except Exception as exc:
            ret['error'] = str(exc)
    log_event(event_type='job', action=action_prefix + 'script_finished',
              **ret)
    if ret['error']:
        log.info('Script failed: %s', ret)
    else:
        log.info('Script succeeded: %s', ret)
    ret['started_at'] = started_at
    ret['finished_at'] = time()
    title = "Execution of '%s' script " % script.name
    title += "failed" if ret['error'] else "succeeded"
    if ret['error']:
        notify_user(
            owner, title,
            cloud_id=cloud_id,
            machine_id=external_id,
            machine_name=machine_name,
            output=ret['stdout'],
            duration=ret['finished_at'] - ret['started_at'],
            retval=ret['exit_code'],
            error=ret['error'],
        )
    if ret['error']:
        title += " for user %s" % str(owner)
        notify_admin(
            title, "%s\n\n%s" % (ret['stdout'], ret['error']), team='dev'
        )
    return ret


@app.task
def update_poller(org_id):
    org = Organization.objects.get(id=org_id)
    update_threshold = datetime.datetime.now() - datetime.timedelta(
        seconds=90)
    if org.poller_updated and org.poller_updated > update_threshold:
        return  # Poller was recently updated
    log.info("Updating poller for %s", org)
    for cloud in Cloud.objects(owner=org, deleted=None, enabled=True):
        log.info("Updating poller for cloud %s", cloud)
        ListMachinesPollingSchedule.add(cloud=cloud, interval=10, ttl=120)
        ListLocationsPollingSchedule.add(cloud=cloud, interval=60 * 60 * 24,
                                         ttl=120)
        ListSizesPollingSchedule.add(cloud=cloud, interval=60 * 60 * 24,
                                     ttl=120)
        ListImagesPollingSchedule.add(cloud=cloud, interval=60 * 60 * 24,
                                      ttl=120)
        if hasattr(cloud.ctl, 'network'):
            ListNetworksPollingSchedule.add(cloud=cloud, interval=60, ttl=120)
        if hasattr(cloud.ctl, 'dns') and cloud.dns_enabled:
            ListZonesPollingSchedule.add(cloud=cloud, interval=60, ttl=120)
        if hasattr(cloud.ctl, 'storage'):
            ListVolumesPollingSchedule.add(cloud=cloud, interval=60, ttl=120)
        if config.ACCELERATE_MACHINE_POLLING:
            for machine in cloud.ctl.compute.list_cached_machines():
                if machine.machine_type != 'container':
                    log.info("Updating poller for machine %s", machine)
                    FindCoresMachinePollingSchedule.add(machine=machine,
                                                        interval=600, ttl=360,
                                                        run_immediately=False)
                    PingProbeMachinePollingSchedule.add(machine=machine,
                                                        interval=300, ttl=120)
                    SSHProbeMachinePollingSchedule.add(machine=machine,
                                                       interval=300, ttl=120)
    org.poller_updated = datetime.datetime.now()
    org.save()


@app.task
def gc_schedulers():
    """Delete disabled celerybeat schedules.

    This takes care of:

    1. Removing disabled list_machines polling schedules.
    2. Removing ssh/ping probe schedules, whose machines are missing or
       corresponding clouds have been deleted.
    3. Removing inactive no-data rules. They are added idempotently the
       first time get_stats receives data for a newly monitored machine.

    Note that this task does not run GC on user-defined schedules. The
    UserScheduler has its own mechanism for choosing which documents to
    load.

    """
    for collection in (PollingSchedule, NoDataRule, ):
        for entry in collection.objects():
            try:
                if not entry.enabled:
                    log.warning('Removing %s', entry)
                    entry.delete()
            except me.DoesNotExist:
                entry.delete()
            except Exception as exc:
                log.error(exc)


@app.task
def set_missing_since(cloud_id):
    for Model in (Machine, CloudLocation, CloudSize, CloudImage,
                  Network, Volume, Zone):
        Model.objects(cloud=cloud_id, missing_since=None).update(
            missing_since=datetime.datetime.utcnow()
        )


@app.task
def delete_periodic_tasks(cloud_id):
    from mist.api.concurrency.models import PeriodicTaskInfo
    for section in ['machines', 'volumes', 'networks', 'zones']:
        try:
            key = 'cloud:list_%s:%s' % (section, cloud_id)
            PeriodicTaskInfo.objects.get(key=key).delete()
            log.info('Deleted periodic task: %s' % key)
        except PeriodicTaskInfo.DoesNotExist:
            pass


@app.task
def create_backup():
    """Create mongo backup if s3 creds are set.
    """
    # If MONGO_URI consists of multiple hosts get the last one
    mongo_backup_host = config.MONGO_URI.split('//')[-1].split('/')[0].split(
        ',')[-1]
    # Strip protocol prefix from influx backup uri
    influx_backup_host = config.INFLUX.get('backup', '').replace(
        'http://', '').replace('https://', '')
    if all(value == '' for value in config.BACKUP.get('gpg', {}).values()):
        os.system("mongodump --host %s --gzip --archive | s3cmd --access_key=%s \
        --secret_key=%s put - s3://%s/mongo/%s-%s" % (mongo_backup_host,
                  config.BACKUP['key'], config.BACKUP['secret'],
                  config.BACKUP['bucket'], config.CORE_URI.split('//')[1],
                  datetime.datetime.now().strftime('%Y%m%d%H%M')))
        if influx_backup_host:
            os.system("influxd backup -portable -host %s ./influx-snapshot &&\
            tar cv influx-snapshot | s3cmd --access_key=%s --secret_key=%s \
            put - s3://%s/influx/%s-%s && rm -rf influx-snapshot" % (
                influx_backup_host, config.BACKUP['key'],
                config.BACKUP['secret'], config.BACKUP['bucket'],
                config.CORE_URI.split('//')[1],
                datetime.datetime.now().strftime('%Y%m%d%H%M')))
    elif config.BACKUP['gpg'].get('public'):  # encrypt with gpg if configured
        f = open('pub.key', 'w+')
        f.write(config.BACKUP['gpg']['public'])
        f.close()
        os.system("gpg --import pub.key && mongodump \
        --host %s --gzip --archive | gpg --yes --trust-model always \
        --encrypt --recipient %s | s3cmd --access_key=%s --secret_key=%s put \
        - s3://%s/mongo/%s-%s.gpg" % (
            mongo_backup_host, config.BACKUP['gpg']['recipient'],
            config.BACKUP['key'], config.BACKUP['secret'],
            config.BACKUP['bucket'], config.CORE_URI.split('//')[1],
            datetime.datetime.now().strftime('%Y%m%d%H%M')))
        if influx_backup_host:
            os.system("influxd backup -portable -host %s ./influx-snapshot \
            && tar cv influx-snapshot | gpg --yes --trust-model always \
            --encrypt --recipient %s | s3cmd --access_key=%s --secret_key=%s \
            put - s3://%s/influx/%s-%s.gpg" % (
                influx_backup_host, config.BACKUP['gpg']['recipient'],
                config.BACKUP['key'], config.BACKUP['secret'],
                config.BACKUP['bucket'], config.CORE_URI.split('//')[1],
                datetime.datetime.now().strftime('%Y%m%d%H%M')))


@app.task
def async_session_update(owner, sections=None):
    if sections is None:
        sections = [
            'org', 'user', 'keys', 'clouds', 'stacks',
            'scripts', 'schedules', 'templates', 'monitoring'
        ]
    trigger_session_update(owner, sections)
