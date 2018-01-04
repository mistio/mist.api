import uuid
import logging
from pyramid.response import Response

import mist.api.machines.methods as methods

from mist.api.clouds.models import Cloud
from mist.api.clouds.models import LibvirtCloud
from mist.api.machines.models import Machine
from mist.api.clouds.methods import filter_list_clouds

from mist.api import tasks

from mist.api.auth.methods import auth_context_from_request
from mist.api.helpers import view_config, params_from_request
from mist.api.helpers import trigger_session_update


from mist.api.exceptions import RequiredParameterMissingError
from mist.api.exceptions import BadRequestError, NotFoundError
from mist.api.exceptions import MachineCreationError
from mist.api.exceptions import CloudUnauthorizedError, CloudUnavailableError

from mist.api import config

if config.HAS_CORE:
    from mist.core.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat

try:
    from mist.core.methods import enable_monitoring
    from mist.core.methods import disable_monitoring
except ImportError:
    from mist.api.dummy.methods import enable_monitoring
    from mist.api.dummy.methods import disable_monitoring

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)

OK = Response("OK", 200)


@view_config(route_name='api_v1_machines',
             request_method='GET', renderer='json')
def list_machines(request):
    """
    List machines of all clouds
    Gets machines and their metadata from all clouds
    Check Permissions take place in filter_list_machines
    """
    auth_context = auth_context_from_request(request)
    # to prevent iterate throw every cloud
    auth_context.check_perm("cloud", "read", None)
    clouds = filter_list_clouds(auth_context)
    machines = []
    for cloud in clouds:
        if cloud.get('enabled'):
            try:
                cloud_machines = methods.filter_list_machines(
                    auth_context, cloud.get('id'))
                machines.extend(cloud_machines)
            except (CloudUnavailableError, CloudUnauthorizedError):
                pass
    return machines


@view_config(route_name='api_v1_cloud_machines',
             request_method='GET', renderer='json')
def list_cloud_machines(request):
    """
    List machines on cloud
    Gets machines and their metadata from a cloud
    Check Permissions take place in filter_list_machines
    READ permission required on cloud.
    READ permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    """
    auth_context = auth_context_from_request(request)
    cloud_id = request.matchdict['cloud']
    # SEC get filtered resources based on auth_context
    try:
        cloud = Cloud.objects.get(owner=auth_context.owner,
                                  id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    machines = methods.filter_list_machines(auth_context, cloud_id)

    if cloud.machine_count != len(machines):
        try:
            tasks.update_machine_count.delay(
                auth_context.owner.id, cloud_id, len(machines))
        except Exception as e:
            log.error('Cannot update machine count for user %s: %r' %
                      (auth_context.owner.id, e))

    return machines


@view_config(route_name='api_v1_cloud_machines', request_method='POST',
             renderer='json')
def create_machine(request):
    """
    Create machine(s) on cloud
    Creates one or more machines on the specified cloud. If async is true, a
    jobId will be returned.
    READ permission required on cloud.
    CREATE_RESOURCES permissn required on cloud.
    CREATE permission required on machine.
    RUN permission required on script.
    READ permission required on key.

    ---
    cloud:
      in: path
      required: true
      type: string
    async:
      description: ' Create machines asynchronously, returning a jobId'
      type: boolean
    quantity:
      description: ' The number of machines that will be created, async only'
      type: integer
    azure_port_bindings:
      type: string
    cloud_id:
      description: The Cloud ID
      required: true
      type: string
    disk:
      description: ' Only required by Linode cloud'
      type: string
    docker_command:
      type: string
    docker_env:
      items:
        type: string
      type: array
    docker_exposed_ports:
      type: object
    docker_port_bindings:
      type: object
    hostname:
      type: string
    image_extra:
      description: ' Needed only by Linode cloud'
      type: string
    image:
      description: ' Id of image to be used with the creation'
      required: true
      type: string
    image_name:
      type: string
    ips:
      type: string
    job_id:
      type: string
    key_id:
      description: ' Associate machine with this key_id'
      required: true
      type: string
    location_id:
      description: ' Id of the cloud''s location to create the machine'
      required: true
      type: string
    location_name:
      type: string
    machine_name:
      required: true
      type: string
    monitoring:
      type: string
    networks:
      items:
        type: string
      type: array
    plugins:
      items:
        type: string
      type: array
    post_script_id:
      type: string
    post_script_params:
      type: string
    script:
      type: string
    script_id:
      type: string
    script_params:
      type: string
    size_id:
      description: ' Id of the size of the machine'
      required: true
      type: string
    size_name:
      type: string
    ssh_port:
      type: integer
    softlayer_backend_vlan_id:
      description: 'Specify id of a backend(private) vlan'
      type: integer
    project_id:
      description: ' Needed only by Packet.net cloud'
      type: string
    billing:
      description: ' Needed only by SoftLayer cloud'
      type: string
    bare_metal:
      description: ' Needed only by SoftLayer cloud'
      type: string
    schedule:
      type: dict
    """

    params = params_from_request(request)
    cloud_id = request.matchdict['cloud']
    for key in ('name', 'size'):
        if key not in params:
            raise RequiredParameterMissingError(key)

    key_id = params.get('key')
    machine_name = params['name']
    location_id = params.get('location', None)
    image_id = params.get('image')
    if not image_id:
        raise RequiredParameterMissingError("image")
    # this is used in libvirt
    disk_size = int(params.get('libvirt_disk_size', 4))
    disk_path = params.get('libvirt_disk_path', '')
    size_id = params['size']
    # deploy_script received as unicode, but ScriptDeployment wants str
    script = str(params.get('script', ''))
    # these are required only for Linode/GCE, passing them anyway
    image_extra = params.get('image_extra', None)
    disk = params.get('disk', None)
    image_name = params.get('image_name', None)
    size_name = params.get('size_name', None)
    location_name = params.get('location_name', None)
    ips = params.get('ips', None)
    monitoring = params.get('monitoring', False)
    create_storage_account = params.get('create_storage_account', False)
    new_storage_account = params.get('new_storage_account', '')
    ex_storage_account = params.get('ex_storage_account', '')
    machine_password = params.get('machine_password', '')
    machine_username = params.get('machine_username', '')
    create_resource_group = params.get('create_resource_group', False)
    new_resource_group = params.get('new_resource_group', '')
    ex_resource_group = params.get('ex_resource_group', '')
    create_network = params.get('create_network', False)
    new_network = params.get('new_network', '')
    networks = params.get('networks', [])
    docker_env = params.get('docker_env', [])
    docker_command = params.get('docker_command', None)
    script_id = params.get('script_id', '')
    script_params = params.get('script_params', '')
    post_script_id = params.get('post_script_id', '')
    post_script_params = params.get('post_script_params', '')
    async = params.get('async', False)
    quantity = params.get('quantity', 1)
    persist = params.get('persist', False)
    docker_port_bindings = params.get('docker_port_bindings', {})
    docker_exposed_ports = params.get('docker_exposed_ports', {})
    azure_port_bindings = params.get('azure_port_bindings', '')
    # hostname: if provided it will be attempted to assign a DNS name
    hostname = params.get('hostname', '')
    plugins = params.get('plugins')
    cloud_init = params.get('cloud_init', '')
    associate_floating_ip = params.get('associate_floating_ip', False)
    associate_floating_ip_subnet = params.get('attach_floating_ip_subnet',
                                              None)
    project_id = params.get('project', None)
    bare_metal = params.get('bare_metal', False)
    # bare_metal True creates a hardware server in SoftLayer,
    # whule bare_metal False creates a virtual cloud server
    # hourly True is the default setting for SoftLayer hardware
    # servers, while False means the server has montly pricing
    softlayer_backend_vlan_id = params.get('softlayer_backend_vlan_id', None)
    hourly = params.get('hourly', True)

    job_id = params.get('job_id')
    job_id = params.get('job_id')
    # The `job` variable points to the event that started the job. If a job_id
    # is not provided, then it means that this is the beginning of a new story
    # that starts with a `create_machine` event. If a job_id is provided that
    # means that the current event will be part of already existing, unknown
    # story. TODO: Provide the `job` in the request's params or query it.
    if not job_id:
        job = 'create_machine'
        job_id = uuid.uuid4().hex
    else:
        job = None

    # these are needed for OnApp
    size_ram = params.get('size_ram', 256)
    size_cpu = params.get('size_cpu', 1)
    size_disk_primary = params.get('size_disk_primary', 5)
    size_disk_swap = params.get('size_disk_swap', 1)
    boot = params.get('boot', True)
    build = params.get('build', True)
    cpu_priority = params.get('cpu_priority', 1)
    cpu_sockets = params.get('cpu_sockets', 1)
    cpu_threads = params.get('cpu_threads', 1)
    port_speed = params.get('port_speed', 0)
    hypervisor_group_id = params.get('hypervisor_group_id')

    auth_context = auth_context_from_request(request)

    try:
        Cloud.objects.get(owner=auth_context.owner,
                          id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    # compose schedule as a dict from relative parameters
    if not params.get('schedule_type'):
        schedule = {}
    else:
        if params.get('schedule_type') not in ['crontab',
                                               'interval', 'one_off']:
            raise BadRequestError('schedule type must be one of '
                                  'these (crontab, interval, one_off)]'
                                  )
        if params.get('schedule_entry') == {}:
            raise RequiredParameterMissingError('schedule_entry')

        schedule = {
            'name': params.get('name'),
            'description': params.get('description', ''),
            'action': params.get('action', ''),
            'script_id': params.get('schedule_script_id', ''),
            'schedule_type': params.get('schedule_type'),
            'schedule_entry': params.get('schedule_entry'),
            'expires': params.get('expires', ''),
            'start_after': params.get('start_after', ''),
            'max_run_count': params.get('max_run_count'),
            'task_enabled': bool(params.get('task_enabled', True)),
            'auth_context': auth_context.serialize(),
        }

    auth_context.check_perm("cloud", "read", cloud_id)
    auth_context.check_perm("cloud", "create_resources", cloud_id)
    tags = auth_context.check_perm("machine", "create", None) or {}
    if script_id:
        auth_context.check_perm("script", "run", script_id)
    if key_id:
        auth_context.check_perm("key", "read", key_id)

    # Parse tags.
    try:
        mtags = params.get('tags') or {}
        if not isinstance(mtags, dict):
            if not isinstance(mtags, list):
                raise ValueError()
            if not all((isinstance(t, dict) and len(t) is 1 for t in mtags)):
                raise ValueError()
            mtags = {key: val for item in mtags for key, val in item.items()}
        tags.update(mtags)
    except ValueError:
        raise BadRequestError('Invalid tags format. Expecting either a '
                              'dictionary of tags or a list of single-item '
                              'dictionaries')

    args = (cloud_id, key_id, machine_name,
            location_id, image_id, size_id,
            image_extra, disk, image_name, size_name,
            location_name, ips, monitoring,
            ex_storage_account, machine_password, ex_resource_group, networks,
            docker_env, docker_command)
    kwargs = {'script_id': script_id,
              'script_params': script_params, 'script': script, 'job': job,
              'job_id': job_id, 'docker_port_bindings': docker_port_bindings,
              'docker_exposed_ports': docker_exposed_ports,
              'azure_port_bindings': azure_port_bindings,
              'hostname': hostname, 'plugins': plugins,
              'post_script_id': post_script_id,
              'post_script_params': post_script_params,
              'disk_size': disk_size,
              'disk_path': disk_path,
              'cloud_init': cloud_init,
              'associate_floating_ip': associate_floating_ip,
              'associate_floating_ip_subnet': associate_floating_ip_subnet,
              'project_id': project_id,
              'bare_metal': bare_metal,
              'tags': tags,
              'hourly': hourly,
              'schedule': schedule,
              'softlayer_backend_vlan_id': softlayer_backend_vlan_id,
              'size_ram': size_ram,
              'size_cpu': size_cpu,
              'size_disk_primary': size_disk_primary,
              'size_disk_swap': size_disk_swap,
              'create_storage_account': create_storage_account,
              'new_storage_account': new_storage_account,
              'create_network': create_network,
              'new_network': new_network,
              'create_resource_group': create_resource_group,
              'new_resource_group': new_resource_group,
              'boot': boot,
              'build': build,
              'cpu_priority': cpu_priority,
              'cpu_sockets': cpu_sockets,
              'cpu_threads': cpu_threads,
              'port_speed': port_speed,
              'hypervisor_group_id': hypervisor_group_id,
              'machine_username': machine_username}
    if not async:
        ret = methods.create_machine(auth_context.owner, *args, **kwargs)
    else:
        args = (auth_context.owner.id, ) + args
        kwargs.update({'quantity': quantity, 'persist': persist})
        tasks.create_machine_async.apply_async(args, kwargs, countdown=2)
        ret = {'job_id': job_id}
    ret.update({'job': job})
    return ret


@view_config(route_name='api_v1_machines', request_method='PUT',
             renderer='json')
def add_machine(request):
    """
    Add a machine to an OtherServer Cloud. This works for bare_metal clouds.
    """
    cloud_id = request.matchdict.get('cloud')
    params = params_from_request(request)
    machine_ip = params.get('machine_ip')
    if not machine_ip:
        raise RequiredParameterMissingError("machine_ip")

    operating_system = params.get('operating_system', '')
    machine_name = params.get('machine_name', '')
    machine_key = params.get('machine_key', '')
    machine_user = params.get('machine_user', '')
    machine_port = params.get('machine_port', '')
    remote_desktop_port = params.get('remote_desktop_port', '')
    monitoring = params.get('monitoring', '')

    job_id = params.get('job_id')
    if not job_id:
        job = 'add_machine'
        job_id = uuid.uuid4().hex
    else:
        job = None

    auth_context = auth_context_from_request(request)
    auth_context.check_perm("cloud", "read", cloud_id)

    if machine_key:
        auth_context.check_perm("key", "read", machine_key)

    try:
        Cloud.objects.get(owner=auth_context.owner,
                          id=cloud_id, deleted=None)
    except Cloud.DoesNotExist:
        raise NotFoundError('Cloud does not exist')

    log.info('Adding bare metal machine %s on cloud %s'
             % (machine_name, cloud_id))
    cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                              deleted=None)

    try:
        machine = cloud.ctl.add_machine(machine_name, host=machine_ip,
                                        ssh_user=machine_user,
                                        ssh_port=machine_port,
                                        ssh_key=machine_key,
                                        os_type=operating_system,
                                        rdp_port=remote_desktop_port,
                                        fail_on_error=True)
    except Exception as e:
        raise MachineCreationError("OtherServer, got exception %r" % e,
                                   exc=e)

    # Enable monitoring
    if monitoring:
        monitor = enable_monitoring(
            auth_context.owner, cloud.id, machine.machine_id,
            no_ssh=not (machine.os_type == 'unix' and
                        machine.key_associations)
        )

    ret = {'id': machine.id,
           'name': machine.name,
           'extra': {},
           'public_ips': machine.public_ips,
           'private_ips': machine.private_ips,
           'job_id': job_id,
           'job': job
           }

    if monitoring:
        ret.update({'monitoring': monitor})

    return ret


@view_config(route_name='api_v1_cloud_machine',
             request_method='POST', renderer='json')
@view_config(route_name='api_v1_machine',
             request_method='POST', renderer='json')
def machine_actions(request):
    """
    Call an action on machine
    Calls a machine action on cloud that support it
    READ permission required on cloud.
    ACTION permission required on machine(ACTION can be START,
    STOP, DESTROY, REBOOT).
    ---
    machine_uuid:
      in: path
      required: true
      type: string
    action:
      enum:
      - start
      - stop
      - reboot
      - destroy
      - resize
      - rename
      required: true
      type: string
    name:
      description: The new name of the renamed machine
      type: string
    size:
      description: The size id of the plan to resize
      type: string
    """
    cloud_id = request.matchdict.get('cloud')
    params = params_from_request(request)
    action = params.get('action', '')
    plan_id = params.get('plan_id', '')
    memory = params.get('memory', '')
    cpus = params.get('cpus', '')
    cpu_shares = params.get('cpu_shares', '')
    cpu_units = params.get('cpu_units', '')
    name = params.get('name', '')
    auth_context = auth_context_from_request(request)

    if cloud_id:
        # this is depracated, keep it for backwards compatibility
        machine_id = request.matchdict['machine']
        auth_context.check_perm("cloud", "read", cloud_id)
        try:
            machine = Machine.objects.get(cloud=cloud_id,
                                          machine_id=machine_id,
                                          state__ne='terminated')
            # used by logging_view_decorator
            request.environ['machine_uuid'] = machine.id
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % machine_id)
    else:
        machine_uuid = request.matchdict['machine_uuid']
        try:
            machine = Machine.objects.get(id=machine_uuid)
            # VMs in libvirt can be started no matter if they are terminated
            if machine.state == 'terminated' and not isinstance(machine.cloud,
                                                                LibvirtCloud):
                raise
            # used by logging_view_decorator
            request.environ['machine_id'] = machine.machine_id
            request.environ['cloud_id'] = machine.cloud.id
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % machine_uuid)

        cloud_id = machine.cloud.id
        auth_context.check_perm("cloud", "read", cloud_id)

    if machine.cloud.owner != auth_context.owner:
        raise NotFoundError("Machine %s doesn't exist" % machine.id)

    auth_context.check_perm("machine", action, machine.id)

    actions = ('start', 'stop', 'reboot', 'destroy', 'resize',
               'rename', 'undefine', 'suspend', 'resume', 'remove')

    if action not in actions:
        raise BadRequestError("Action '%s' should be "
                              "one of %s" % (action, actions))
    if action == 'destroy':
        methods.destroy_machine(auth_context.owner, cloud_id,
                                machine.machine_id)
    elif action == 'remove':
        log.info('Removing machine %s in cloud %s'
                 % (machine.machine_id, cloud_id))

        if not machine.monitoring.hasmonitoring:
            machine.ctl.remove()
            # Schedule a UI update
            trigger_session_update(auth_context.owner, ['clouds'])
            return

        # if machine has monitoring, disable it. the way we disable depends on
        # whether this is a standalone io installation or not
        try:
            # we don't actually bother to undeploy collectd
            disable_monitoring(auth_context.owner, cloud_id, machine_id,
                               no_ssh=True)
        except Exception as exc:
            log.warning("Didn't manage to disable monitoring, maybe the "
                        "machine never had monitoring enabled. Error: %r", exc)

        machine.ctl.remove()

        # Schedule a UI update
        trigger_session_update(auth_context.owner, ['clouds'])

    elif action in ('start', 'stop', 'reboot',
                    'undefine', 'suspend', 'resume'):
        getattr(machine.ctl, action)()
    elif action == 'rename':
        if not name:
            raise BadRequestError("You must give a name!")
        getattr(machine.ctl, action)(name)
    elif action == 'resize':
        kwargs = {}
        if memory:
            kwargs['memory'] = memory
        if cpus:
            kwargs['cpus'] = cpus
        if cpu_shares:
            kwargs['cpu_shares'] = cpu_shares
        if cpu_units:
            kwargs['cpu_units'] = cpu_units
        getattr(machine.ctl, action)(plan_id, kwargs)

    # TODO: We shouldn't return list_machines, just OK. Save the API!
    return methods.filter_list_machines(auth_context, cloud_id)


@view_config(route_name='api_v1_cloud_machine_rdp',
             request_method='GET', renderer='json')
@view_config(route_name='api_v1_machine_rdp',
             request_method='GET', renderer='json')
def machine_rdp(request):
    """
    Rdp file for windows machines
    Generate and return an rdp file for windows machines
    READ permission required on cloud.
    READ permission required on machine.
    ---
    cloud:
      in: path
      required: true
      type: string
    machine:
      in: path
      required: true
      type: string
    rdp_port:
      default: 3389
      in: query
      required: true
      type: integer
    host:
      in: query
      required: true
      type: string
    """
    cloud_id = request.matchdict.get('cloud')

    auth_context = auth_context_from_request(request)

    if cloud_id:
        # this is depracated, keep it for backwards compatibility
        machine_id = request.matchdict['machine']
        auth_context.check_perm("cloud", "read", cloud_id)
        try:
            machine = Machine.objects.get(cloud=cloud_id,
                                          machine_id=machine_id,
                                          state__ne='terminated')
            # used by logging_view_decorator
            request.environ['machine_uuid'] = machine.id
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % machine_id)
    else:
        machine_uuid = request.matchdict['machine_uuid']
        try:
            machine = Machine.objects.get(id=machine_uuid,
                                          state__ne='terminated')
            # used by logging_view_decorator
            request.environ['machine_id'] = machine.machine_id
            request.environ['cloud_id'] = machine.cloud.id
        except Machine.DoesNotExist:
            raise NotFoundError("Machine %s doesn't exist" % machine_uuid)

        cloud_id = machine.cloud.id
        auth_context.check_perm("cloud", "read", cloud_id)

    auth_context.check_perm("machine", "read", machine.id)
    rdp_port = request.params.get('rdp_port', 3389)
    host = request.params.get('host')

    if not host:
        raise BadRequestError('No hostname specified')
    try:
        1 < int(rdp_port) < 65535
    except (ValueError, TypeError):
        rdp_port = 3389

    host, rdp_port = dnat(auth_context.owner, host, rdp_port)

    rdp_content = 'full address:s:%s:%s\nprompt for credentials:i:1' % \
                  (host, rdp_port)
    return Response(content_type='application/octet-stream',
                    content_disposition='attachment; filename="%s.rdp"' % host,
                    charset='utf8',
                    pragma='no-cache',
                    body=rdp_content)
