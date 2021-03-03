# Default
from mist.api.scripts.models import Script
from mist.api.tag.methods import get_tags_for_resource
from mist.api import config

from libcloud.container.types import Provider as Container_Provider
from libcloud.container.providers import get_driver as get_container_driver
from libcloud.container.base import ContainerImage

# Added by achilleas, require cleanup
import tempfile

import requests

# debug lib
import ipdb


def list_scripts(owner):
    scripts = Script.objects(owner=owner, deleted=None)
    script_objects = []
    for script in scripts:
        script_object = script.as_dict()
        script_object["tags"] = get_tags_for_resource(owner, script)
        script_objects.append(script_object)
    return script_objects


def filter_list_scripts(auth_context, perm='read'):
    """Return a list of scripts based on the user's RBAC map."""
    scripts = list_scripts(auth_context.owner)
    if not auth_context.is_owner():
        scripts = [script for script in scripts if script['id'] in
                   auth_context.get_allowed_resources(rtype='scripts')]
    return scripts


def docker_run(name, script_id, env=None, command=None):
    print(script_id)
    try:
        if config.DOCKER_TLS_KEY and config.DOCKER_TLS_CERT:
            # tls auth, needs to pass the key and cert as files
            key_temp_file = tempfile.NamedTemporaryFile(delete=False)
            key_temp_file.write(config.DOCKER_TLS_KEY.encode())
            key_temp_file.close()
            cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            cert_temp_file.write(config.DOCKER_TLS_CERT.encode())
            cert_temp_file.close()
            if config.DOCKER_TLS_CA:
                # docker started with tlsverify
                ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
                ca_cert_temp_file.write(config.DOCKER_TLS_CA.encode())
                ca_cert_temp_file.close()
            driver = get_container_driver(Container_Provider.DOCKER)
            conn = driver(host=config.DOCKER_IP,
                          port=config.DOCKER_PORT,
                          key_file=key_temp_file.name,
                          cert_file=cert_temp_file.name,
                          ca_cert=ca_cert_temp_file.name)
        else:
            driver = get_container_driver(Container_Provider.DOCKER)
            conn = driver(host=config.DOCKER_IP, port=config.DOCKER_PORT)
        image_id = "achilleasein/anisble4mist:latest"
        image = ContainerImage(id=image_id, name=image_id,
                               extra={}, driver=conn, path=None,
                               version=None)
        node = conn.deploy_container(name, image, environment=env,
                                     command=command, tty=True)
        return node
    except Exception as err:
        print(str(err))
        