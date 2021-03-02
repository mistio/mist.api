# Default
from mist.api.scripts.models import Script
from mist.api.tag.methods import get_tags_for_resource

# Added by achilleas, require cleanup
import os
import uuid
import tempfile
import logging

import requests

#debug lib
import ipdb
# from functools import cmp_to_key

# import mongoengine as me

# from libcloud.container.types import Provider as Container_Provider
# from libcloud.container.providers import get_driver as get_container_driver
# from libcloud.container.base import ContainerImage

# from mist.api import helpers as io_helpers

# from mist.api.mongoengine_extras import escape_dots_and_dollars_from_dict

# from mist.api.auth.models import ApiToken

# from mist.api.tag.methods import add_tags_to_resource, get_tags_for_resource

# from mist.orchestration.helpers import download, unpack, find_path
# from mist.orchestration.models import Template, Stack
# from mist.orchestration.exceptions import WorkflowExecutionError

# from mist.api.exceptions import BadRequestError
# from mist.api.exceptions import ConflictError
# from mist.api.exceptions import RequiredParameterMissingError

# from mist.api.logs.methods import log_event

# from mist.api import config

# if config.HAS_RBAC:
#     from mist.rbac.tokens import SuperToken

# log = logging.getLogger(__name__)


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

def docker_run(name, env=None, command=None, script_id):
    import mist.api.shell
    from mist.api.methos import notify_admin, notify_user
    from mist.api.machines.methos import list_machines
    print(script_id)
    # try:
    #     if config.DOCKER_TLS_KEY and config.DOCKER_TLS_CERT:
    #         # tls auth, needs to pass the key and cert as files
    #         key_temp_file = tempfile.NamedTemporaryFile(delete=False)
    #         key_temp_file.write(config.DOCKER_TLS_KEY.encode())
    #         key_temp_file.close()
    #         cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
    #         cert_temp_file.write(config.DOCKER_TLS_CERT.encode())
    #         cert_temp_file.close()
    #         if config.DOCKER_TLS_CA:
    #             # docker started with tlsverify
    #             ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
    #             ca_cert_temp_file.write(config.DOCKER_TLS_CA.encode())
    #             ca_cert_temp_file.close()
    #         driver = get_container_driver(Container_Provider.DOCKER)
    #         conn = driver(host=config.DOCKER_IP,
    #                       port=config.DOCKER_PORT,
    #                       key_file=key_temp_file.name,
    #                       cert_file=cert_temp_file.name,
    #                       ca_cert=ca_cert_temp_file.name)
    #     else:
    #         driver = get_container_driver(Container_Provider.DOCKER)
    #         conn = driver(host=config.DOCKER_IP, port=config.DOCKER_PORT)
        # image_id = "mist/cloudify-mist-plugin:latest"
        # image = ContainerImage(id=image_id, name=image_id,
        #                        extra={}, driver=conn, path=None,
        #                        version=None)
        # node = conn.deploy_container(name, image, environment=env,
        #                              command=command, tty=True)
    # except Exception as err:
    #     raise WorkflowExecutionError(str(err))

    # return node
