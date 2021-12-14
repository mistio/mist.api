#!/usr/bin/env python

import sys
import yaml
import re
import os
import json

import mist.api

this_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(this_dir)
paths = ['src', 'libcloud']
for p in paths:
    sys.path.append(os.path.join(parent_dir, p))
BASE_FILE_PATH = os.path.join(this_dir, 'base.yml')
OAS_FILE_PATH = os.path.join(this_dir, 'spec.yml')

OPENAPI_KEYWORDS = {'parameters', 'requestBody',
                    'responses', 'description',
                    'tags'}

DEFAULT_RESPONSES = {'200': {'description': 'Successful Operation'},
                     '401': {'description': 'Unauthorized'},
                     '403': {'description': 'You are not\
                     authorized to perform this action'},
                     '404': {'description': 'Not Found'}
                     }

EXCLUDED_ROUTE_NAMES = ['api_v1_avatars', 'api_v1_avatar', 'api_v1_fetch',
                        'api_v1_spec', 'stripe', 'api_v1_org_billing',
                        'purchase', 'api_v1_request_info', 'api_v1_tokens',
                        'api_v1_ping', 'api_v1_report', 'manage',
                        'api_v1_manage_orgs', 'api_v1_manage_org',
                        'api_v1_manage_users', 'api_v1_manage_user',
                        'api_v1_logs_ui', 'api_v1_license', 'api_v1_section',
                        'api_v1_version_check',
                        'api_v1_cloudify_insights_register']


def extract_params_from_operation(operation):
    params = []
    for key in list(set(operation.keys()) - OPENAPI_KEYWORDS):
        if 'in' in list(operation[key].keys()):
            p = {}
            p['name'] = key
            p['schema'] = {}

            for k in list(operation[key].keys()):
                if k in ['type', 'enum', 'default']:
                    p['schema'][k] = operation[key][k]
                else:
                    p[k] = operation[key][k]
            params.append(p)

    return params


def extract_request_body(operation, ret):
    properties = {}
    _require = []

    for key in list(set(operation.keys()) - OPENAPI_KEYWORDS):

        if 'in' not in list(operation[key].keys()):
            properties[key] = {}

            for param in list(operation[key].keys()):
                if param in ['type', 'description', 'example']:
                    properties[key][param] = operation[key][param]

                if param in ['required']:
                    _require.append(key)

    if properties:
        properties = json.dumps(properties)
        _properties = json.loads(properties)
        schema = {}

        schema['type'] = 'object'
        schema['properties'] = _properties

        if _require:
            schema['required'] = _require

        requestBody = {'content': {'application/json': {'schema': schema}}}

        ret['requestBody'] = requestBody

    return ret


def patch_operation(operation):
    ret = {}
    if list(operation.keys()) and 'responses' in list(operation.keys()):
        ret['responses'] = operation['responses']
    else:
        ret['responses'] = DEFAULT_RESPONSES

    if 'parameters' in list(operation.keys()):
        ret['parameters'] = operation['parameters']
    else:
        params = extract_params_from_operation(operation)
        if params:
            ret['parameters'] = params

    if 'description' in list(operation.keys()):
        ret['description'] = operation['description']
        ret['summary'] = operation['description'].split('.')[0]

    if 'tags' in list(operation.keys()):
        ret['tags'] = operation['tags']

    if 'requestBody' in list(operation.keys()):
        ret['requestBody'] = operation['requestBody']

    else:
        ret = extract_request_body(operation, ret)

    return ret


def docstring_to_object(docstring):
    if not docstring:
        return {}

    operation = {}
    tokens = docstring.split('---')

    if len(tokens) > 2:  # tags, description, and arguments
        operation = yaml.safe_load(tokens[2]) or {}
        description = re.sub(r'\s+', r' ', tokens[1]).strip()
        tags = re.sub(r'\s+', r' ', tokens[0]).strip().split()[1]
        tags_array = []
        tags_array.append(tags)
        operation['description'] = description
        operation['tags'] = tags_array
        return operation

    if len(tokens) == 2:
        operation = yaml.safe_load(tokens[1]) or {}

    description = re.sub(r'\s+', r' ', tokens[0]).strip()
    operation['description'] = description

    return operation


def main():
    routes = []
    paths = {}
    app = mist.api.main({}).app.app
    while not hasattr(app, 'registry'):
        app = app.app
    for v in app.registry.introspector.get_category('views'):
        vi = v['introspectable']
        (route_name, request_method, func) = (vi['route_name'],
                                              vi['request_methods'],
                                              vi['callable'])
        if route_name and request_method:
            route_path = app.routes_mapper.get_route(route_name).path
            if route_path and route_name.startswith('api_v1_')\
               and not route_name.startswith('api_v1_dev') and\
               ('whitelist' not in route_name) and\
               route_name not in EXCLUDED_ROUTE_NAMES:
                try:
                    operation = docstring_to_object(func.__doc__)
                except:
                    continue
                if isinstance(request_method, tuple):
                    for method in request_method:
                        routes.append((route_path, method.lower(), operation))
                else:
                    routes.append((route_path, request_method.lower(),
                                   operation))

    for path, method, operation in routes:
        if path not in paths:
            paths[path] = {}
        paths[path][method] = patch_operation(operation)

    with open(BASE_FILE_PATH, 'r') as f:
        openapi = yaml.safe_load(f.read())
        openapi['paths'] = paths
    with open(OAS_FILE_PATH, 'w') as f:
        noalias_dumper = yaml.dumper.SafeDumper
        noalias_dumper.ignore_aliases = lambda self, data: True
        yaml.dump(openapi, f, default_flow_style=False, Dumper=noalias_dumper)


if __name__ == '__main__':
    main()
