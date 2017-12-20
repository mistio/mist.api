import sys
import yaml
import re
import os
import mist.api

import json

this_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(this_dir)
paths = ['src', 'libcloud', 'celerybeat-mongo']
for p in paths:
    sys.path.append(os.path.join(parent_dir, p))
BASE_FILE_PATH = os.path.join(this_dir, 'base.yml')
OAS_FILE_PATH = os.path.join(this_dir, 'spec.yml')

# cleanup (operation --> docstring)

# docker image


#delete:
#      description: Deletes the requested avatar
#      parameters:
#        - description: Avatar Id
#          in: path
#          name: avatar
#          required: true
#          schema:
#            type: string
#      responses:
#        '200':
#          description: Successful Operation
#      requestBody:
#        description: Optional description in *Markdown*
#        required: true
#        content:
#          application/json:
#            schema:
#              type: object
#              properties:
#                id:
#                  type: string
#                  description: Test


def extract_params_from_operation(operation):
    params = []
    for key in list(set(operation.keys()) - {'parameters', 'requestBody',
                                             'responses', 'description',
                                             'tags'}):
        if 'in' in operation[key].keys():
            p = {}
            p['name'] = key
            p['schema'] = {}

            for k in operation[key].keys():
                if k in ['type', 'enum', 'default']:
                    p['schema'][k] = operation[key][k]
                else:
                    p[k] = operation[key][k]
            params.append(p)

    return params


def patch_operation(operation):
    ret = {}
    if operation.keys() and 'responses' in operation.keys():
        ret['responses'] = operation['responses']
    else:
        ret['responses'] = {'200': {'description': 'Successful Operation'}}

    if 'parameters' in operation.keys():
        ret['parameters'] = operation['parameters']
    else:
        params = extract_params_from_operation(operation)
        if params:
            ret['parameters'] = params

    if 'description' in operation.keys():
        ret['description'] = operation['description']

    if 'tags' in operation.keys():
        ret['tags'] = operation['tags']

    if 'requestBody' in operation.keys():
        ret['requestBody'] = operation['requestBody']

    else:

        properties = {}
        _require = []

        for key in list(set(operation.keys()) - {'parameters', 'requestBody',
                                                 'responses', 'description',
                                                 'tags'}):

                if 'in' not in operation[key].keys():
                    properties[key] = {}

                    for param in operation[key].keys():
                        if param in ['type', 'description']:
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

            ret['requestBody'] = {'content': {'application/json': {'schema': schema
                                                    }
                                }
                    }

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
    for v in app.registry.introspector.get_category('views'):
        vi = v['introspectable']
        (route_name, request_method, func) = (vi['route_name'],
                                              vi['request_methods'],
                                              vi['callable'])
        if route_name:
            route_path = app.routes_mapper.get_route(route_name).path
            if route_path and route_name.startswith('api_v1_') and not\
               route_name.startswith('api_v1_dev'):
                try:
                    operation = docstring_to_object(func.func_doc)
                except:
                    pass
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
