#!/usr/bin/env python

import sys
import yaml
import re
import os

this_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(this_dir)
paths = ['src','libcloud','celerybeat-mongo']
for p in paths:
    sys.path.append(os.path.join(parent_dir,p))

import mist.api

BASE_FILE_PATH = os.path.join(this_dir,'base.yml')
OAS_FILE_PATH = os.path.join(this_dir,'spec.yml')

def docstring_to_object(docstring):
    if not docstring:
        return {}

    operation = {}
    tokens = docstring.split('---')
    if len(tokens) > 1:
        # sanitization
        operation = yaml.safe_load(tokens[1]) or {}

    description = re.sub(r'\s+',r' ',tokens[0]).strip()
    operation['description'] = description

    # patch 'responses' section where it is not filled yet
    #if not 'responses' in operation:
    #    operation['responses'] = { '200': { 'description': 'Foo' } }

    return operation

def main():
    routes = []
    paths = {}
    app = mist.api.main({}).app.app
    for v in app.registry.introspector.get_category('views'):
        vi = v['introspectable']
        (route_name, request_method, func) = (vi['route_name'], vi['request_methods'], vi['callable'])
        if route_name:
            route_path = app.routes_mapper.get_route(route_name).path
            if route_path and route_name.startswith('api_v1_'):
                operation = docstring_to_object(func.func_doc)
                if isinstance(request_method,tuple):
                    for method in request_method:
                        routes.append((route_path, method.lower(), operation))
                else:
                    routes.append((route_path, request_method.lower(), operation))

    for path, method, operation in routes:
        if not path in paths:
            paths[path] = {}
        paths[path][method] = operation

    with open(BASE_FILE_PATH,'r') as f:
        openapi = yaml.safe_load(f.read())
        openapi['paths'] = paths
    with open(OAS_FILE_PATH,'w') as f:
        yaml.dump(openapi,f,default_flow_style=False)

if __name__ == '__main__':
    main()
