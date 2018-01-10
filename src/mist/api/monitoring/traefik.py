import requests

from mist.api import config

from mist.api.machines.models import Machine


TRAEFIK_API_URL = '%s/api/providers/web' % config.TRAEFIK_API


def _gen_machine_frontend_config(machine):
    """Generate traefik frontend config for machine with monitoring"""
    if not machine.monitoring.hasmonitoring:
        raise Exception("Machine.monitoring.hasmonitoring is False")
    if machine.monitoring.method == 'telegraf-graphite':
        backend = 'gocky-graphite'
    elif machine.monitoring.method == 'telegraf-influxdb':
        backend = 'gocky-influxdb'
    else:
        raise Exception("Invalid monitoring method '%s'"
                        % machine.monitoring.method)
    return {
        "routes": {
            "main": {
                "rule": "PathPrefixStrip:/%s" % (
                    machine.monitoring.collectd_password
                ),
            },
        },
        "backend": backend,
        "passHostHeader": True,
        "headers": {
            "customrequestheaders": {
                "X-Gocky-Tag-Resource-Id": machine.id,
                "X-Gocky-Tag-Org-Id": machine.cloud.owner.id,
                "X-Gocky-Tag-Cloud-Id": machine.cloud.id,
                "X-Gocky-Tag-Machine-Id": machine.id,
                "X-Gocky-Tag-Machine-External-Id": machine.machine_id,
                "X-Gocky-Tag-Source-Type": machine.os_type,
            },
        },
        "entryPoints": [
            "http",
        ],
    }


def _gen_config():
    """Generate traefik config from scratch for all machines"""
    return {
        "backends": {
            "gocky-influxdb": {
                "loadBalancer": {
                    "method": "wrr",
                },
                "servers": {
                    "gocky": {
                        "url": "http://gocky:9096",
                        "weight": 10,
                    },
                },
            },
            "gocky-graphite": {
                "loadBalancer": {
                    "method": "wrr",
                },
                "servers": {
                    "gocky": {
                        "url": "http://gocky:9097",
                        "weight": 10,
                    },
                },
            },
        },
        "frontends": {
            machine.id: _gen_machine_frontend_config(machine)
            for machine in Machine.objects(
                monitoring__hasmonitoring=True,
                monitoring__method__in=['telegraf-graphite',
                                        'telegraf-influxdb'],
            )
        },
    }


def _get_config():
    """Get current traefik config"""
    resp = requests.get(TRAEFIK_API_URL)
    if not resp.ok:
        raise Exception("Bad traefik response: %s %s" % (resp.status_code,
                                                         resp.text))
    return resp.json()


def _set_config(config):
    """Set traefik config"""
    resp = requests.put(TRAEFIK_API_URL, json=config)
    if not resp.ok:
        raise Exception("Bad traefik response: %s %s" % (resp.status_code,
                                                         resp.text))
    return _get_config()


def reset_config():
    """Reset traefik config by regenerating from scratch"""
    return _set_config(_gen_config())


def add_machine_to_config(machine):
    """Add frontend rule for machine monitoring"""
    config = _get_config()
    config["frontends"][machine.id] = _gen_machine_frontend_config(machine)
    return _set_config(config)


def remove_machine_from_config(machine):
    """Remove frontend rule for machine monitoring"""
    config = _get_config()
    config["frontends"].pop(machine.id, None)
    return _set_config(config)
