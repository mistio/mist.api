import requests

from mist.api import config

from mist.api.machines.models import Machine


TRAEFIK_API_URL = "%s/api/providers/rest" % config.TRAEFIK_API


def _gen_machine_config(machine):
    """Generate traefik frontend config for machine with monitoring"""
    if not machine.monitoring.hasmonitoring:
        raise Exception("Machine.monitoring.hasmonitoring is False")
    frontend = {
        "routes": {
            "main": {
                "rule": "PathPrefixStrip:/%s"
                % (machine.monitoring.collectd_password),
            },
        },
        "backend": machine.id,
        "passHostHeader": True,
        "headers": {
            "customrequestheaders": {
                "X-Gocky-Tag-Resource-Id": machine.id,
                "X-Gocky-Tag-Org-Id": machine.cloud.owner.id,
                "X-Gocky-Tag-Cloud-Id": machine.cloud.id,
                "X-Gocky-Tag-Machine-Id": machine.id,
                "X-Gocky-Tag-Machine-External-Id": machine.external_id,
                "X-Gocky-Tag-Source-Type": machine.os_type,
            },
        },
        "entryPoints": ["http"],
    }
    backend = {
        "servers": {
            "gocky": {
                "url": "http://%s:%d" % (config.GOCKY_HOST, config.GOCKY_PORT),
                "weight": 10,
            },
        },
        "loadBalancer": {"method": "wrr"},
    }
    return frontend, backend


def _gen_config():
    """Generate traefik config from scratch for all machines"""
    cfg = {"frontends": {}, "backends": {}}
    for machine in Machine.objects(
        monitoring__hasmonitoring=True,
    ):
        frontend, backend = _gen_machine_config(machine)
        cfg["frontends"][machine.id] = frontend
        cfg["backends"][machine.id] = backend
    return cfg


def _get_config():
    """Get current traefik config"""
    resp = requests.get(TRAEFIK_API_URL)
    if not resp.ok:
        raise Exception(
            "Bad traefik response: %s %s" % (resp.status_code, resp.text)
        )
    return resp.json()


def _set_config(cfg):
    """Set traefik config"""
    resp = requests.put(TRAEFIK_API_URL, json=cfg)
    if not resp.ok:
        raise Exception(
            "Bad traefik response: %s %s" % (resp.status_code, resp.text)
        )
    return _get_config()


def reset_config():
    """Reset traefik config by regenerating from scratch"""
    return _set_config(_gen_config())


def add_machine_to_config(machine):
    """Add frontend rule for machine monitoring"""
    cfg = _get_config()
    frontend, backend = _gen_machine_config(machine)
    cfg["frontends"][machine.id] = frontend
    cfg["backends"][machine.id] = backend
    return _set_config(cfg)


def remove_machine_from_config(machine):
    """Remove frontend rule for machine monitoring"""
    cfg = _get_config()
    cfg["frontends"].pop(machine.id, None)
    cfg["backends"].pop(machine.id, None)
    return _set_config(cfg)
