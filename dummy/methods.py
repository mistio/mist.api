"""This file contains dummy methods which used from open source in place of
core functions"""


def assign_promo(org, promo_code='', promo_token='', force=False):
    return None


def dnat(owner, ip_addr, port):
    return ip_addr, port


def to_tunnel(owner, host):
    return


def super_ping(owner, tunnel_id='', host='', pkts=10):
    return None


def filter_list_templates(auth_context):
    return {}


def filter_list_stacks(auth_context):
    return {}


def get_user_data(auth_context):
    return None


def filter_list_tags(auth_context, scripts=None, perm='read'):
    return {}


def filter_list_vpn_tunnels(auth_context, perm='read'):
    return {}


def get_stats(owner, cloud_id, machine_id, start='', stop='', step='',
              metrics=None, callback=None, tornado_async=False):
    return None


def get_load(owner, start='', stop='', step='', tornado_callback=None):
    return {}


def check_monitoring(owner):
    return {}

