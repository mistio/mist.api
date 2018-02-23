"""This file contains dummy methods which used from open source in place of
core functions"""


def dnat(owner, ip_addr, port=''):
    if port:
        return ip_addr, port
    return ip_addr


def to_tunnel(owner, host):
    return


def filter_list_tags(auth_context, scripts=None, perm='read'):
    return {}


def cross_populate_session_data(event, kwargs):
    return
