"""This file contains dummy methods which used from open source in place of
core functions"""


def dnat(owner, ip_addr, port=''):
    if port:
        return ip_addr, port
    return ip_addr


def to_tunnel(owner, host):
    return


def cross_populate_session_data(event, kwargs):
    return


def get_cost_from_price_catalog(machine):
    return None, None, 1
