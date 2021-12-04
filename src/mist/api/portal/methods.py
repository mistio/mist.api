import requests
import dns.resolver

from mist.api.exceptions import InternalServerError

from mist.api import config


def active_websocket_sessions():
    hosts = []
    entries = dns.resolver.query(config.INTERNAL_SOCKJS_HOST, "A")
    for entry in entries:
        hosts.append(entry.address)

    users = {}
    for h in hosts:
        host = '%s:8081' % h
        try:
            resp = requests.get('http://' + host)
            if not resp.ok:
                print("Error response from host '%s': %s" % (host, resp.body))
                raise
            res = resp.json()
        except Exception as exc:
            raise InternalServerError("Error querying host '%s': %r" % (
                host, exc))
        for channel in res.keys():
            for entry in res[channel]:
                if entry['user'] not in users:
                    users[entry['user']] = {

                        'sessions': []
                    }
                users[entry['user']]['sessions'].append((channel, entry))
                if entry['last_rcv'] > users[entry['user']].get('last_rcv', 0):
                    users[entry['user']]['last_rcv'] = entry['last_rcv']

    return users
