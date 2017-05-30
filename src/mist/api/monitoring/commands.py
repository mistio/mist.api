"""Definition of commands used to (un)install Telegraf"""

from mist.api.config import INFLUX


REPO = "https://gitlab.ops.mist.io/mistio/mist-telegraf/raw/master/scripts"


def unix_install(machine_uuid):
    cmd = "wget -qO- %s/install-telegraf.sh | sudo sh -s -- " % REPO
    cmd += "-m %s " % machine_uuid
    cmd += "-s %(host)s -d %(db)s" % INFLUX
    return cmd


def unix_uninstall(machine_uuid):
    return "wget -qO- %s/uninstall-telegraf.sh | sudo sh" % REPO


def coreos_install(machine_uuid):
    cmd = "wget -qO- %s/docker-telegraf.sh | sudo sh -s -- " % REPO
    cmd += "-m %s " % machine_uuid
    cmd += "-s %(host)s -d %(db)s" % INFLUX
    return cmd


def coreos_uninstall(machine_uuid):
    return "wget -qO- %s/docker-telegraf.sh | sudo sh -s -- -k" % REPO
