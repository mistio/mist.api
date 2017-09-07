"""Definition of commands used to (un)install Telegraf"""

from mist.api.config import INFLUX


REPO = "https://gitlab.ops.mist.io/mistio/mist-telegraf/raw/master/scripts"


def unix_install(machine_uuid):
    cmd = "wget -O- %s/install-telegraf.sh | sudo sh -s -- " % REPO
    cmd += "-m %s " % machine_uuid
    cmd += "-s http://gocky:9096"
    # cmd += "-s %(host)s -d %(db)s" % INFLUX
    return cmd


def unix_uninstall(machine_uuid):
    return "wget -O- %s/uninstall-telegraf.sh | sudo sh" % REPO


def coreos_install(machine_uuid):
    cmd = "wget -O- %s/docker-telegraf.sh | sudo sh -s -- " % REPO
    cmd += "-m %s " % machine_uuid
    cmd += "-s http://gocky:9096"
    # cmd += "-s %(host)s -d %(db)s" % INFLUX
    return cmd


def coreos_uninstall(machine_uuid):
    return "wget -O- %s/docker-telegraf.sh | sudo sh -s -- -k" % REPO
