"""Definition of commands used to (un)install Telegraf"""

from mist.api import config


REPO = "https://gitlab.ops.mist.io/mistio/mist-telegraf/raw/master/scripts"


def unix_install(machine):
    cmd = "wget -O- %s/install-telegraf.sh | sudo sh -s -- " % REPO
    cmd += "-m %s " % machine.id
    cmd += "-s %s/%s" % (config.TELEGRAF_TARGET,
                         machine.monitoring.collectd_password)
    return cmd


def unix_uninstall():
    return "wget -O- %s/uninstall-telegraf.sh | sudo sh" % REPO


def coreos_install(machine):
    cmd = "wget -O- %s/docker-telegraf.sh | sudo sh -s -- " % REPO
    cmd += "-m %s " % machine.id
    cmd += "-s %s/%s" % (config.TELEGRAF_TARGET,
                         machine.monitoring.collectd_password)
    return cmd


def coreos_uninstall():
    return "wget -O- %s/docker-telegraf.sh | sudo sh -s -- -k" % REPO
