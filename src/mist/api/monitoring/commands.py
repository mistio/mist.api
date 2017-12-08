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


def windows_install(machine):
    cmd = "$TELEGRAF_MACHINE = '%s';\n" \
          "$TELEGRAF_HOST = '%s/%s';\n" \
          "mkdir 'C:\Program Files\Telegraf';" \
          "cd 'C:\Program Files\Telegraf';\n" \
          "Set-ExecutionPolicy -ExecutionPolicy " \
          "RemoteSigned -Scope CurrentUser -Force;\n" \
          "(New-Object System.Net.WebClient)." \
          "DownloadFile('https://dl.influxdata.com/telegraf" \
          "/releases/telegraf-1.4.4_windows_i386.zip', " \
          "'C:\Program Files\Telegraf\\telegraf.zip');\n" \
          "Expand-Archive .\\telegraf.zip; " \
          "cp .\\telegraf\\telegraf\\telegraf.exe .;\n" \
          "Set-ExecutionPolicy -ExecutionPolicy " \
          "RemoteSigned -Scope CurrentUser -Force;\n" \
          "(New-Object System.Net.WebClient).DownloadFile('" \
          "https://raw.githubusercontent.com/mistio/mist-telegraf/" \
          "windows-monitoring/telegraf-windows.conf', " \
          "'C:\Program Files\Telegraf\\telegraf.conf');\n" \
          "(Get-Content .\\telegraf.conf) -replace 'TELEGRAF_HOST', " \
          "$TELEGRAF_HOST | Set-Content .\\telegraf.conf;\n" \
          "(Get-Content .\\telegraf.conf) -replace 'TELEGRAF_MACHINE', " \
          "$TELEGRAF_MACHINE | Set-Content .\\telegraf.conf;\n" \
          "C:\\'Program Files'\\Telegraf\\telegraf.exe --service install;\n" \
          "net start telegraf\n" % (machine.id,
                                   config.TELEGRAF_TARGET,
                                   machine.monitoring.collectd_password)

    return cmd
