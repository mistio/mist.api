import os
import re
import yaml
import random
import logging
import mist.api.shell
from StringIO import StringIO
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import ScriptFormatError
from mist.api.scripts.base import BaseScriptController
from yaml.parser import ParserError as YamlParserError
from yaml.scanner import ScannerError as YamlScannerError
from mist.api.exceptions import RequiredParameterMissingError

from mist.api.monitoring.methods import associate_metric


log = logging.getLogger(__name__)


class AnsibleScriptController(BaseScriptController):

    def _preparse_file(self):
        if self.script.location.type == 'inline':
            try:
                yaml.load(self.script.location.source_code)
            except (YamlParserError, YamlScannerError):
                raise ScriptFormatError()

    def run_script(self, shell, params=None, job_id=None):
        path, params, wparams = super(
            AnsibleScriptController, self).run_script(shell, params=params,
                                                      job_id=job_id)
        wparams += " -a"
        return path, params, wparams


class ExecutableScriptController(BaseScriptController):

    def _preparse_file(self):
        if self.script.location.type == 'inline':
            if self.script.location.source_code:
                if not self.script.location.source_code.startswith('#!'):
                    raise BadRequestError(
                        "'script' must start with a hashbang/shebang ('#!')."
                    )
            else:
                raise BadRequestError("for inline script you must provide "
                                      "source code")


class CollectdScriptController(BaseScriptController):

    def run_script(self, shell, params=None, job_id=None):
        if self.script.location.type == 'inline':
            # wrap collectd python plugin so that it can run as script
            source_code = self.script.location.source_code
            hashbang = '#!/usr/bin/env python\n\n'
            if not source_code.startswith('#!'):
                self.script.location.source_code = hashbang + source_code
            self.script.location.source_code += '\n\nprint read()\n'

        path, params, wparams = super(CollectdScriptController,
                                      self).run_script(shell,
                                                       params=params,
                                                       job_id=job_id)
        return path, params, wparams

    def deploy_python_plugin(self, machine):
        if machine.monitoring.method != 'collectd-graphite':
            raise BadRequestError('%s is not using collectd' % machine)

        # Construct plugin_id from script name
        plugin_id = self.script.name.lower()
        plugin_id = re.sub('[^a-z0-9_]+', '_', plugin_id)
        plugin_id = re.sub('_+', '_', plugin_id)
        plugin_id = re.sub('^_', '', plugin_id)
        plugin_id = re.sub('_$', '', plugin_id)

        owner = self.script.owner
        value_type = self.script.extra.get('value_type', 'gauge')
        read_function = self.script.location.source_code
        host = machine.hostname

        # Sanity checks
        if not plugin_id:
            raise RequiredParameterMissingError('plugin_id')
        if not value_type:
            raise RequiredParameterMissingError('value_type')
        if not read_function:
            raise RequiredParameterMissingError('read_function')
        if not host:
            raise RequiredParameterMissingError('host')
        chars = [chr(ord('a') + i) for i in range(26)] + list('0123456789_')
        for c in plugin_id:
            if c not in chars:
                raise BadRequestError(
                    "Invalid plugin_id '%s'.plugin_id can only "
                    "lower case chars, numeric digits and"
                    "underscores" % plugin_id)
        if plugin_id.startswith('_') or plugin_id.endswith('_'):
            raise BadRequestError(
                "Invalid plugin_id '%s'. plugin_id can't start "
                "or end with an underscore." % plugin_id)
        if value_type not in ('gauge', 'derive'):
            raise BadRequestError(
                "Invalid value_type '%s'. Must be 'gauge' or "
                "'derive'." % value_type)

        # Initialize SSH connection
        shell = mist.api.shell.Shell(host)
        key_id, ssh_user = shell.autoconfigure(owner, machine.cloud.id,
                                               machine.machine_id)
        sftp = shell.ssh.open_sftp()

        tmp_dir = "/tmp/mist-python-plugin-%d" % random.randrange(2 ** 20)
        retval, stdout = shell.command("""
sudo=$(command -v sudo)
mkdir -p %s
cd /opt/mistio-collectd/
$sudo mkdir -p plugins/mist-python/
$sudo chown -R root plugins/mist-python/""" % tmp_dir)

        # Test read function
        test_code = """
import time

from %s_read import *

for i in range(3):
    val = read()
    if val is not None and not isinstance(val, (int, float, long)):
        raise Exception("read() must return a single int, float or long "
                        "(or None to not submit any sample to collectd)")
    time.sleep(1)
print("READ FUNCTION TEST PASSED")
        """ % plugin_id

        sftp.putfo(StringIO(read_function),
                   "%s/%s_read.py" % (tmp_dir, plugin_id))
        sftp.putfo(StringIO(test_code), "%s/test.py" % tmp_dir)

        retval, test_out = shell.command(
            "$(command -v sudo) python %s/test.py" % tmp_dir)
        stdout += test_out

        if not test_out.strip().endswith("READ FUNCTION TEST PASSED"):
            stdout += "\nERROR DEPLOYING PLUGIN\n"
            raise BadRequestError(stdout)

        # Generate plugin script
        plugin = """# Generated by mist.api web ui

import collectd

%(read_function)s

def read_callback():
    val = read()
    if val is None:
        return
    vl = collectd.Values(type="%(value_type)s")
    vl.plugin = "mist.python"
    vl.plugin_instance = "%(plugin_instance)s"
    vl.dispatch(values=[val])

collectd.register_read(read_callback)""" % {'read_function': read_function,
                                            'value_type': value_type,
                                            'plugin_instance': plugin_id}

        sftp.putfo(StringIO(plugin), "%s/%s.py" % (tmp_dir, plugin_id))
        retval, cmd_out = shell.command("""
cd /opt/mistio-collectd/
$(command -v sudo) mv %s/%s.py plugins/mist-python/
$(command -v sudo) chown -R root plugins/mist-python/""" % (tmp_dir, plugin_id)
                                        )
        stdout += cmd_out

        # Prepare collectd.conf
        script = """
sudo=$(command -v sudo)
cd /opt/mistio-collectd/

if ! grep '^Include.*plugins/mist-python' collectd.conf; then
    echo "Adding Include line in collectd.conf for plugins/mist-python/include.conf"
    $sudo su -c 'echo Include \\"/opt/mistio-collectd/plugins/mist-python/include.conf\\" >> collectd.conf'
else
    echo "plugins/mist-python/include.conf is already included in collectd.conf"
fi
if [ ! -f plugins/mist-python/include.conf ]; then
    echo "Generating plugins/mist-python/include.conf"
    $sudo su -c 'echo -e "# Do not edit this file, unless you are looking for trouble.\n\n<LoadPlugin python>\n    Globals true\n</LoadPlugin>\n\n\n<Plugin python>\n    ModulePath \\"/opt/mistio-collectd/plugins/mist-python/\\"\n    LogTraces true\n    Interactive false\n</Plugin>\n" > plugins/mist-python/include.conf'
else
    echo "plugins/mist-python/include.conf already exists, continuing"
fi

echo "Adding Import line for plugin in plugins/mist-python/include.conf"
if ! grep '^ *Import %(plugin_id)s *$' plugins/mist-python/include.conf; then
    $sudo cp plugins/mist-python/include.conf plugins/mist-python/include.conf.backup
    $sudo sed -i 's/^<\/Plugin>$/    Import %(plugin_id)s\\n<\/Plugin>/' plugins/mist-python/include.conf
    echo "Checking that python plugin is available"
    if $sudo /usr/bin/collectd -C /opt/mistio-collectd/collectd.conf -t 2>&1 | grep 'Could not find plugin python'; then
        echo "WARNING: collectd python plugin is not installed, will attempt to install it"
        zypper in -y collectd-plugin-python
        if $sudo /usr/bin/collectd -C /opt/mistio-collectd/collectd.conf -t 2>&1 | grep 'Could not find plugin python'; then
            echo "Install collectd-plugin-python failed"
            $sudo cp plugins/mist-python/include.conf.backup plugins/mist-python/include.conf
            echo "ERROR DEPLOYING PLUGIN"
        fi
    fi
    echo "Restarting collectd"
    $sudo /opt/mistio-collectd/collectd.sh restart
    sleep 2
    if ! $sudo /opt/mistio-collectd/collectd.sh status; then
        echo "Restarting collectd failed, restoring include.conf"
        $sudo cp plugins/mist-python/include.conf.backup plugins/mist-python/include.conf
        $sudo /opt/mistio-collectd/collectd.sh restart
        echo "ERROR DEPLOYING PLUGIN"
    fi
else
    echo "Plugin already imported in include.conf"
fi
$sudo rm -rf %(tmp_dir)s""" % {'plugin_id': plugin_id, 'tmp_dir': tmp_dir}  # noqa

        retval, cmd_out = shell.command(script)
        stdout += cmd_out
        if stdout.strip().endswith("ERROR DEPLOYING PLUGIN"):
            raise BadRequestError(stdout)

        shell.disconnect()

        parts = ["mist", "python"]  # strip duplicates (bucky also does this)
        for part in plugin_id.split("."):
            if part != parts[-1]:
                parts.append(part)
        metric_id = ".".join(parts)

        return {'metric_id': metric_id, 'stdout': stdout}

    def deploy_and_assoc_python_plugin_from_script(self, machine):
        # FIXME this works only for inline source_code
        # else we must_download the source from url or github
        ret = self.deploy_python_plugin(machine)
        associate_metric(machine, ret['metric_id'],
                         name=self.script.name,
                         unit=self.script.extra.get('value_unit', ''))
        return ret


class TelegrafScriptController(BaseScriptController):

    # FIXME Rename methods, since telegraf can run any sort of executable,
    # not just python scripts.

    def deploy_python_plugin(self, machine):
        # FIXME Remove.
        if machine.monitoring.method == 'collectd-graphite':
            raise BadRequestError('%s is not using Telegraf' % machine)

        # Paths for testing and deployment.
        conf_dir = '/opt/mistio/mist-telegraf/custom'
        test_dir = '/tmp/mist-telegraf-plugin-%d' % random.randrange(2 ** 20)
        test_conf = os.path.join(test_dir, 'exec.conf')
        test_plugin = os.path.join(test_dir, self.script.name)

        # Test configuration to ensure telegraf can load the executable.
        exec_conf = """
[[inputs.exec]]
  commands = ['%s']
  data_format = 'influx'
""" % (test_plugin)

        # Code to run in order to test the script's execution. Firstly, the
        # script is run by itself to make sure it does not throw any errors
        # and then it is loaded by telegraf using the exec plugin to verify
        # the computed series can be parsed.
        test_code = """
$(command -v sudo) chmod +x %s && \
$(command -v sudo) %s && \
$(command -v sudo) /opt/mistio/telegraf/usr/bin/telegraf -test -config %s
""" % (test_plugin, test_plugin, test_conf)

        # Initialize SSH connection.
        shell = mist.api.shell.Shell(machine.ctl.get_host())
        key_id, ssh_user = shell.autoconfigure(self.script.owner,
                                               machine.cloud.id,
                                               machine.machine_id)
        sftp = shell.ssh.open_sftp()

        # Create the test directory and the directory to store custom scripts,
        # if missing.
        retval, stdout = shell.command(
            'mkdir -p %s && [ -d %s ] || mkdir %s' % (test_dir,
                                                      conf_dir, conf_dir)
        )
        if retval:
            raise BadRequestError('Failed to init working dir: %s' % stdout)

        # Deploy the test configuration and the plugin.
        sftp.putfo(StringIO(exec_conf), test_conf)
        sftp.putfo(StringIO(self.script.location.source_code), test_plugin)

        # Run the test code to verify the plugin is working.
        retval, test_out, test_err = shell.command(test_code, pty=False)
        stdout += test_out
        if test_err:
            raise BadRequestError(
                "Test of read() function failed. Ensure the script's output "
                "is in the correct format for telegraf to parse. Expected "
                "format is 'measurement_name field1=val1[,field2=val2,...]'."
                "Error: %s" % test_err)

        # After the test/dry run, parse the series from stdout to gather
        # the measurement's name, tags, and values.
        series = []
        for line in test_out.splitlines():
            if line.startswith('> '):
                line = line[2:]
                measurement_and_tags, values, timestamp = line.split()
                measurement, tags = measurement_and_tags.split(',', 1)
                series.append((measurement, tags, values))
        if not series:
            raise BadRequestError('No computed series found in stdout')

        # Construct a list of `metric_id`s. All `metric_id`s are in the form:
        # `<measurement>.<column>`. The aforementioned notation does not hold
        # for the Graphite-based system, if the column name is "value", since
        # in that case Graphite stores the series at the top level and not in
        # a subdirectory, thus the measurement name suffices to query for the
        # specified metric.
        metrics = []
        for s in series:
            measurement = s[0]
            values_list = s[2].split(',')
            for value in values_list:
                metric = measurement
                column = value.split('=')[0]
                if not (machine.monitoring.method == 'telegraf-graphite' and
                        column == 'value'):
                    metric += '.' + column
                if metric in machine.monitoring.metrics:
                    raise BadRequestError('Metric %s already exists' % metric)
                metrics.append(metric)

        # Copy the plugin to the proper directory in order to be picked up by
        # telegraf.
        retval, stdout = shell.command('$(command -v sudo) '
                                       'cp %s %s' % (test_plugin, conf_dir))
        if retval:
            raise BadRequestError('Failed to deploy plugin: %s' % stdout)

        # Clean up working tmp dir.
        retval, stdout = shell.command('$(command -v sudo) '
                                       'rm -rf %s' % test_dir)
        if retval:
            log.error('Failed to clean up working dir: %s', stdout)

        # Close SSH connection.
        shell.disconnect()

        return {'metrics': metrics, 'stdout': stdout}

    def deploy_and_assoc_python_plugin_from_script(self, machine):
        ret = self.deploy_python_plugin(machine)
        for metric_id in ret['metrics']:
            associate_metric(machine, metric_id,
                             name=self.script.name,
                             unit=self.script.extra.get('value_unit', ''))
        return ret
