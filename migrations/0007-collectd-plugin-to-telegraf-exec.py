import re
import traceback

from mist.api.scripts.models import CollectdScript
from mist.api.scripts.models import TelegrafScript


def migrate():
    """Migrate collectd plugins to telegraf executables"""

    scripts = CollectdScript.objects(deleted=None, migrated__ne=True)
    unmigrated = scripts.count()
    succeeded = failed = 0

    print 'Will migrate %d collectd script' % unmigrated

    for old_script in scripts:
        try:
            print 'Migrating', old_script,

            # Construct new script's name from old script's name. This
            # will also be the executable's filesystem name.
            plugin_id = old_script.name.lower()
            plugin_id = re.sub('[^a-z0-9_]+', '_', plugin_id)
            plugin_id = re.sub('_+', '_', plugin_id)
            plugin_id = re.sub('^_', '', plugin_id)
            plugin_id = re.sub('_$', '', plugin_id)

            # Prepend shebang, if missing, and append `print` statement.
            source = old_script.location.source_code
            if not source.startswith('#!'):
                source = '#!/usr/bin/env python\n\n' + source
            source += '\n\nprint "%s value=" + str(read())\n' % plugin_id

            # Add new Telegraf executable.
            new_script = TelegrafScript()
            new_script.name = plugin_id
            new_script.owner = old_script.owner
            new_script.extra = old_script.extra
            new_script.location = old_script.location
            new_script.location.source_code = source
            new_script.description = old_script.description

            # Avoid uniqueness constrains.
            if new_script.name == old_script.name:
                new_script.name += '_new'

            # Attempt to save.
            new_script.save()
        except Exception:
            traceback.print_exc()
            failed += 1
            print '[ERROR]'
            continue
        else:
            succeeded += 1
            print '[OK]'

        try:
            old_script.migrated = True
            old_script.save()
        except Exception:
            traceback.print_exc()
            new_script.delete()

    print
    print 'Migrated %d/%d' % (succeeded, unmigrated)
    print
    print 'Completed %s' % ('successfully!' if not failed else 'with errors!')
    print


if __name__ == '__main__':
    migrate()
