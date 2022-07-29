import os
import logging
import datetime
import subprocess

import requests

import mongoengine as me

from mist.api.dramatiq_app import dramatiq

from mist.api import config
from mist.api.helpers import get_victoriametrics_uri
from mist.api.helpers import get_victoriametrics_write_uri
from mist.api.portal.models import Portal, AvailableUpgrade
from mist.api.metering.methods import get_current_portal_usage
from mist.api.rules.models import NoDataRule
from mist.api.poller.models import PollingSchedule
from mist.api.auth.models import SessionToken, ApiToken
from mist.api.portal.methods import check_task_threshold
from mist.api.methods import notify_admin

log = logging.getLogger(__name__)

__all__ = [
    'create_backup',
    'check_new_versions',
    'usage_survey'
]


def get_version_params(portal=None):
    if portal is None:
        portal = Portal.get_singleton()
    params = {
        'portal_id': portal.id,
        'created': str(portal.created),
        'license_key': config.LICENSE_KEY,
    }
    for key, value in config.VERSION.items():
        params['version_%s' % key] = value
    for key, value in list(get_current_portal_usage().items()):
        params['usage_%s' % key] = value
    return params


@dramatiq.actor
def gc_schedulers():
    """Delete disabled schedules.

    This takes care of:

    1. Removing disabled list_machines polling schedules.
    2. Removing ssh/ping probe schedules, whose machines are missing or
       corresponding clouds have been deleted.
    3. Removing inactive no-data rules. They are added idempotently the
       first time get_stats receives data for a newly monitored machine.

    Note that this task does not run GC on user-defined schedules.

    """
    for collection in (PollingSchedule, NoDataRule, ):
        for entry in collection.objects():
            try:
                if not entry.enabled:
                    log.warning('Removing %s', entry)
                    entry.delete()
            except me.DoesNotExist:
                entry.delete()
            except Exception as exc:
                log.error(exc)


@dramatiq.actor
def gc_sessions():
    """Delete expired sessions & invalid old tokens.
    """
    tdelta = datetime.timedelta(days=7)
    expired_sessions = SessionToken.objects(
        created__lt=datetime.datetime.now() - tdelta)
    expired_session_count = expired_sessions.count()
    if expired_session_count:
        print(f"Removing {expired_session_count} expired sessions.")
        expired_sessions.delete()
    aged_tokens = ApiToken.objects(
        created__lt=datetime.datetime.now() - tdelta)
    expired_tokens = [t.id for t in aged_tokens if not t.is_valid()]
    expired_token_count = len(expired_tokens)
    if expired_token_count:
        print(f"Removing {expired_token_count} expired API tokens.")
        ApiToken.objects(id__in=expired_tokens).delete()
    print(f"{SessionToken.objects.count()} sessions remaining")
    print(f"{ApiToken.objects.count()} api tokens remaining")


@dramatiq.actor
def check_new_versions(url="https://mist.io/api/v1/version-check"):
    portal = Portal.get_singleton()
    params = get_version_params(portal)

    log.info("Will check for new versions. Url %s - Params %s", url, params)
    resp = requests.get(url, params)
    if not resp.ok:
        log.error("Bad response while checking for new versions: %s: %s",
                  resp.status_code, resp.text)
        raise Exception("%s: %s" % (resp.status_code, resp.text))
    portal.available_upgrades = []
    for version in resp.json():
        available_upgrade = AvailableUpgrade()
        for key in ('name', 'sha'):
            if key not in version:
                log.warning("Missing required field '%s' from version.", key)
                break
            available_upgrade[key] = version[key]
        else:
            portal.available_upgrades.append(available_upgrade)
    portal.save()


def get_usage_params(portal=None):
    if portal is None:
        portal = Portal.get_singleton()
    params = get_version_params(portal=portal)
    # Inject more info into params
    return params


@dramatiq.actor
def usage_survey(url="https://mist.io/api/v1/usage-survey"):
    portal = Portal.get_singleton()
    params = get_usage_params(portal)

    log.info("Will send usage info. Url %s - Params %s", url, params)
    resp = requests.get(url, params)
    if not resp.ok:
        log.error("Bad response while sending usage info: %s: %s",
                  resp.status_code, resp.text)
        raise Exception("%s: %s" % (resp.status_code, resp.text))


@dramatiq.actor(store_results=True,
                time_limit=3_600_000,
                queue_name='dramatiq_schedules')
def create_backup(
        databases=['mongo', 'influx', 'elastic', 'victoria', 'vault'],
        prefer_incremental=True):
    """
        Backup databases if s3 creds are set.
    """

    if not config.BACKUP_INTERVAL or not config.BACKUP.get('key'):
        return

    start = datetime.datetime.now()
    dt = start.strftime('%Y%m%d%H%M')
    s3_host = config.BACKUP.get('host', 's3.amazonaws.com')
    portal_host = config.PORTAL_URI.split('//')[1]

    # Encrypt backup if GPG configured
    has_gpg = not all(
        value == '' for value in config.BACKUP.get('gpg', {}).values())
    if has_gpg:
        f = open('pub.key', 'w+')
        f.write(config.BACKUP['gpg']['public'])
        f.close()
        os.system("gpg --import pub.key")
        gpg_cmd = (
            f"gpg --yes --trust-model always --encrypt"
            f" --recipient {config.BACKUP['gpg']['recipient']} |"
        )
    else:
        gpg_cmd = ""
    if 'mongo' in databases:
        start_mongo = datetime.datetime.now()
        # If MONGO_URI consists of multiple hosts get the last one
        mongo_backup_host = config.MONGO_URI.split('//')[-1].split(
            '/')[0].split(',')[-1]
        cmd = (
            f"mongodump --host {mongo_backup_host} --gzip --archive"
            f" --forceTableScan | {gpg_cmd}"
            f"s3cmd --host={s3_host} --access_key={config.BACKUP['key']}"
            f" --secret_key={config.BACKUP['secret']} put - "
            f" s3://{config.BACKUP['bucket']}/{portal_host}/mongo/{dt}"
        )

        os.system(cmd)
        log.info('MongoDB backup finished in %s' % (
            datetime.datetime.now() - start_mongo))

    if 'influx' in databases:
        start_influx = datetime.datetime.now()
        # Strip protocol prefix from influx backup uri
        influx_backup_host = config.INFLUX.get('backup', '').replace(
            'http://', '').replace('https://', '')
        if influx_backup_host:
            cmd = (
                f"influxd backup -portable -host {influx_backup_host} "
                f"./influx-snapshot && tar cv influx-snapshot |"
                f"{gpg_cmd}"
                f"s3cmd --host={s3_host} --access_key={config.BACKUP['key']}"
                f" --secret_key={config.BACKUP['secret']} put - "
                f" s3://{config.BACKUP['bucket']}/{portal_host}/"
                f"influx/{dt} && rm -rf influx-snapshot"
            )
            os.system(cmd)
            log.info('InfluxDB backup finished in %s' % (
                datetime.datetime.now() - start_influx))

    if 'victoria' in databases:
        from mist.api.users.models import Organization

        start_victoria = datetime.datetime.now()
        last_month = start_victoria - datetime.timedelta(days=31)
        start_of_hour = start_victoria.replace(
            minute=0, second=0, microsecond=0)
        if prefer_incremental:
            last_backup_time = start_of_hour - datetime.timedelta(
                hours=config.BACKUP_INTERVAL)
            start_ts = int((last_backup_time - datetime.timedelta(
                hours=config.BACKUP_INTERVAL)).timestamp())
        else:
            start_ts = 0
        suffix = '.gpg' if has_gpg else ''
        for org in Organization.objects(
                last_active__gt=last_month).order_by('-last_active'):
            base_uri = get_victoriametrics_uri(org)
            uri = (
                f'{base_uri}/api/v1/export/native?start={start_ts}&'
                f'match[]={{__name__!=""}}'
            )
            cmd = (
                f'curl "{uri}" | gzip | '
                f'{gpg_cmd}'
                f's3cmd --host={s3_host} --access_key={config.BACKUP["key"]}'
                f' --secret_key={config.BACKUP["secret"]} put - '
                f's3://{config.BACKUP["bucket"]}/{portal_host}/victoria/'
                f'{dt}/{org.id}{suffix}'
            )
            # print(cmd)
            os.system(cmd)
        log.info('VictoriaMetrics backup finished in %s' % (
            datetime.datetime.now() - start_victoria))
    log.info('All backups finished in %s' % (
        datetime.datetime.now() - start))


def restore_backup(backup, portal=None, until=False, databases=[
        'mongodb', 'influxdb', 'elasticsearch', 'victoriametrics', 'vault']):
    if not portal:
        portal = config.PORTAL_URI.split('//')[1]
    portal_path = f"{portal}/" if portal else ""
    s3_host = config.BACKUP.get('host', 's3.amazonaws.com')
    start = datetime.datetime.now()
    has_gpg = not all(
        value == '' for value in config.BACKUP.get('gpg', {}).values())

    for db in databases:
        cmd = (
            f"s3cmd --host={s3_host} --access_key={config.BACKUP['key']}"
            f" --secret_key={config.BACKUP['secret']} get --recursive --force"
            f" s3://{config.BACKUP['bucket']}/{portal_path}{db}/{backup}"
            f" {backup}.{db} && "
        )
        if 'mongo' in db:
            start_mongo = datetime.datetime.now()
            if has_gpg:
                cmd += (
                    f"mv {backup}.{db} {backup}.{db}.gpg && "
                    f"gpg -o {backup}.{db} --pinentry-mode loopback"
                    f" -d {backup}.{db}.gpg && "
                )
            cmd += (
                f"mongorestore -h {config.MONGO_URI} --gzip"
                f" --archive={backup}.{db}"
            )
            os.system(cmd)
            log.info('MongoDB restore finished in %s' % (
                datetime.datetime.now() - start_mongo))
        elif 'influx' in db:
            start_influx = datetime.datetime.now()
            if has_gpg:
                cmd += (
                    f"mv {backup}.{db} {backup}.{db}.gpg && "
                    f"gpg -o {backup}.{db} --pinentry-mode loopback"
                    f" -d {backup}.{db}.gpg && "
                )
            influx_backup_host = config.INFLUX.get('backup', '').replace(
                'http://', '').replace('https://', '')
            # Prepare base URL.
            url = '%s/query' % config.INFLUX['host']
            cmd += (
                f"rm -rf influx-snapshot && tar xvf {backup}.{db}"
            )
            # print(cmd)
            os.system(cmd)

            for idb in ['telegraf', 'metering']:
                cmd = (
                    f"influxd restore -host {influx_backup_host} -portable"
                    f" -db {idb} -newdb {idb}_bak influx-snapshot && "
                    f"echo Restored database as {idb}_bak"
                )
                print(cmd)
                os.system(cmd)
                resp = input("Move data from %s_bak to %s? [y/n] " % (
                    idb, idb))
                if resp.lower() == 'y':
                    requests.post('%s?q=CREATE database %s' % (url, idb))
                    query = (
                        "SELECT * INTO %s..:MEASUREMENT FROM /.*/ "
                        "GROUP BY *;"
                    )
                    query += "DROP DATABASE %s_bak"
                    query = query % (idb, idb)
                    requests.post('%s?db=%s_bak&q=%s' % (url, idb, query))
                    requests.post('%s?q=DROP database %s_bak' % (url, idb))
            log.info('InfluxDB restore finished in %s' % (
                datetime.datetime.now() - start_influx))
        elif 'elastic' in db:
            # TODO
            print(cmd)
        elif 'vault' in db:
            # TODO
            print(cmd)
        elif 'victoria' in db:
            from mist.api.models import Organization
            start_victoria = datetime.datetime.now()
            if has_gpg:
                cmd += (
                    f"gpg --pinentry-mode loopback --decrypt-files"
                    f" {backup}.{db}/{backup}/*.gpg && "
                    f"rm {backup}.{db}/{backup}/*.gpg && "
                )

            cmd += "echo Dowloaded"
            cmd = f"rm -rf {backup}.{db} && mkdir {backup}.{db} && " + cmd
            # print(cmd)
            os.system(cmd)
            last_month = start - datetime.timedelta(days=31)
            for org_id in os.listdir(f'{backup}.{db}/{backup}'):
                try:
                    org = Organization.objects.get(id=org_id)
                except org.DoesNotExist:
                    log.error(f"Organization {org_id} not found")
                    continue
                if org.last_active < last_month:
                    log.error(
                        f"Organization {org.name} not recently active")
                    continue

                uri = get_victoriametrics_write_uri(org)
                cmd = (
                    f'cat {backup}.{db}/{backup}/{org_id} | '
                    f'gzip -d > {backup}.{db}/{org_id}.plain && '
                    f'curl -X POST "{uri}/api/v1/import/native" '
                    f' -T {backup}.{db}/{org_id}.plain'
                )
                # print(cmd)
                os.system(cmd)
            if until:
                cmd = (
                    f"s3cmd --host={s3_host} "
                    f" --access_key={config.BACKUP['key']}"
                    f" --secret_key={config.BACKUP['secret']} ls "
                    f"s3://{config.BACKUP['bucket']}/{portal_path}{db}/ |"
                    f" grep {db}"
                )
                result = subprocess.check_output(cmd, shell=True)
                available_backups = [
                    int(l.strip().split('/victoria/')[1].rstrip('/'))
                    for l in result.decode().split('\n') if '/victoria/' in l]
                available_backups.sort(reverse=True)
                for b in available_backups:
                    if b < int(backup) and b >= int(until or 0):
                        restore_backup(b, databases=['victoria'])

            log.info('VictoriaMetrics restore finished in %s' % (
                datetime.datetime.now() - start_victoria))

        else:
            print('Unknown backup type')

    return


@dramatiq.actor
def check_periodic_tasks():
    """ Check whether the periodic tasks for recently active organizations
    are running as frequently as expected.
    """
    from mist.api.clouds.models import Cloud
    from mist.api.users.models import Organization
    # Check only recently active orgs
    timedelta = datetime.timedelta(days=10)
    orgs = Organization.objects(
        last_active__gt=datetime.datetime.now() - timedelta
    ).only("id")
    clouds = Cloud.objects(enabled=True, deleted=None, owner__in=orgs)

    tasks = {
        "list_machines": datetime.timedelta(hours=1),
        "list_locations": datetime.timedelta(days=1),
        "list_images": datetime.timedelta(days=1),
        "list_sizes": datetime.timedelta(days=1),
        "list_clusters": datetime.timedelta(hours=1),
        "list_networks": datetime.timedelta(hours=1),
        "list_volumes": datetime.timedelta(hours=1),
        "list_zones": datetime.timedelta(hours=1),
        "list_buckets": datetime.timedelta(hours=1),
    }

    error_messages = []
    title = f"[{config.PORTAL_NAME}] Periodic tasks that were not scheduled"
    for cloud in clouds:
        for task, timedelta in tasks.items():
            error_message = check_task_threshold(
                cloud=cloud, task=task, acceptable_timedelta=timedelta)
            if error_message:
                error_messages.append(error_message)

    if error_messages:
        notify_admin(title=title,
                     message="\n".join(error_messages),
                     team="ops",)
    return error_messages
