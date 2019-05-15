"""Routes and wsgi app creation"""

import os
import time
import logging
import importlib

from pyramid.config import Configurator
from pyramid.renderers import JSON

import mongoengine as me

from mist.api import config

logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)


log = logging.getLogger(__name__)


class Root(object):
    def __init__(self, request):
        self.request = request


def mongo_connect(*args, **kwargs):
    """Connect mongoengine to mongo db. This connection is reused everywhere"""
    exc = None
    for _ in range(30):
        try:
            log.info("Attempting to connect to %s at %s...", config.MONGO_DB,
                     config.MONGO_URI)
            me.connect(db=config.MONGO_DB, host=config.MONGO_URI)
        except Exception as e:
            log.warning("Error connecting to mongo, will retry in 1 sec: %r",
                        e)
            time.sleep(1)
            exc = e
        else:
            log.info("Connected...")
            break
    else:
        log.critical("Unable to connect to %s at %s: %r", config.MONGO_DB,
                     config.MONGO_URI, exc)
        raise exc


try:
    import uwsgi  # noqa
except ImportError:
    if os.getenv('CELERY_CONTEXT'):
        log.info('Celery context')
        from celery.signals import worker_process_init
        worker_process_init.connect(mongo_connect)
    else:
        log.debug('Not in uwsgi/celery context')
        mongo_connect()
else:
    log.info('Uwsgi context')
    from uwsgidecorators import postfork
    mongo_connect = postfork(mongo_connect)


def main(global_config, **settings):
    """This function returns a Pyramid WSGI application."""

    import mist.api.auth.middleware

    settings = {}

    configurator = Configurator(root_factory=Root, settings=settings)
    configurator.include('pyramid_chameleon')

    # Add custom adapter to the JSON renderer to avoid serialization errors
    json_renderer = JSON()

    def string_adapter(obj, request):
        return str(obj)

    json_renderer.add_adapter(object, string_adapter)
    configurator.add_renderer('json', json_renderer)

    # Add CSV renderer
    configurator.add_renderer('csv', 'mist.api.renderers.CSVRenderer')

    configurator.add_static_view('docs', path='../../../docs/build')

    # FIXME this should not be necessary
    social_auth_keys = {key: getattr(config, key, '')
                        for key in ('SOCIAL_AUTH_GOOGLE_OAUTH2_KEY',
                                    'SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET',
                                    'SOCIAL_AUTH_GITHUB_KEY',
                                    'SOCIAL_AUTH_GITHUB_SECRET',
                                    'SOCIAL_AUTH_INTRALOT_OAUTH2_KEY',
                                    'SOCIAL_AUTH_INTRALOT_OAUTH2_SECRET')}
    configurator.registry.settings.update(social_auth_keys)
    configurator.registry.settings.update(getattr(config,
                                                  'SOCIAL_AUTH_SETTINGS', {}))
    # /FIXME

    configurator.include(add_routes)
    configurator.scan(ignore=['mist.api.sock', 'mist.api.sockjs_mux'])

    for plugin in config.PLUGINS:
        log.info("Loading plugin mist.%s", plugin)
        configurator.include('mist.%s.add_routes' % plugin)
        ignore_modules = ['mist.%s.sock' % plugin, 'mist.%s.handler' % plugin]
        configurator.scan('mist.%s' % plugin, ignore=ignore_modules)

    app = mist.api.auth.middleware.AuthMiddleware(
        mist.api.auth.middleware.CsrfMiddleware(
            configurator.make_wsgi_app()
        )
    )

    for plugin in config.PLUGINS:
        try:
            module = importlib.import_module('mist.%s.middleware' % plugin)
            for middleware in module.CHAIN:
                app = middleware(app)
        except ImportError:
            pass

    return app


def add_routes(configurator):
    """This function defines pyramid routes.

    Takes a Configurator instance as argument and changes it's configuration.
    Any return value is ignored. This was put in a separate function so that it
    can easily be imported and extended upon.
    Just use: config.include(add_routes)

    """

    def valid_ui_section(context, request):
        ui_sections = ['clouds', 'machines', 'images', 'keys', 'scripts',
                       'templates', 'stacks', 'teams', 'networks', 'volumes',
                       'tunnels', 'members', 'insights', 'my-account',
                       'schedules', 'zones']
        landing_sections = ['about', 'product', 'pricing',
                            'sign-up', 'sign-in', 'forgot-password',
                            'buy-license', 'request-pricing', 'get-started',
                            'privacy-policy', 'pledge', 'tos',
                            'error', 'index']
        for section in ui_sections + landing_sections:
            if request.path.startswith('/' + section):
                return True
        return False

    configurator.add_route('version', '/version')

    configurator.add_route('ui_routes', '/{section}*fizzle',
                           custom_predicates=[valid_ui_section])
    configurator.add_route('home', '/')
    configurator.add_route('switch_context', '/switch_context')
    configurator.add_route('switch_context_org', '/switch_context/{org_id}')
    configurator.add_route('login', '/login')
    configurator.add_route('login_service', 'login/{service}')
    configurator.add_route('logout', '/logout')
    configurator.add_route('register', '/register')
    configurator.add_route('confirm', '/confirm')
    configurator.add_route('set_password', '/set-password')
    configurator.add_route('forgot_password', '/forgot')
    configurator.add_route('reset_password', '/reset-password')
    configurator.add_route('confirm_invitation', '/confirm-invitation')
    configurator.add_route('request_whitelist_ip', '/request-whitelist-ip')
    configurator.add_route('confirm_whitelist', '/confirm-whitelist')

    # openapi endpoint
    configurator.add_route('api_v1_spec', '/api/v1/spec')

    configurator.add_route('api_v1_section', '/api/v1/section/{section}')

    configurator.add_route('api_v1_avatars', '/api/v1/avatars')
    configurator.add_route('api_v1_avatar', '/api/v1/avatars/{avatar}')

    configurator.add_route('api_v1_providers', '/api/v1/providers')
    configurator.add_route('api_v1_clouds', '/api/v1/clouds')
    configurator.add_route('api_v1_cloud_action', '/api/v1/clouds/{cloud}')

    configurator.add_route('api_v1_machines',
                           '/api/v1/machines')

    configurator.add_route('api_v1_cloud_machines',
                           '/api/v1/clouds/{cloud}/machines')
    configurator.add_route('api_v1_cloud_machine',
                           '/api/v1/clouds/{cloud}/machines/{machine}')
    configurator.add_route('api_v1_machine',
                           '/api/v1/machines/{machine_uuid}')

    configurator.add_route('api_v1_cloud_machine_rdp',
                           '/api/v1/clouds/{cloud}/machines/{machine}/rdp')
    configurator.add_route('api_v1_machine_rdp',
                           '/api/v1/machines/{machine_uuid}/rdp')

    configurator.add_route(
        'api_v1_cloud_machine_console',
        '/api/v1/clouds/{cloud}/machines/{machine}/console'
    )
    configurator.add_route('api_v1_machine_console',
                           '/api/v1/machines/{machine_uuid}/console')

    configurator.add_route('api_v1_machine_tags',
                           '/api/v1/clouds/{cloud}/machines/{machine}/tags')
    configurator.add_route(
        'api_v1_machine_tag',
        '/api/v1/clouds/{cloud}/machines/{machine}/tags/{tag}'
    )
    configurator.add_route('api_v1_tags', '/api/v1/tags')
    configurator.add_route('cloud_tags', '/clouds/{cloud_id}/tags')
    configurator.add_route('key_tags', '/keys/{key_id}/tags')

    configurator.add_route('script_tags', '/scripts/{script_id}/tags')
    configurator.add_route('schedule_tags', '/schedules/{schedule_id}/tags')
    configurator.add_route('network_tags',
                           '/clouds/{cloud_id}/networks/{network_id}/tags')

    configurator.add_route('script_tag', '/scripts/{script_id}/tag')
    configurator.add_route('schedule_tag', '/schedules/{schedule_id}/tag')
    configurator.add_route(
        'network_tag',
        '/clouds/{cloud}/networks/{network_id}/tag/{tag_key}'
    )
    configurator.add_route('key_tag', '/keys/{key_id}/tag')
    configurator.add_route('cloud_tag', '/clouds/{cloud_id}/tag')

    configurator.add_route('machine_tag',
                           '/clouds/{cloud_id}/machines/{machine_id}/tag')

    configurator.add_route('api_v1_cloud_probe',
                           '/api/v1/clouds/{cloud}/machines/{machine}/probe')
    configurator.add_route('api_v1_probe',
                           '/api/v1/machines/{machine_uuid}/probe')

    configurator.add_route('api_v1_ping', '/api/v1/ping')

    configurator.add_route('api_v1_images', '/api/v1/clouds/{cloud}/images')
    configurator.add_route('api_v1_image',
                           '/api/v1/clouds/{cloud}/images/{image}')
    configurator.add_route('api_v1_sizes', '/api/v1/clouds/{cloud}/sizes')
    configurator.add_route('api_v1_locations',
                           '/api/v1/clouds/{cloud}/locations')

    configurator.add_route('api_v1_networks',
                           '/api/v1/clouds/{cloud}/networks')
    configurator.add_route('api_v1_network',
                           '/api/v1/clouds/{cloud}/networks/{network}')
    configurator.add_route('api_v1_subnets',
                           '/api/v1/clouds/{cloud}/networks/{network}/subnets')
    configurator.add_route(
        'api_v1_subnet',
        '/api/v1/clouds/{cloud}/networks/{network}/subnets/{subnet}'
    )

    # Volumes
    configurator.add_route(
        'api_v1_volumes',
        '/api/v1/clouds/{cloud}/volumes'
    )
    configurator.add_route(
        'api_v1_volume',
        '/api/v1/clouds/{cloud}/volumes/{volume}'
    )

    configurator.add_route('api_v1_keys', '/api/v1/keys')
    configurator.add_route('api_v1_key_action', '/api/v1/keys/{key}')
    configurator.add_route('api_v1_key_public', '/api/v1/keys/{key}/public')
    configurator.add_route('api_v1_key_private', '/api/v1/keys/{key}/private')
    configurator.add_route(
        'api_v1_cloud_key_association',
        '/api/v1/clouds/{cloud}/machines/{machine}/keys/{key}'
    )
    configurator.add_route('api_v1_key_association',
                           '/api/v1/machines/{machine_uuid}/keys/{key}')

    # Rules
    configurator.add_route('api_v1_rules', '/api/v1/rules')
    configurator.add_route('api_v1_rule', '/api/v1/rules/{rule}')
    configurator.add_route('api_v1_rule_triggered', '/api/v1/rule-triggered')

    # Metering
    configurator.add_route('api_v1_metering', '/api/v1/metering')

    # Ownership
    configurator.add_route('api_v1_ownership', '/api/v1/ownership')

    configurator.add_route('api_v1_zones',
                           '/api/v1/clouds/{cloud}/dns/zones')
    configurator.add_route('api_v1_zone',
                           '/api/v1/clouds/{cloud}/dns/zones/{zone}')
    configurator.add_route('api_v1_records',
                           '/api/v1/clouds/{cloud}/dns/zones/{zone}/records')
    configurator.add_route(
        'api_v1_record',
        '/api/v1/clouds/{cloud}/dns/zones/{zone}/records/{record}'
    )
    configurator.add_route('api_v1_cloud_zones',
                           '/api/v1/clouds/{cloud}/zones')
    configurator.add_route('api_v1_cloud_zone',
                           '/api/v1/clouds/{cloud}/zones/{zone}')
    configurator.add_route('api_v1_cloud_records',
                           '/api/v1/clouds/{cloud}/zones/{zone}/records')
    configurator.add_route(
        'api_v1_cloud_record',
        '/api/v1/clouds/{cloud}/zones/{zone}/records/{record}'
    )

    configurator.add_route('api_v1_scripts', '/api/v1/scripts')
    configurator.add_route('api_v1_script', '/api/v1/scripts/{script_id}')
    configurator.add_route('api_v1_script_file',
                           '/api/v1/scripts/{script_id}/file')
    configurator.add_route('api_v1_script_url',
                           '/api/v1/scripts/{script_id}/url')
    configurator.add_route('api_v1_fetch', '/api/v1/fetch')

    configurator.add_route('api_v1_schedules', '/api/v1/schedules')
    configurator.add_route('api_v1_schedule',
                           '/api/v1/schedules/{schedule_id}')

    configurator.add_route('api_v1_tokens', '/api/v1/tokens')
    configurator.add_route('api_v1_sessions', '/api/v1/sessions')

    configurator.add_route('api_v1_orgs', '/api/v1/orgs')
    configurator.add_route('api_v1_org', '/api/v1/org')
    configurator.add_route('api_v1_org_info', '/api/v1/org/{org_id}')

    configurator.add_route('api_v1_teams', '/api/v1/org/{org_id}/teams')
    configurator.add_route('api_v1_team',
                           '/api/v1/org/{org_id}/teams/{team_id}')

    configurator.add_route('api_v1_team_members',
                           '/api/v1/org/{org_id}/teams/{team_id}/members')

    configurator.add_route(
        'api_v1_team_member',
        '/api/v1/org/{org_id}/teams/{team_id}/members/{user_id}'
    )

    configurator.add_route('delete_account', '/delete_account/{email}')

    # Account page.
    configurator.add_route('api_v1_account', '/api/v1/account')

    configurator.add_route('api_v1_user_whitelist_ip',
                           '/api/v1/whitelist')

    # Logs & stories.
    configurator.add_route('api_v1_logs', '/api/v1/logs')
    configurator.add_route('api_v1_job', '/api/v1/jobs/{job_id}')
    configurator.add_route('api_v1_story', '/api/v1/stories/{story_id}')

    # Monitoring API endpoints.
    configurator.add_route('api_v1_home_dashboard', '/api/v1/dashboard')
    configurator.add_route(
        'api_v1_cloud_machine_dashboard',
        '/api/v1/clouds/{cloud}/machines/{machine}/dashboard')
    configurator.add_route('api_v1_machine_dashboard',
                           '/api/v1/machines/{machine_uuid}/dashboard')
    configurator.add_route('api_v1_monitoring', '/api/v1/monitoring')
    configurator.add_route(
        'api_v1_cloud_machine_monitoring',
        '/api/v1/clouds/{cloud}/machines/{machine}/monitoring')
    configurator.add_route('api_v1_machine_monitoring',
                           '/api/v1/machines/{machine_uuid}/monitoring')
    configurator.add_route(
        'api_v1_cloud_metrics',
        '/api/v1/clouds/{cloud}/machines/{machine}/metrics')
    configurator.add_route('api_v1_metrics',
                           '/api/v1/machines/{machine_uuid}/metrics')
    configurator.add_route('api_v1_metric', '/api/v1/metrics/{metric}')
    configurator.add_route(
        'api_v1_cloud_deploy_plugin',
        '/api/v1/clouds/{cloud}/machines/{machine}/plugins/{plugin}')
    configurator.add_route(
        'api_v1_deploy_plugin',
        '/api/v1/machines/{machine_uuid}/plugins/{plugin}')
    configurator.add_route(
        'api_v1_cloud_stats',
        '/api/v1/clouds/{cloud}/machines/{machine}/stats')
    configurator.add_route(
        'api_v1_stats',
        '/api/v1/machines/{machine_uuid}/stats')
    configurator.add_route('api_v1_load', '/api/v1/machines/stats/load')

    # Notifications
    configurator.add_route(
        'api_v1_dismiss_notification',
        '/api/v1/notifications/{notification_id}')
    configurator.add_route(
        'api_v1_notification_override',
        '/api/v1/notification-overrides/{override_id}')
    configurator.add_route(
        'api_v1_notification_overrides',
        '/api/v1/notification-overrides')

    # Notifications - Unsubscribe
    configurator.add_route('unsubscribe_page', '/unsubscribe')
    configurator.add_route('unsubscribe', '/api/v1/unsubscribe')

    # Notifications - Unsuppress
    configurator.add_route('suppressed', '/suppressed-alerts')

    configurator.add_route('user_invitations', '/user_invitations')

    configurator.add_route('su', '/su')

    # DEV ENDPOINT
    configurator.add_route('api_v1_dev_register', '/api/v1/dev/register')
    configurator.add_route('api_v1_dev_add_user_to_team',
                           '/api/v1/dev/orgs/{org_id}/teams/{team_id}')
    configurator.add_route('api_v1_dev_users', '/api/v1/dev/users')
