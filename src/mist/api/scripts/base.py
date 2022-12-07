import logging
import requests
import datetime

import urllib.request
import urllib.parse
import urllib.error

import mongoengine as me

from time import time

from mist.api.exceptions import BadRequestError
from mist.api.helpers import trigger_session_update, mac_sign
from mist.api.helpers import RabbitMQStreamConsumer
from mist.api.exceptions import ScriptNameExistsError

from mist.api import config


log = logging.getLogger(__name__)


class BaseScriptController(object):
    def __init__(self, script):
        """Initialize a script controller given a script

        Most times one is expected to access a controller from inside the
        script, like this:

            script = mist.api.scripts.models.Script.objects.get(id=script.id)
            script.ctl.edit('renamed')
        """
        self.script = script

    def add(self, fail_on_invalid_params=False, **kwargs):
        """Add an entry to the database

        This is only to be called by `Script.add` classmethod to create
        a script. Fields `owner` and `name` are already populated in
        `self.script`. The `self.script` is not yet saved.
        """

        import mist.api.scripts.models as scripts

        # set description
        self.script.description = kwargs.pop('description', '')

        # set location
        location_type = kwargs.pop('location_type')
        if location_type not in ['inline', 'url', 'github']:
            raise BadRequestError('location type must be one of these: '
                                  '(inline, github, url)]')

        entrypoint = kwargs.pop('entrypoint', '')

        if location_type == 'inline':
            script_entry = kwargs.pop('script' '')
            self.script.location = scripts.InlineLocation(
                source_code=script_entry)
        elif location_type == 'github':
            script_entry = kwargs.pop('script', '')
            self.script.location = scripts.GithubLocation(
                repo=script_entry, entrypoint=entrypoint)
        elif location_type == 'url':
            script_entry = kwargs.pop('script', '')
            self.script.location = scripts.UrlLocation(
                url=script_entry, entrypoint=entrypoint)
        else:
            raise BadRequestError("Param 'location_type' must be in "
                                  "('url', 'github', 'inline').")

        # specific check
        self._preparse_file()

        errors = {}
        for key in list(kwargs.keys()):
            if key not in self.script._script_specific_fields:
                error = "Invalid parameter %s=%r." % (key, kwargs[key])
                if fail_on_invalid_params:
                    errors[key] = error
                else:
                    log.warning(error)
                    kwargs.pop(key)

        if errors:
            log.error("Error adding %s: %s", self.script, errors)
            raise BadRequestError({
                'msg': "Invalid parameters %s." % list(errors.keys()),
                'errors': errors,
            })

        for key, value in kwargs.items():
            setattr(self.script, key, value)

        try:
            self.script.save()
        except me.ValidationError as exc:
            log.error("Error adding %s: %s", self.script.name, exc.to_dict())
            raise BadRequestError({'msg': str(exc),
                                   'errors': exc.to_dict()})
        except me.NotUniqueError as exc:
            log.error("Script %s not unique error: %s", self.script.name, exc)
            raise ScriptNameExistsError()
        self.script.owner.mapper.update(self.script)
        log.info("Added script with name '%s'", self.script.name)
        trigger_session_update(self.script.owner, ['scripts'])

    def edit(self, name=None, description=None):
        """Edit name or description of an existing script"""
        log.info("Edit script '%s''.", self.script.name)

        if name:
            self.script.name = name
        if description:
            self.script.description = description
        self.script.save()
        log.info("Edit script: '%s'.", self.script.id)
        trigger_session_update(self.script.owner, ['scripts'])

    def delete(self, expire=False):
        """ Delete a script

        By default the corresponding mongodb document is not actually
        deleted, but rather marked as deleted.

        :param expire: if True, the document is expires from the collection.
        """

        self.script.deleted = datetime.datetime.utcnow()
        self.script.save()
        if expire:
            self.script.delete()
        trigger_session_update(self.script.owner, ['scripts'])

    def _url(self):
        redirect_url = ''
        if self.script.location.type == 'github':
            token = config.GITHUB_BOT_TOKEN
            if token:
                headers = {'Authorization': 'token %s' % token}
            else:
                headers = {}

            path = self.script.location.repo.replace(
                'https://github.com/', '')

            if '/tree/' in path:
                [path, branch] = path.split('/tree/')
            else:
                api_url = 'https://api.github.com/repos/%s' % path
                resp = requests.get(api_url, headers=headers,
                                    allow_redirects=False)
                if resp.ok:
                    branch = resp.json().get('default_branch')
                else:
                    log.error('Failed to fetch default branch %r', resp)
                    branch = 'master'

            api_url = 'https://api.github.com/repos/%s/tarball/%s' % (
                path, branch)

            resp = requests.get(api_url, headers=headers,
                                allow_redirects=False)
            if resp.ok and resp.is_redirect and 'location' in resp.headers:
                redirect_url = resp.headers['location']
            else:
                log.error('%d: Could not retrieve your file: %s',
                          resp.status_code, resp.content)
                raise BadRequestError('%d: Could not retrieve your file: %s'
                                      % (resp.status_code, resp.content))
        else:
            redirect_url = self.script.location.url
        return redirect_url

    def get_file(self):
        """Return a file along with HTTP response parameters."""

        if self.script.location.type == 'inline':
            return dict(content_type='text/plain', charset='utf-8',
                        body=self.script.location.source_code)
        else:
            # Download a file over HTTP
            url = self._url()
            log.debug("Downloading %s.", url)
            try:
                r = requests.get(url)
                r.raise_for_status()
            except requests.exceptions.HTTPError as err:
                raise BadRequestError(err.msg)

            if 'gzip' in r.headers['Content-Type']:
                if r.headers.get('content-disposition', ''):
                    filename = r.headers.get(
                        'content-disposition').split("=", 1)[1]
                else:
                    filename = "script.tar.gz"

                return dict(content_type=r.headers['Content-Type'],
                            content_disposition='attachment; '
                            'filename=%s' %
                            filename,
                            charset='utf8',
                            pragma='no-cache',
                            body=r.content)
            else:
                return dict(content_type=r.headers['Content-Type'],
                            content_disposition='attachment; '
                            'filename="script.gzip"',
                            charset='utf8',
                            pragma='no-cache',
                            body=r.content)

    def generate_signed_url(self):
        # build HMAC and inject into the `curl` command
        hmac_params = {'action': 'fetch_script', 'object_id': self.script.id}
        expires_in = 60 * 15
        mac_sign(hmac_params, expires_in)
        url = "%s/api/v1/fetch" % config.PORTAL_URI
        encode_params = urllib.parse.urlencode(hmac_params)
        return url + '?' + encode_params

    def generate_signed_url_v2(self):
        # build HMAC and inject into the `curl` command
        script_id = self.script.id
        hmac_params = {'object_id': script_id}
        expires_in = 60 * 15
        mac_sign(hmac_params, expires_in)
        url = f'{config.PORTAL_URI}/api/v2/scripts/{script_id}/file'
        encode_params = urllib.parse.urlencode(hmac_params)
        return url + '?' + encode_params

    def run(self, auth_context, machine, host=None, port=None, username=None,
            password=None, su=False, key_id=None, params=None, job_id=None,
            env='', owner=None, ret=None, action_prefix=None):
        from mist.api.users.models import Organization
        from mist.api.machines.methods import prepare_ssh_dict
        import re
        if auth_context:
            owner = auth_context.owner

        assert isinstance(owner, Organization)

        url = self.generate_signed_url()
        tmp_dir = '/tmp/script-%s-%s-XXXX' % (self.script.id, job_id)
        sudo = 'sudo ' if su else ''
        if env:
            env_str = '&& '.join([f"export {kv} " for kv in env.split('\n')])
            env_str += ' && ' if env_str else ''
        else:
            env_str = ''
        entrypoint = getattr(self.script.location, 'entrypoint', 'main')
        command = (
            f'{env_str}'
            'fetchrun() {'
            f'  TMP_DIR=$(mktemp -d {tmp_dir}) && '
            f'  cd $TMP_DIR && '
            f'  command -v curl > /dev/null 2>&1 && DLCMD="curl -o "'
            f'  || DLCMD="wget -O " && '
            f'  $DLCMD ./script "{url}" > /dev/null 2>&1 && '
            f'  (unzip ./script > /dev/null 2>&1 || '
            f'   tar xvzf ./script > /dev/null 2>&1); '
            f'  (chmod +x ./*/{entrypoint}  > /dev/null 2>&1 && '
            f'   {sudo} ./*/{entrypoint} {params}) ||'
            f'  (chmod +x ./script && '
            f'   {sudo} ./script {params});'
            f'  retval="$?";'
            f'  rm -rf $TMP_DIR; echo retval:$retval;'
            f'  cd - > /dev/null 2>&1;'
            f'  return "$retval";'
            '} && fetchrun'
        )
        log.info('Preparing ssh dict')
        ssh_dict, key_name = prepare_ssh_dict(
            auth_context=auth_context, machine=machine,
            command=command)
        sendScriptURI = '%s/ssh/jobs/%s' % (
            config.PORTAL_URI,
            job_id
        )
        log.info('Sending request to sheller:: %s' % sendScriptURI)
        log.info(ssh_dict)
        start = time()
        resp = requests.post(sendScriptURI, json=ssh_dict)
        log.info('Sheller returned %s in %d' % (
            resp.status_code, time() - start))
        exit_code, stdout = 1, ""
        if resp.status_code == 200:
            from mist.api.logs.methods import log_event
            log_event(
                event_type='job',
                action=action_prefix + 'script_started',
                **ret
            )
            log.info('Script started: %s' % ret)
            # start reading from rabbitmq-stream
            c = RabbitMQStreamConsumer(job_id)
            log.info("reading logs from rabbitmq-stream of job_id:%s" % job_id)
            exit_code, stdout = c.consume()
        return {
            'command': command,
            'exit_code': exit_code,
            'stdout': re.sub(r"(\n)\1+", r"\1", stdout.replace(
                '\r\n', '\n').replace('\r', '\n')),
            'key_name': key_name,
            'ssh_user': ssh_dict["user"],
        }

    def _preparse_file(self):
        return
