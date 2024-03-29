import copy
import errno
import json
import logging
import os
from pbr.version import VersionInfo
import requests
import time


LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


class UnconfiguredException(Exception):
    pass


class IncapableException(Exception):
    pass


class InvalidException(Exception):
    pass


class APIException(Exception):
    def __init__(self, message, method, url, status_code, text):
        self.message = message
        self.method = method
        self.url = url
        self.status_code = status_code
        self.text = text


class RequestMalformedException(APIException):
    pass


class UnauthenticatedException(APIException):
    pass


class UnauthorizedException(APIException):
    pass


class ResourceNotFoundException(APIException):
    pass


class InternalServerError(APIException):
    pass


STATUS_CODES_TO_ERRORS = {
    400: RequestMalformedException,
    401: UnauthenticatedException,
    403: UnauthorizedException,
    404: ResourceNotFoundException,
    500: InternalServerError,
}


class Client(object):
    def __init__(self, base_url=None, logger=None, verbose=False):
        global LOG
        if verbose:
            LOG.setLevel(logging.DEBUG)
        if logger:
            LOG = logger

        if not base_url:
            raise UnconfiguredException(
                'You have not specified the server to communicate with')

        self.base_url = base_url
        self.cached_auth = None

        # Request capabilities information
        self._collect_capabilities()

    def _collect_capabilities(self):
        r = requests.request(
            'GET', self.base_url, allow_redirects=True,
            headers={'Accept': 'application/json'})
        LOG.debug('Capabiltiies request returned: %s' % r.text)
        self.root_json = r.json()
        self.capabilities = self.root_json.get('capabilities', [])
        LOG.debug('Collected capabilities: %s' % self.capabilities)

    def check_capability(self, capability_string):
        return capability_string in self.capabilities

    def _actual_request_url(self, method, url, data=None,
                            allow_redirects=True):
        url = self.base_url + url

        h = {
            'Authorization': self.cached_auth,
            'User-Agent': get_user_agent(),
            'Accept': 'application/json'
            }
        if data:
            h['Content-Type'] = 'application/json'
            data = json.dumps(data, indent=4, sort_keys=True)

        start_time = time.time()
        r = requests.request(method, url, data=data, headers=h,
                             allow_redirects=allow_redirects)
        end_time = time.time()

        LOG.debug('-------------------------------------------------------')
        LOG.debug('API client requested: %s %s' % (method, url))
        if data:
            LOG.debug('Data:\n    %s' % '\n    '.join(data.split('\n')))
        for h in r.history:
            LOG.debug('URL request history: %s --> %s %s'
                      % (h.url, h.status_code, h.headers.get('Location')))
        LOG.debug('API client response: code = %s (took %.02f seconds)'
                  % (r.status_code, (end_time - start_time)))

        if r.text:
            try:
                LOG.debug('Data:\n    %s'
                            % ('\n    '.join(json.dumps(json.loads(r.text),
                                                        indent=4,
                                                        sort_keys=True).split('\n'))))
            except Exception:
                LOG.debug('Text:\n    %s'
                            % ('\n    '.join(r.text.split('\n'))))
        LOG.debug('-------------------------------------------------------')

        if r.status_code in STATUS_CODES_TO_ERRORS:
            raise STATUS_CODES_TO_ERRORS[r.status_code](
                'API request failed', method, url, r.status_code, r.text)

        acceptable = [200]
        if not allow_redirects:
            acceptable.append(301)
        if r.status_code not in acceptable:
            raise APIException(
                'API request failed', method, url, r.status_code, r.text)
        return r

    def _authenticate(self):
        LOG.debug('Authentication request made, contents not logged')
        auth_url = self.base_url + '/auth'
        r = requests.request(
            'POST', auth_url,
            data=json.dumps(
                {
                    'username': os.environ.get('OS_USERNAME', None),
                    'password': os.environ.get('OS_PASSWORD', None)
                }),
            headers={
                'Content-Type': 'application/json',
                'User-Agent': get_user_agent(),
                'Accept': 'application/json'
                })
        if r.status_code != 200:
            raise UnauthenticatedException('API unauthenticated', 'POST', auth_url,
                                           r.status_code, r.text)
        return 'Bearer %s' % r.json()['access_token']

    def _request_url(self, method, url, data=None):
        # NOTE(mikal): if we are not authenticated, probe the base_url looking
        # for redirections. If we are redirected, rewrite our base_url to the
        # redirection target.
        if not self.cached_auth:
            probe = self._actual_request_url('GET', '', allow_redirects=False)
            if probe.status_code == 301:
                LOG.debug('API server redirects to %s' % probe.headers['Location'])
                self.base_url = probe.headers['Location']
            self.cached_auth = self._authenticate()

        try:
            return self._actual_request_url(method, url, data=data)
        except UnauthenticatedException:
            self.cached_auth = self._authenticate()
            return self._actual_request_url(method, url, data=data)

    def get_sources(self):
        r = self._request_url('GET', '/source')
        return r.json()

    def get_source(self, name):
        r = self._request_url('GET', '/source/' + name)
        return r.json()

    def get_consoles(self):
        r = self._request_url('GET', '/console')
        return r.json()

    def get_console(self, source, uuid):
        r = self._request_url('GET', '/console/' + source + '/' + uuid)
        return r.json()

    def get_console_audit(self, source, uuid, limit):
        r = self._request_url('GET', '/console/' + source + '/' + uuid +
                              '/audit?limit=' + str(limit))
        return r.json()

    def get_console_direct_vv(self, source, uuid):
        r = self._request_url('GET', '/console/direct/' + source + '/' + uuid +
                              '/console.vv')
        return r.text

    def get_console_proxy_vv(self, source, uuid):
        r = self._request_url('GET', '/console/proxy/' + source + '/' + uuid +
                              '/console.vv')
        return r.text

    def console_terminate(self, source, uuid):
        r = self._request_url('GET', '/console/' + source + '/' + uuid +
                              '/terminate')
        return r.json()

    def get_sessions(self):
        r = self._request_url('GET', '/session')
        return r.json()

    def session_terminate(self, session_id):
        r = self._request_url('GET', '/session/' + session_id + '/terminate')
        return r.json()

def get_user_agent():
    ks_version = VersionInfo('kerbside_client').version_string()
    return 'Mozilla/5.0 (Ubuntu; Linux x86_64) Kerbside/%s' % ks_version