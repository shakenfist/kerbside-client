import json
import logging
import os
import sys
import types
from unittest import mock

import kerbside_client
from kerbside_client import apiclient
from kerbside_client.tests.unit import base


BASE_URL = 'http://kerbside.example.com/api'


class ClientConstructionTestCase(base.ApiClientStateTestCase):
    def test_no_base_url_raises(self):
        self.assertRaises(apiclient.UnconfiguredException, apiclient.Client)

    def test_empty_base_url_raises(self):
        # --apiurl '' and an empty KERBSIDE_API_URL both arrive here as
        # the empty string, not as None.
        self.assertRaises(
            apiclient.UnconfiguredException, apiclient.Client, base_url='')

    def test_capabilities_collected_on_construction(self):
        with mock.patch('kerbside_client.apiclient.requests.request') as r:
            r.return_value = base.FakeResponse(
                body={'capabilities': ['consoles', 'sessions']})
            c = apiclient.Client(base_url=BASE_URL)

        # The capability probe follows redirects and asks for JSON, and
        # it is the only request construction makes.
        r.assert_called_once_with(
            'GET', BASE_URL, allow_redirects=True,
            headers={'Accept': 'application/json'})
        self.assertEqual(['consoles', 'sessions'], c.capabilities)
        self.assertEqual({'capabilities': ['consoles', 'sessions']}, c.root_json)
        self.assertIsNone(c.cached_auth)

    def test_capabilities_absent_is_empty_list(self):
        # An older server which does not advertise capabilities at all
        # must not break the client, it just has no capabilities.
        c = self._client(body={'version': 1})
        self.assertEqual([], c.capabilities)
        self.assertFalse(c.check_capability('consoles'))

    def test_check_capability(self):
        c = self._client(body={'capabilities': ['consoles']})
        self.assertTrue(c.check_capability('consoles'))
        self.assertFalse(c.check_capability('sessions'))

    def test_verbose_sets_debug_logging(self):
        apiclient.LOG.setLevel(logging.INFO)
        self._client(verbose=True)
        self.assertEqual(logging.DEBUG, apiclient.LOG.level)

    def test_logger_replaces_the_module_logger(self):
        # The CLI hands its console logger in, and the client installs
        # it as the module global rather than keeping it per instance.
        logger = logging.getLogger('test-replacement-logger')
        self._client(logger=logger)
        self.assertIs(logger, apiclient.LOG)

    def _client(self, body=None, **kwargs):
        with mock.patch('kerbside_client.apiclient.requests.request') as r:
            r.return_value = base.FakeResponse(body=body or {'capabilities': []})
            return apiclient.Client(base_url=BASE_URL, **kwargs)


class ClientTestCase(base.ApiClientStateTestCase):
    """Base class for tests against an already constructed client."""

    def setUp(self):
        super().setUp()

        with mock.patch('kerbside_client.apiclient.requests.request') as r:
            r.return_value = base.FakeResponse(body={'capabilities': []})
            self.client = apiclient.Client(base_url=BASE_URL)

        # Pretend we have already authenticated, so that the tests below
        # exercise the request path rather than the login path. The
        # tests which care about authentication clear this.
        self.client.cached_auth = 'Bearer cached-token'

    def request(self, *responses):
        """Patch requests.request to return each response in turn."""
        patcher = mock.patch('kerbside_client.apiclient.requests.request')
        r = patcher.start()
        self.addCleanup(patcher.stop)
        r.side_effect = list(responses)
        return r


class ActualRequestUrlTestCase(ClientTestCase):
    def test_url_is_appended_to_base_url(self):
        r = self.request(base.FakeResponse(body={}))
        self.client._actual_request_url('GET', '/source')
        self.assertEqual(BASE_URL + '/source', r.call_args[0][1])

    def test_headers(self):
        r = self.request(base.FakeResponse(body={}))
        self.client._actual_request_url('GET', '/source')

        headers = r.call_args[1]['headers']
        self.assertEqual('Bearer cached-token', headers['Authorization'])
        self.assertEqual('application/json', headers['Accept'])
        self.assertIn('Kerbside/', headers['User-Agent'])
        # No body, so nothing claims to be sending JSON.
        self.assertNotIn('Content-Type', headers)
        self.assertIsNone(r.call_args[1]['data'])

    def test_data_is_serialised_as_sorted_json(self):
        r = self.request(base.FakeResponse(body={}))
        self.client._actual_request_url('POST', '/source', data={'b': 2, 'a': 1})

        self.assertEqual(
            'application/json', r.call_args[1]['headers']['Content-Type'])
        self.assertEqual(
            {'a': 1, 'b': 2}, json.loads(r.call_args[1]['data']))

    def test_returns_the_response(self):
        response = base.FakeResponse(body={'hello': 'world'})
        self.request(response)
        self.assertIs(
            response, self.client._actual_request_url('GET', '/source'))

    def test_redirects_followed_by_default(self):
        r = self.request(base.FakeResponse(body={}))
        self.client._actual_request_url('GET', '/source')
        self.assertTrue(r.call_args[1]['allow_redirects'])

    def test_non_json_body_is_logged_without_raising(self):
        # The debug logging pretty prints a JSON body and falls back to
        # the raw text for anything else. .vv files take that path.
        apiclient.LOG.setLevel(logging.DEBUG)
        self.request(base.FakeResponse(text='[virt-viewer]\ntype=spice\n'))
        r = self.client._actual_request_url('GET', '/console/a/b/console.vv')
        self.assertIn('virt-viewer', r.text)

    def test_response_history_is_logged(self):
        apiclient.LOG.setLevel(logging.DEBUG)
        hop = base.FakeResponse(
            status_code=301, headers={'Location': BASE_URL + '/v2'})
        hop.url = BASE_URL
        self.request(base.FakeResponse(body={}, history=[hop]))
        self.client._actual_request_url('GET', '/source')


class StatusCodeTestCase(ClientTestCase):
    def test_mapped_status_codes_raise_their_exception(self):
        for status_code, expected in apiclient.STATUS_CODES_TO_ERRORS.items():
            self.request(base.FakeResponse(status_code=status_code, text='boom'))
            e = self.assertRaises(
                expected, self.client._actual_request_url, 'GET', '/source')
            self.assertEqual('API request failed', e.message)
            self.assertEqual('GET', e.method)
            self.assertEqual(BASE_URL + '/source', e.url)
            self.assertEqual(status_code, e.status_code)
            self.assertEqual('boom', e.text)

    def test_the_mapping_covers_the_codes_the_server_returns(self):
        self.assertEqual(
            {400: apiclient.RequestMalformedException,
             401: apiclient.UnauthenticatedException,
             403: apiclient.UnauthorizedException,
             404: apiclient.ResourceNotFoundException,
             500: apiclient.InternalServerError},
            apiclient.STATUS_CODES_TO_ERRORS)

    def test_every_mapped_exception_is_an_apiexception(self):
        # main.GroupCatchExceptions catches these by name, so each one
        # has to carry the .text attribute APIException defines.
        for expected in apiclient.STATUS_CODES_TO_ERRORS.values():
            self.assertTrue(issubclass(expected, apiclient.APIException))

    def test_unmapped_failure_raises_the_base_exception(self):
        # 502 and 503 are what a proxy in front of the API returns when
        # the API itself is down, and neither is in the mapping.
        self.request(base.FakeResponse(status_code=503, text='unavailable'))
        e = self.assertRaises(
            apiclient.APIException, self.client._actual_request_url, 'GET', '/source')
        self.assertEqual(503, e.status_code)

    def test_200_is_accepted(self):
        self.request(base.FakeResponse(status_code=200, body={}))
        self.client._actual_request_url('GET', '/source')

    def test_301_is_rejected_when_following_redirects(self):
        self.request(base.FakeResponse(status_code=301, text=''))
        self.assertRaises(
            apiclient.APIException, self.client._actual_request_url, 'GET', '')

    def test_301_is_accepted_when_not_following_redirects(self):
        # This is the one caller that wants to see the redirect itself:
        # the probe in _request_url rewrites base_url from it.
        response = base.FakeResponse(
            status_code=301, headers={'Location': 'http://elsewhere/api'})
        self.request(response)
        self.assertIs(
            response,
            self.client._actual_request_url('GET', '', allow_redirects=False))


class AuthenticateTestCase(ClientTestCase):
    def test_credentials_come_from_the_environment(self):
        r = self.request(base.FakeResponse(body={'access_token': 'tok'}))
        with mock.patch.dict(os.environ,
                             {'OS_USERNAME': 'banana', 'OS_PASSWORD': 'sekrit'}):
            auth = self.client._authenticate()

        self.assertEqual('Bearer tok', auth)
        self.assertEqual('POST', r.call_args[0][0])
        self.assertEqual(BASE_URL + '/auth', r.call_args[0][1])
        self.assertEqual(
            {'username': 'banana', 'password': 'sekrit'},
            json.loads(r.call_args[1]['data']))

    def test_authentication_request_is_not_authenticated(self):
        # Nothing to authenticate with yet, so no Authorization header.
        r = self.request(base.FakeResponse(body={'access_token': 'tok'}))
        self.client._authenticate()
        self.assertNotIn('Authorization', r.call_args[1]['headers'])
        self.assertIn('Kerbside/', r.call_args[1]['headers']['User-Agent'])

    def test_missing_credentials_are_sent_as_null(self):
        # Documented rather than endorsed: with OS_USERNAME unset the
        # client posts a null username and lets the server reject it,
        # so the error the user sees comes from the server.
        r = self.request(base.FakeResponse(status_code=401, text='nope'))
        env = {k: v for k, v in os.environ.items()
               if k not in ('OS_USERNAME', 'OS_PASSWORD')}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertRaises(
                apiclient.UnauthenticatedException, self.client._authenticate)
        self.assertEqual(
            {'username': None, 'password': None},
            json.loads(r.call_args[1]['data']))

    def test_failure_raises_unauthenticated(self):
        self.request(base.FakeResponse(status_code=401, text='denied'))
        e = self.assertRaises(
            apiclient.UnauthenticatedException, self.client._authenticate)
        self.assertEqual('API unauthenticated', e.message)
        self.assertEqual('POST', e.method)
        self.assertEqual(BASE_URL + '/auth', e.url)
        self.assertEqual(401, e.status_code)
        self.assertEqual('denied', e.text)

    def test_non_401_failure_also_raises_unauthenticated(self):
        # _authenticate() checks for "not 200" rather than for 401, so a
        # 500 from /auth is reported as an authentication failure too.
        self.request(base.FakeResponse(status_code=500, text='bang'))
        e = self.assertRaises(
            apiclient.UnauthenticatedException, self.client._authenticate)
        self.assertEqual(500, e.status_code)


class RequestUrlTestCase(ClientTestCase):
    def setUp(self):
        super().setUp()
        self.client.cached_auth = None

    def test_first_request_probes_authenticates_then_requests(self):
        r = self.request(
            base.FakeResponse(status_code=200, body={}),              # probe
            base.FakeResponse(body={'access_token': 'fresh'}),        # auth
            base.FakeResponse(body={'result': 'ok'}))                 # request

        self.assertEqual({'result': 'ok'}, self.client._request_url('GET', '/x').json())
        self.assertEqual(3, r.call_count)

        # The probe asks the base URL itself, with redirects disabled.
        self.assertEqual(('GET', BASE_URL), r.call_args_list[0][0])
        self.assertFalse(r.call_args_list[0][1]['allow_redirects'])

        # And the real request carries the token the login returned.
        self.assertEqual(
            'Bearer fresh',
            r.call_args_list[2][1]['headers']['Authorization'])

    def test_a_301_probe_rewrites_the_base_url(self):
        moved = 'https://kerbside.example.com/api'
        self.request(
            base.FakeResponse(status_code=301, headers={'Location': moved}),
            base.FakeResponse(body={'access_token': 'fresh'}),
            base.FakeResponse(body={}))

        self.client._request_url('GET', '/x')
        self.assertEqual(moved, self.client.base_url)

    def test_a_200_probe_leaves_the_base_url_alone(self):
        self.request(
            base.FakeResponse(status_code=200, body={}),
            base.FakeResponse(body={'access_token': 'fresh'}),
            base.FakeResponse(body={}))

        self.client._request_url('GET', '/x')
        self.assertEqual(BASE_URL, self.client.base_url)

    def test_an_authenticated_client_does_not_probe(self):
        self.client.cached_auth = 'Bearer cached-token'
        r = self.request(base.FakeResponse(body={}))
        self.client._request_url('GET', '/x')
        self.assertEqual(1, r.call_count)

    def test_a_401_reauthenticates_once_and_retries(self):
        self.client.cached_auth = 'Bearer stale'
        r = self.request(
            base.FakeResponse(status_code=401, text='expired'),   # the request
            base.FakeResponse(body={'access_token': 'fresh'}),    # re-auth
            base.FakeResponse(body={'result': 'ok'}))             # the retry

        self.assertEqual({'result': 'ok'}, self.client._request_url('GET', '/x').json())
        self.assertEqual(
            'Bearer stale', r.call_args_list[0][1]['headers']['Authorization'])
        self.assertEqual(
            'Bearer fresh', r.call_args_list[2][1]['headers']['Authorization'])

    def test_a_second_401_propagates(self):
        # One retry, not a loop: if the freshly minted token is also
        # rejected the caller sees the failure.
        self.client.cached_auth = 'Bearer stale'
        r = self.request(
            base.FakeResponse(status_code=401, text='expired'),
            base.FakeResponse(body={'access_token': 'fresh'}),
            base.FakeResponse(status_code=401, text='still no'))

        self.assertRaises(
            apiclient.UnauthenticatedException,
            self.client._request_url, 'GET', '/x')
        self.assertEqual(3, r.call_count)

    def test_other_errors_are_not_retried(self):
        self.client.cached_auth = 'Bearer cached-token'
        r = self.request(base.FakeResponse(status_code=403, text='nope'))
        self.assertRaises(
            apiclient.UnauthorizedException, self.client._request_url, 'GET', '/x')
        self.assertEqual(1, r.call_count)


class EndpointTestCase(ClientTestCase):
    # Every public method of Client, the request it makes, and whether
    # it hands back decoded JSON or the raw body.
    ENDPOINTS = [
        ('get_sources', (), 'GET', '/source', 'json'),
        ('get_source', ('ovirt',), 'GET', '/source/ovirt', 'json'),
        ('get_consoles', (), 'GET', '/console', 'json'),
        ('get_console', ('ovirt', 'uuid1'), 'GET', '/console/ovirt/uuid1', 'json'),
        ('get_console_audit', ('ovirt', 'uuid1', 50), 'GET',
         '/console/ovirt/uuid1/audit?limit=50', 'json'),
        ('get_console_direct_vv', ('ovirt', 'uuid1'), 'GET',
         '/console/direct/ovirt/uuid1/console.vv', 'text'),
        ('get_console_proxy_vv', ('ovirt', 'uuid1'), 'GET',
         '/console/proxy/ovirt/uuid1/console.vv', 'text'),
        ('console_terminate', ('ovirt', 'uuid1'), 'GET',
         '/console/ovirt/uuid1/terminate', 'json'),
        ('get_sessions', (), 'GET', '/session', 'json'),
        ('session_terminate', ('sess1',), 'GET', '/session/sess1/terminate', 'json'),
    ]

    def test_endpoints(self):
        for name, args, method, url, kind in self.ENDPOINTS:
            if kind == 'json':
                response = base.FakeResponse(body={'called': name})
                expected = {'called': name}
            else:
                response = base.FakeResponse(text='[virt-viewer]\n')
                expected = '[virt-viewer]\n'

            r = self.request(response)
            self.assertEqual(
                expected, getattr(self.client, name)(*args),
                'wrong return value from %s' % name)
            self.assertEqual(
                (method, BASE_URL + url), r.call_args[0],
                'wrong request from %s' % name)

    def test_every_public_method_is_covered(self):
        # A new endpoint added to Client without a row above fails here
        # rather than going untested.
        public = set()
        for name in dir(apiclient.Client):
            if name.startswith('_'):
                continue
            if not callable(getattr(apiclient.Client, name)):
                continue
            public.add(name)

        self.assertEqual(
            {'check_capability'} | {row[0] for row in self.ENDPOINTS}, public)

    def test_audit_limit_is_stringified(self):
        # The limit arrives from click as an int and is concatenated
        # into the query string, so it has to survive str().
        r = self.request(base.FakeResponse(body={}))
        self.client.get_console_audit('ovirt', 'uuid1', 200)
        self.assertTrue(r.call_args[0][1].endswith('/audit?limit=200'))

    def test_path_components_are_not_url_escaped(self):
        # Documenting current behaviour, not endorsing it: a source name
        # or console uuid is interpolated into the path verbatim, so a
        # value containing a slash or a query separator changes which
        # endpoint is called. Every value in practice comes from the
        # server's own listing, which is why this has not bitten.
        r = self.request(base.FakeResponse(body={}))
        self.client.get_source('one/../two')
        self.assertEqual(BASE_URL + '/source/one/../two', r.call_args[0][1])


class UserAgentTestCase(base.ApiClientStateTestCase):
    def setUp(self):
        super().setUp()
        apiclient.VERSION_CACHE = None

    def _hide_version_module(self):
        """Make "from kerbside_client import _version" raise ImportError.

        Both halves are needed. Once the submodule has been imported
        once -- and a tree that has been pip installed has been built,
        so it has been -- the import statement finds it as an attribute
        of the package and never consults sys.modules, so the attribute
        has to go too. The None in sys.modules is what stops the import
        machinery loading _version.py from disk again.
        """
        missing = object()
        existing = getattr(kerbside_client, '_version', missing)
        if existing is not missing:
            delattr(kerbside_client, '_version')
            self.addCleanup(setattr, kerbside_client, '_version', existing)

        patcher = mock.patch.dict(sys.modules, {'kerbside_client._version': None})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _fake_version_module(self, version):
        module = types.ModuleType('kerbside_client._version')
        module.version = version
        patcher = mock.patch.object(
            kerbside_client, '_version', module, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_without_a_version_module(self):
        # A checkout that has never been built has no _version.py, and
        # the user agent says so rather than failing.
        self._hide_version_module()
        self.assertEqual(
            'Mozilla/5.0 (Ubuntu; Linux x86_64) '
            'Kerbside/unreleased development version',
            apiclient.get_user_agent())

    def test_with_a_version_module(self):
        self._fake_version_module('1.2.3')
        self.assertEqual(
            'Mozilla/5.0 (Ubuntu; Linux x86_64) Kerbside/1.2.3',
            apiclient.get_user_agent())

    def test_the_version_is_cached(self):
        self._fake_version_module('1.2.3')
        apiclient.get_user_agent()
        self.assertEqual('1.2.3', apiclient.VERSION_CACHE)

        # The module is unreachable now, and the cached value is still
        # what the user agent reports: the import happens once per
        # process, not once per request.
        self._hide_version_module()
        self.assertEqual(
            'Mozilla/5.0 (Ubuntu; Linux x86_64) Kerbside/1.2.3',
            apiclient.get_user_agent())
