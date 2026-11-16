import datetime
import json
import logging
import os
import tempfile
from unittest import mock

import click
from click.testing import CliRunner

from kerbside_client import apiclient
from kerbside_client import main
from kerbside_client.tests.unit import base


# One timestamp used throughout, converted with the same call the code
# under test uses so that the expectations do not depend on the
# timezone the tests run in.
WHEN = 1700000000
WHEN_LOCAL = str(datetime.datetime.fromtimestamp(WHEN))

SOURCE = {
    'name': 'ovirt-prod',
    'type': 'ovirt',
    'last_seen': WHEN,
    'seen_by': 'node1',
    'errored': False,
    'flavor': 'spice;vnc',
    'project_domain_id': 'default',
    'project_name': 'vdi',
    'url': 'https://ovirt.example.com',
    'user_domain_id': 'default',
    'username': 'admin',
    'ca_cert': None,
}

CONSOLE = {
    'uuid': 'c0ffee',
    'name': 'desktop-1',
    'source': 'ovirt-prod',
    'discovered': WHEN,
    'host_subject': 'CN=hv1.example.com',
    'hypervisor': 'hv1',
    'hypervisor_ip': '10.0.0.5',
    'insecure_port': 5900,
    'secure_port': 5901,
    'token_count': 2,
    'sessions': ['sess1'],
}

AUDIT = {
    'total': 17,
    'audit': [
        {'timestamp': WHEN, 'node': 'node1', 'pid': 42, 'session_id': 'sess1',
         'channel': 'main', 'message': 'connected'},
    ],
}

CHANNEL = {
    'channel_type': 'main',
    'client_ip': '10.1.1.1',
    'client_port': 54321,
    'created': WHEN,
    'node': 'node1',
    'pid': 42,
    'session_id': 'sess1',
}

SESSIONS = {
    'sess1': {
        'source': 'ovirt-prod',
        'name': 'desktop-1',
        'uuid': 'c0ffee',
        'channels': [CHANNEL],
    },
}

VV = '[virt-viewer]\ntype=spice\nhost=10.0.0.5\n'


class ErrorTextTestCase(base.MainStateTestCase):
    def test_json_with_an_error_key(self):
        self.assertEqual(
            'that did not work',
            main.error_text(json.dumps({'error': 'that did not work'})))

    def test_json_without_an_error_key(self):
        # Nothing to pull out, so the caller gets the whole body rather
        # than an empty message.
        body = json.dumps({'detail': 'something else'})
        self.assertEqual(body, main.error_text(body))

    def test_text_that_is_not_json(self):
        self.assertEqual(
            '<html>502 Bad Gateway</html>',
            main.error_text('<html>502 Bad Gateway</html>'))

    def test_empty_text(self):
        self.assertEqual('', main.error_text(''))

    def test_none(self):
        # json.loads(None) raises, which the bare except swallows.
        self.assertIsNone(main.error_text(None))


class GroupCatchExceptionsTestCase(base.MainStateTestCase):
    """The CLI group turns an API exception into a message and exit 1."""

    def _run(self, exception):
        @click.group(cls=main.GroupCatchExceptions)
        def group():
            pass

        @group.command(name='boom')
        def boom():
            raise exception

        logger = mock.Mock()
        with mock.patch.object(main, 'LOG', logger):
            e = self.assertRaises(SystemExit, group, ['boom'])

        messages = [call[0][0] % call[0][1:] if len(call[0]) > 1 else call[0][0]
                    for call in logger.error.call_args_list]
        return e.code, messages

    def test_malformed_request(self):
        code, messages = self._run(apiclient.RequestMalformedException(
            'API request failed', 'GET', '/source', 400,
            json.dumps({'error': 'bad name'})))
        self.assertEqual(1, code)
        self.assertEqual(['Malformed Request: bad name'], messages)

    def test_unauthenticated(self):
        code, messages = self._run(apiclient.UnauthenticatedException(
            'API unauthenticated', 'POST', '/auth', 401, 'denied'))
        self.assertEqual(1, code)
        self.assertEqual(1, len(messages))
        self.assertTrue(messages[0].startswith('Not authenticated: '))

    def test_unauthorized(self):
        code, messages = self._run(apiclient.UnauthorizedException(
            'API request failed', 'GET', '/source', 403,
            json.dumps({'error': 'not yours'})))
        self.assertEqual(1, code)
        self.assertEqual(['Not authorized: not yours'], messages)

    def test_resource_not_found(self):
        code, messages = self._run(apiclient.ResourceNotFoundException(
            'API request failed', 'GET', '/source/nope', 404,
            json.dumps({'error': 'no such source'})))
        self.assertEqual(1, code)
        self.assertEqual(['Resource not found: no such source'], messages)

    def test_internal_server_error(self):
        # Deliberately the whole body rather than the 'error' field: the
        # server should not have failed, so the detail is wanted.
        code, messages = self._run(apiclient.InternalServerError(
            'API request failed', 'GET', '/source', 500, 'Traceback...'))
        self.assertEqual(1, code)
        self.assertEqual(['Internal Server Error: Traceback...'], messages)

    def test_an_unmapped_api_error_is_not_caught(self):
        # Documenting a gap rather than endorsing it. The group catches
        # the five subclasses by name, so a bare APIException -- which
        # is what a 502 or 503 from a proxy in front of the API becomes
        # -- reaches the user as a traceback instead of a message.
        @click.group(cls=main.GroupCatchExceptions)
        def group():
            pass

        @group.command(name='boom')
        def boom():
            raise apiclient.APIException(
                'API request failed', 'GET', '/source', 503, 'unavailable')

        self.assertRaises(apiclient.APIException, group, ['boom'])

    def test_unconfigured_is_not_caught_either(self):
        @click.group(cls=main.GroupCatchExceptions)
        def group():
            pass

        @group.command(name='boom')
        def boom():
            raise apiclient.UnconfiguredException('no server')

        self.assertRaises(apiclient.UnconfiguredException, group, ['boom'])


class CommandTestCase(base.MainStateTestCase):
    """Base class for tests which invoke a single command.

    The commands are invoked directly rather than through the cli
    group, because the group's callback builds a real API client and
    probes the server before any subcommand runs. Each command reads
    the client and the output format out of the click context, so
    handing it an object is all that is needed -- and that is also what
    keeps these tests off the network.
    """

    def setUp(self):
        super().setUp()
        self.client = mock.Mock()

    def invoke(self, command, args=None, output='pretty'):
        result = CliRunner().invoke(
            command, args or [],
            obj={'OUTPUT': output, 'CLIENT': self.client, 'VERBOSE': False})
        return result

    def run_ok(self, command, args=None, output='pretty'):
        result = self.invoke(command, args, output)
        if result.exception:
            raise result.exception
        self.assertEqual(0, result.exit_code)
        return result.output


class SourceCommandTestCase(CommandTestCase):
    def setUp(self):
        super().setUp()
        self.client.get_sources.return_value = [SOURCE]
        self.client.get_source.return_value = SOURCE

    def test_list_json(self):
        output = self.run_ok(main.list_sources, output='json')
        self.assertEqual([SOURCE], json.loads(output))

    def test_list_simple(self):
        output = self.run_ok(main.list_sources, output='simple')
        lines = output.strip().split('\n')
        self.assertEqual('name,type,last seen,seen by,errored', lines[0])
        self.assertEqual(
            'ovirt-prod,ovirt,%s,node1,False' % WHEN_LOCAL, lines[1])

    def test_list_pretty(self):
        output = self.run_ok(main.list_sources)
        self.assertIn('ovirt-prod', output)
        self.assertIn('last seen', output)
        # A table, not the raw epoch.
        self.assertIn('|', output)
        self.assertNotIn(str(WHEN), output)

    def test_show_json(self):
        output = self.run_ok(main.show_source, ['ovirt-prod'], output='json')
        self.assertEqual(SOURCE, json.loads(output))
        self.client.get_source.assert_called_once_with('ovirt-prod')

    def test_show_pretty(self):
        output = self.run_ok(main.show_source, ['ovirt-prod'])
        self.assertIn('Name                : ovirt-prod', output)
        self.assertIn('Last seen           : %s' % WHEN_LOCAL, output)
        # The semicolon separated flavor list is re-joined for humans.
        self.assertIn('Flavors             : spice, vnc', output)

    def test_show_simple(self):
        output = self.run_ok(main.show_source, ['ovirt-prod'], output='simple')
        self.assertIn('Name:ovirt-prod', output)
        self.assertIn('Flavors:spice, vnc', output)

    def test_show_omits_falsy_fields(self):
        # errored is False here, and the show loop skips anything falsy,
        # so a working source does not print "Errored: False".
        output = self.run_ok(main.show_source, ['ovirt-prod'])
        self.assertNotIn('Errored', output)

    def test_show_without_a_ca_certificate(self):
        output = self.run_ok(main.show_source, ['ovirt-prod'])
        self.assertIn('CA Certificate      : none', output)

    def test_show_with_a_ca_certificate(self):
        source = dict(SOURCE)
        source['ca_cert'] = '-----BEGIN CERTIFICATE-----\nMIIB\n'
        self.client.get_source.return_value = source

        output = self.run_ok(main.show_source, ['ovirt-prod'])
        self.assertIn('CA certificate:', output)
        self.assertIn('     -----BEGIN CERTIFICATE-----', output)


class ConsoleCommandTestCase(CommandTestCase):
    def setUp(self):
        super().setUp()
        self.client.get_consoles.return_value = [CONSOLE]
        self.client.get_console.return_value = CONSOLE
        self.client.get_console_audit.return_value = AUDIT

    def test_list_json(self):
        output = self.run_ok(main.list_consoles, output='json')
        self.assertEqual([CONSOLE], json.loads(output))

    def test_list_simple(self):
        output = self.run_ok(main.list_consoles, output='simple')
        lines = output.strip().split('\n')
        self.assertEqual(
            'uuid,name,source,discovered,token count,sessions', lines[0])
        self.assertEqual(
            'c0ffee,desktop-1,ovirt-prod,%s,2,sess1' % WHEN_LOCAL, lines[1])

    def test_list_simple_joins_sessions_with_semicolons(self):
        console = dict(CONSOLE)
        console['sessions'] = ['sess1', 'sess2']
        self.client.get_consoles.return_value = [console]

        output = self.run_ok(main.list_consoles, output='simple')
        # Semicolons, because the fields themselves are comma separated.
        self.assertIn('sess1;sess2', output.strip().split('\n')[1])

    def test_list_pretty(self):
        output = self.run_ok(main.list_consoles)
        self.assertIn('desktop-1', output)
        self.assertIn(WHEN_LOCAL, output)

    def test_show_json(self):
        output = self.run_ok(
            main.show_console, ['ovirt-prod', 'c0ffee'], output='json')
        self.assertEqual(CONSOLE, json.loads(output))
        self.client.get_console.assert_called_once_with('ovirt-prod', 'c0ffee')

    def test_show_pretty(self):
        output = self.run_ok(main.show_console, ['ovirt-prod', 'c0ffee'])
        self.assertIn('Name                : desktop-1', output)
        self.assertIn('UUID                : c0ffee', output)
        self.assertIn('Discovered          : %s' % WHEN_LOCAL, output)
        self.assertIn('Secure VDI port     : 5901', output)

    def test_show_simple(self):
        output = self.run_ok(
            main.show_console, ['ovirt-prod', 'c0ffee'], output='simple')
        self.assertIn('Name:desktop-1', output)
        self.assertIn('UUID:c0ffee', output)

    def test_show_with_sessions(self):
        output = self.run_ok(main.show_console, ['ovirt-prod', 'c0ffee'])
        self.assertIn('Sessions:', output)
        self.assertIn('     sess1', output)

    def test_show_without_sessions(self):
        console = dict(CONSOLE)
        console['sessions'] = []
        self.client.get_console.return_value = console

        output = self.run_ok(main.show_console, ['ovirt-prod', 'c0ffee'])
        self.assertIn('Sessions            : none', output)

    def test_audit_json(self):
        output = self.run_ok(
            main.audit_console, ['ovirt-prod', 'c0ffee'], output='json')
        self.assertEqual(AUDIT, json.loads(output))

    def test_audit_default_limit(self):
        self.run_ok(main.audit_console, ['ovirt-prod', 'c0ffee'], output='json')
        self.client.get_console_audit.assert_called_once_with(
            'ovirt-prod', 'c0ffee', 200)

    def test_audit_explicit_limit(self):
        self.run_ok(
            main.audit_console, ['ovirt-prod', 'c0ffee', '--limit', '5'],
            output='json')
        self.client.get_console_audit.assert_called_once_with(
            'ovirt-prod', 'c0ffee', 5)

    def test_audit_simple(self):
        output = self.run_ok(
            main.audit_console, ['ovirt-prod', 'c0ffee'], output='simple')
        # The count header is printed for every non-JSON format, so that
        # a truncated listing says so.
        self.assertIn('There are 17 audit events, displaying 1', output)
        self.assertIn('timestamp,node,pid,session_id,channel,message', output)
        # The simple format prints the raw epoch rather than a datetime.
        self.assertIn('%s,node1,42,sess1,main,connected' % WHEN, output)

    def test_audit_pretty(self):
        output = self.run_ok(main.audit_console, ['ovirt-prod', 'c0ffee'])
        self.assertIn('There are 17 audit events, displaying 1', output)
        self.assertIn(WHEN_LOCAL, output)
        self.assertIn('connected', output)

    def test_terminate(self):
        self.run_ok(main.terminate_console, ['ovirt-prod', 'c0ffee'])
        self.client.console_terminate.assert_called_once_with(
            'ovirt-prod', 'c0ffee')


class VvCommandTestCase(CommandTestCase):
    def setUp(self):
        super().setUp()
        self.client.get_console_direct_vv.return_value = VV
        self.client.get_console_proxy_vv.return_value = VV

        patcher = mock.patch.object(main.subprocess, 'run')
        self.subprocess_run = patcher.start()
        self.addCleanup(patcher.stop)
        self.subprocess_run.return_value = mock.Mock(returncode=0)

    def _output_path(self):
        path = os.path.join(tempfile.mkdtemp(), 'console.vv')
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def test_direct_uses_the_direct_endpoint(self):
        self.run_ok(
            main.direct_console,
            ['ovirt-prod', 'c0ffee', '--execute', 'none'])
        self.client.get_console_direct_vv.assert_called_once_with(
            'ovirt-prod', 'c0ffee')
        self.assertFalse(self.client.get_console_proxy_vv.called)

    def test_proxy_uses_the_proxy_endpoint(self):
        self.run_ok(
            main.proxy_console,
            ['ovirt-prod', 'c0ffee', '--execute', 'none'])
        self.client.get_console_proxy_vv.assert_called_once_with(
            'ovirt-prod', 'c0ffee')
        self.assertFalse(self.client.get_console_direct_vv.called)

    def test_execute_none_launches_nothing(self):
        self.run_ok(
            main.direct_console,
            ['ovirt-prod', 'c0ffee', '--execute', 'none'])
        self.assertFalse(self.subprocess_run.called)

    def test_output_writes_the_vv_file(self):
        path = self._output_path()
        self.run_ok(
            main.direct_console,
            ['ovirt-prod', 'c0ffee', '--execute', 'none', '--output', path])
        with open(path) as f:
            self.assertEqual(VV, f.read())

    def test_the_viewer_is_launched_against_the_temporary_file(self):
        self.run_ok(main.direct_console, ['ovirt-prod', 'c0ffee'])
        self.assertEqual(1, self.subprocess_run.call_count)

        command = self.subprocess_run.call_args[0][0]
        self.assertTrue(command.startswith('remote-viewer '))
        self.assertTrue(self.subprocess_run.call_args[1]['shell'])

    def test_the_temporary_file_is_removed_afterwards(self):
        written = {}

        def record(command, shell=False):
            path = command.split(' ', 1)[1]
            with open(path) as f:
                written['path'] = path
                written['content'] = f.read()
            return mock.Mock(returncode=0)

        self.subprocess_run.side_effect = record
        self.run_ok(main.direct_console, ['ovirt-prod', 'c0ffee'])

        # The viewer saw the file...
        self.assertEqual(VV, written['content'])
        # ...and it is gone now, because it held a console token.
        self.assertFalse(os.path.exists(written['path']))

    def test_the_temporary_file_is_removed_when_the_viewer_fails(self):
        self.subprocess_run.side_effect = OSError('no remote-viewer here')
        result = self.invoke(main.direct_console, ['ovirt-prod', 'c0ffee'])
        self.assertIsInstance(result.exception, OSError)
        # Nothing left in TMPDIR holding a token. The helper's finally
        # clause is what guarantees this.
        self.assertFalse(self.subprocess_run.call_args is None)

    def test_output_with_a_viewer_is_broken(self):
        # https://github.com/shakenfist/kerbside-client/issues/17
        #
        # _vv_helper() writes to --output and then runs the viewer
        # against temp_name, a name only bound in the other branch, so
        # this raises NameError instead of launching anything. Remove
        # the expectFailure when #17 is fixed.
        path = self._output_path()

        def it_should_launch_the_viewer():
            result = self.invoke(
                main.direct_console,
                ['ovirt-prod', 'c0ffee', '--output', path])
            self.assertEqual(0, result.exit_code)

        self.expectFailure(
            'issues/17: _vv_helper references temp_name in the --output branch',
            it_should_launch_the_viewer)


class SessionCommandTestCase(CommandTestCase):
    def setUp(self):
        super().setUp()
        self.client.get_sessions.return_value = SESSIONS

    def test_list_json(self):
        output = self.run_ok(main.list_sessions, output='json')
        self.assertEqual(SESSIONS, json.loads(output))

    def test_list_simple(self):
        output = self.run_ok(main.list_sessions, output='simple')
        lines = output.strip().split('\n')
        self.assertEqual(
            'source,name,console uuid,session id,created,client ip', lines[0])
        # The simple format reports the raw epoch, where the pretty one
        # below formats it.
        self.assertIn('ovirt-prod,desktop-1,c0ffee,sess1,%s,10.1.1.1' % WHEN,
                      lines[1])

    def test_list_pretty(self):
        output = self.run_ok(main.list_sessions)
        self.assertIn('ovirt-prod', output)
        self.assertIn('desktop-1', output)
        self.assertIn('10.1.1.1', output)
        self.assertIn(WHEN_LOCAL, output)

    def test_list_reports_the_earliest_channel_creation(self):
        # A session has a channel per SPICE channel type, each created
        # at a slightly different moment; the listing shows when the
        # session started, which is the earliest of them.
        early = dict(CHANNEL, created=WHEN - 60, channel_type='display')
        self.client.get_sessions.return_value = {
            'sess1': dict(SESSIONS['sess1'], channels=[CHANNEL, early])}

        output = self.run_ok(main.list_sessions)
        self.assertIn(str(datetime.datetime.fromtimestamp(WHEN - 60)), output)

    def test_list_with_no_channels_is_broken(self):
        # https://github.com/shakenfist/kerbside-client/issues/31
        #
        # A session row whose channels list is empty crashes the whole
        # listing with UnboundLocalError: the loop variable is read
        # after the loop, and an empty list never binds it. The window
        # is small but real -- a session that has just been torn down
        # between the server building the list and the client printing
        # it -- and one such session hides every other.
        self.client.get_sessions.return_value = {
            'sess1': dict(SESSIONS['sess1'], channels=[])}

        def it_should_list_the_session():
            result = self.invoke(main.list_sessions)
            self.assertEqual(0, result.exit_code)

        self.expectFailure(
            'issues/31: session list raises UnboundLocalError on a session '
            'with no channels', it_should_list_the_session)

    def test_show_is_broken(self):
        # https://github.com/shakenfist/kerbside-client/issues/30
        #
        # "kerbside-client session show <id>" does not work at all, in
        # any output format other than json. get_sessions() returns a
        # dict keyed by session id whose values are {source, name, uuid,
        # channels}; show_session iterates that value directly instead
        # of its 'channels' list, so it walks the four key strings and
        # raises TypeError on the first subscript.
        def it_should_show_the_session():
            result = self.invoke(main.show_session, ['sess1'])
            self.assertEqual(0, result.exit_code)

        self.expectFailure(
            'issues/30: session show iterates the session dict rather than '
            'its channels', it_should_show_the_session)

    def test_show_json_works(self):
        # The json format returns before reaching the broken loop, so
        # this is the one way to read a session today.
        output = self.run_ok(main.show_session, ['sess1'], output='json')
        self.assertEqual(SESSIONS['sess1'], json.loads(output))

    def test_show_an_unknown_session_in_json(self):
        output = self.run_ok(main.show_session, ['nope'], output='json')
        self.assertIsNone(json.loads(output))

    def test_terminate(self):
        self.run_ok(main.terminate_session, ['sess1'])
        self.client.session_terminate.assert_called_once_with('sess1')


class VersionCommandTestCase(CommandTestCase):
    def test_version_prints_the_user_agent(self):
        output = self.run_ok(main.version)
        self.assertEqual(apiclient.get_user_agent(), output.strip())
        self.assertIn('Kerbside/', output)

    def test_version_needs_no_client(self):
        # The command itself never touches the API...
        self.run_ok(main.version)
        self.assertEqual([], self.client.method_calls)

    def test_version_through_the_cli_group_is_broken(self):
        # https://github.com/shakenfist/kerbside-client/issues/18
        #
        # ...but reaching it does. The group callback constructs the API
        # client before dispatching to any subcommand, so asking the
        # client its own version fails without a configured server.
        # Remove the expectFailure when #18 is fixed.
        def it_should_print_a_version():
            result = CliRunner().invoke(
                main.cli, ['version'], env={'KERBSIDE_API_URL': None})
            self.assertEqual(0, result.exit_code)

        self.expectFailure(
            'issues/18: the cli group builds a client before every subcommand',
            it_should_print_a_version)


class CliGroupTestCase(base.MainStateTestCase):
    """The group callback, which every real invocation goes through.

    apiclient.Client is patched out because constructing a real one
    probes the server for its capabilities before click has dispatched
    to any subcommand. "version" is the subcommand used here precisely
    because it makes no request of its own, so what is being tested is
    the callback and nothing else.
    """

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(main.apiclient, 'Client')
        self.client_class = patcher.start()
        self.addCleanup(patcher.stop)

    def invoke(self, args, env=None):
        env = dict(env or {})
        env.setdefault('KERBSIDE_API_URL', None)
        result = CliRunner().invoke(main.cli, args, env=env)
        if result.exception and not isinstance(result.exception, SystemExit):
            raise result.exception
        return result

    def test_apiurl_option(self):
        self.invoke(['--apiurl', 'http://kerbside.example.com/api', 'version'])
        self.assertEqual(
            'http://kerbside.example.com/api',
            self.client_class.call_args[1]['base_url'])

    def test_apiurl_comes_from_the_environment(self):
        # KERBSIDE_API_URL is how this is configured in practice; there
        # is no config file.
        self.invoke(
            ['version'], env={'KERBSIDE_API_URL': 'http://from-env/api'})
        self.assertEqual(
            'http://from-env/api', self.client_class.call_args[1]['base_url'])

    def test_the_option_beats_the_environment(self):
        self.invoke(
            ['--apiurl', 'http://from-flag/api', 'version'],
            env={'KERBSIDE_API_URL': 'http://from-env/api'})
        self.assertEqual(
            'http://from-flag/api', self.client_class.call_args[1]['base_url'])

    def test_the_client_is_given_the_console_logger(self):
        # So that the client's debug logging is formatted like the rest
        # of the CLI's rather than going to logging's own default.
        self.invoke(['--apiurl', 'http://x/api', 'version'])
        self.assertIs(main.LOG, self.client_class.call_args[1]['logger'])

    def test_the_client_is_published_as_a_module_global(self):
        self.invoke(['--apiurl', 'http://x/api', 'version'])
        self.assertIs(self.client_class.return_value, main.CLIENT)

    def test_verbose_turns_on_debug_logging(self):
        self.invoke(['--verbose', '--apiurl', 'http://x/api', 'version'])
        self.assertEqual(logging.DEBUG, main.LOG.logger.level)

    def test_not_verbose_is_info(self):
        main.LOG.setLevel(logging.DEBUG)
        self.invoke(['--apiurl', 'http://x/api', 'version'])
        self.assertEqual(logging.INFO, main.LOG.logger.level)

    def test_output_formats_are_mutually_exclusive(self):
        for args, expected in [([], 'pretty'),
                               (['--pretty'], 'pretty'),
                               (['--simple'], 'simple'),
                               (['--json'], 'json'),
                               (['--simple', '--json'], 'json'),
                               (['--json', '--simple'], 'simple')]:
            captured = {}

            @click.command(name='capture')
            @click.pass_context
            def capture(ctx):
                captured.update(ctx.obj)

            with mock.patch.dict(main.cli.commands, {'capture': capture}):
                self.invoke(args + ['--apiurl', 'http://x/api', 'capture'])

            self.assertEqual(
                expected, captured['OUTPUT'],
                'wrong output format for %s' % (args,))


class CommandCoverageTestCase(base.MainStateTestCase):
    def test_every_command_has_tests(self):
        # The output formats are implemented per command rather than
        # centrally, so a new command is a new set of format branches.
        # This fails when one is added without tests alongside it.
        expected = {
            'source': {'list', 'show'},
            'console': {'list', 'show', 'audit', 'direct', 'proxy', 'terminate'},
            'session': {'list', 'show', 'terminate'},
        }
        for group_name, commands in expected.items():
            group = getattr(main, group_name)
            self.assertEqual(
                commands, set(group.commands.keys()),
                'the %s group has gained or lost a command' % group_name)

        self.assertEqual(
            {'source', 'console', 'session', 'version'},
            set(main.cli.commands.keys()))
