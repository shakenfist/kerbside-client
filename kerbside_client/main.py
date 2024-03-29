import click
import datetime
import json
import logging
import os
from prettytable import PrettyTable
from shakenfist_utilities import logs
import subprocess
import sys
import tempfile
import time

from kerbside_client import apiclient


LOG = logs.setup_console(__name__)
CLIENT = None


class GroupCatchExceptions(click.Group):
    def __call__(self, *args, **kwargs):
        try:
            return self.main(*args, **kwargs)

        except apiclient.RequestMalformedException as e:
            LOG.error('Malformed Request: %s' % error_text(e.text))
            sys.exit(1)

        except apiclient.UnauthenticatedException as e:
            LOG.error('Not authenticated: %s' % e)
            sys.exit(1)

        except apiclient.UnauthorizedException as e:
            LOG.error('Not authorized: %s' % error_text(e.text))
            sys.exit(1)

        except apiclient.ResourceNotFoundException as e:
            LOG.error('Resource not found: %s' % error_text(e.text))
            sys.exit(1)

        except apiclient.InternalServerError as e:
            # Print full error since server should not fail
            LOG.error('Internal Server Error: %s' % e.text)
            sys.exit(1)


def error_text(json_text):
    try:
        err = json.loads(json_text)
        if 'error' in err:
            return err['error']
    except Exception:
        pass

    return json_text


@click.group(cls=GroupCatchExceptions)
@click.option('--pretty', 'output', flag_value='pretty', default=True)
@click.option('--simple', 'output', flag_value='simple')
@click.option('--json', 'output', flag_value='json')
@click.option('--verbose/--no-verbose', default=False)
@click.option('--apiurl', envvar='KERBSIDE_API_URL', default=None)
@click.pass_context
def cli(ctx, output, verbose, apiurl):
    if not ctx.obj:
        ctx.obj = {}
    ctx.obj['OUTPUT'] = output
    ctx.obj['VERBOSE'] = verbose

    if verbose:
        LOG.setLevel(logging.DEBUG)
        LOG.debug('Set log level to DEBUG')
    else:
        LOG.setLevel(logging.INFO)

    global CLIENT
    CLIENT = apiclient.Client(base_url=apiurl, logger=LOG)
    ctx.obj['CLIENT'] = CLIENT
    LOG.debug('Client for %s constructed' % apiurl)


@click.group(help='Source commands')
def source():
    pass


@source.command(
    name='list', help='Output information about the configured console sources')
@click.pass_context
def list_sources(ctx):
    sources = ctx.obj['CLIENT'].get_sources()
    if ctx.obj['OUTPUT'] == 'json':
        print(json.dumps(sources, indent=4, sort_keys=True))
        return

    if ctx.obj['OUTPUT'] == 'simple':
        print('name,type,last seen,seen by,errored')
        for s in sources:
            last_seen = datetime.datetime.fromtimestamp(s['last_seen'])
            print('%s,%s,%s,%s,%s'
                  % (s['name'], s['type'], last_seen, s['seen_by'],
                     s['errored']))
        return

    x = PrettyTable()
    x.field_names = ['name', 'type', 'last seen', 'seen by', 'errored']
    for s in sources:
        last_seen = datetime.datetime.fromtimestamp(s['last_seen'])
        x.add_row([s['name'], s['type'], last_seen, s['seen_by'], s['errored']])
    print(x)


@source.command(
    name='show', help='Output detailed information about a specific console source')
@click.argument('name', type=click.STRING)
@click.pass_context
def show_source(ctx, name):
    source = ctx.obj['CLIENT'].get_source(name)

    if ctx.obj['OUTPUT'] == 'json':
        print(json.dumps(source, indent=4, sort_keys=True))
        return

    if ctx.obj['OUTPUT'] == 'simple':
        format = '%s:%s'
    else:
        format = '%-20s: %s'

    for field, field_pretty in [
        ('name', 'Name'),
        ('errored', 'Errored'), ('flavor', 'Flavors'),
        ('last_seen', 'Last seen'),
        ('project_domain_id', 'Project domain ID'),
        ('project_name', 'Project name'), ('seen_by', 'Seen by'),
        ('type', 'Type'), ('url', 'URL'),
        ('user_domain_id', 'User domain ID'), ('username', 'Username')]:
        if source.get(field):
            if field == 'flavor':
                print(format % (field_pretty,
                                ', '.join(source.get(field).split(';'))))
            elif field == 'last_seen':
                print(format % (field_pretty,
                                datetime.datetime.fromtimestamp(source.get(field))))
            else:
                print(format % (field_pretty, source.get(field)))

    if not source['ca_cert']:
        print(format % ('CA Certificate', 'none'))
    else:
        print('CA certificate:')
        for line in source['ca_cert'].split('\n'):
            print('     %s' % line)


@click.group(help='Console commands')
def console():
    pass


@console.command(name='list', help='List the discovered consoles')
@click.pass_context
def list_consoles(ctx):
    consoles = ctx.obj['CLIENT'].get_consoles()
    if ctx.obj['OUTPUT'] == 'json':
        print(json.dumps(consoles, indent=4, sort_keys=True))
        return

    if ctx.obj['OUTPUT'] == 'simple':
        print('uuid,name,source,discovered,token count,sessions')
        for c in consoles:
            discovered = datetime.datetime.fromtimestamp(c['discovered'])
            print('%s,%s,%s,%s,%s,%s'
                  % (c['uuid'], c['name'], c['source'], discovered, c['token_count'],
                     ';'.join(c['sessions'])))
        return

    x = PrettyTable()
    x.field_names = ['uuid', 'name', 'source', 'discovered', 'token count', 'sessions']
    for c in consoles:
        discovered = datetime.datetime.fromtimestamp(c['discovered'])
        x.add_row([c['uuid'], c['name'], c['source'], discovered, c['token_count'],
                  '\n'.join(c['sessions'])])
    print(x)


@console.command(
    name='show', help='Output detailed information about a specific console')
@click.argument('source', type=click.STRING)
@click.argument('uuid', type=click.STRING)
@click.pass_context
def show_console(ctx, source, uuid):
    c = ctx.obj['CLIENT'].get_console(source, uuid)

    if ctx.obj['OUTPUT'] == 'json':
        print(json.dumps(c, indent=4, sort_keys=True))
        return

    if ctx.obj['OUTPUT'] == 'simple':
        format = '%s:%s'
    else:
        format = '%-20s: %s'

    for field, field_pretty in [
        ('name', 'Name'), ('uuid', 'UUID'), ('source', 'Source'),
        ('discovered', 'Discovered'), ('host_subject', 'Host subject'),
        ('hypervisor', 'Hypervisor'), ('hypervisor_ip', 'Hypervisor IP'),
        ('insecure_port', 'Insecure VDI port'), ('secure_port', 'Secure VDI port'),
        ('token_count', 'Token Count')]:
        if c.get(field):
            if field == 'discovered':
                print(format % (field_pretty,
                                datetime.datetime.fromtimestamp(c.get(field))))
            else:
                print(format % (field_pretty, c.get(field)))

    if not c['sessions']:
        print(format % ('Sessions', 'none'))
    else:
        print('Sessions:')
        for s in c['sessions']:
            print('     %s' % s)


@console.command(
    name='audit', help='Output audit information for a specific console')
@click.argument('source', type=click.STRING)
@click.argument('uuid', type=click.STRING)
@click.option(
    '-l', '--limit', default=200, help='The number of audit events to return')
@click.pass_context
def audit_console(ctx, source, uuid, limit):
    c = ctx.obj['CLIENT'].get_console_audit(source, uuid, limit)

    if ctx.obj['OUTPUT'] == 'json':
        print(json.dumps(c, indent=4, sort_keys=True))
        return

    print('There are %d audit events, displaying %d'
          % (c['total'], len(c['audit'])))
    print()

    if ctx.obj['OUTPUT'] == 'simple':
        print('timestamp,node,pid,session_id,channel,message')
        for a in c['audit']:
            print('%s,%s,%s,%s,%s,%s'
                  % (a['timestamp'], a['node'], a['pid'], a['session_id'], a['channel'],
                     a['message']))
        return

    x = PrettyTable()
    x.align = 'l'
    x.field_names = ['timestamp', 'node', 'pid', 'session_id', 'channel', 'message']
    for a in c['audit']:
        ts = datetime.datetime.fromtimestamp(a['timestamp'])
        x.add_row([ts, a['node'], a['pid'], a['session_id'], a['channel'],
                   a['message']])
    print(x)


def _vv_helper(execute, output, vv):
    # We don't use NamedTemporaryFile as a context manager as the .vv file
    # will also attempt to clean up the file.
    if not output:
        (temp_handle, temp_name) = tempfile.mkstemp()
        os.close(temp_handle)
        try:
            with open(temp_name, 'w') as f:
                f.write(vv)

            if execute != 'none':
                p = subprocess.run('%s %s' % (execute, temp_name), shell=True)
                LOG.debug(
                    'Viewer process exited with %d return code'  % p.returncode)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    else:
        with open(output, 'w') as f:
            f.write(vv)

        if execute != 'none':
            p = subprocess.run('%s %s' % (execute, temp_name), shell=True)
            LOG.debug(
                    'Viewer process exited with %d return code'  % p.returncode)


@console.command(name='direct', help='Connect directly to a console')
@click.argument('source', type=click.STRING)
@click.argument('uuid', type=click.STRING)
@click.option(
    '-e', '--execute', default='remote-viewer',
    help='The program to open the .vv file with, use "none" to not use a program.')
@click.option(
    '-o', '--output', default=None,
    help='Where to write the .vv file, leave empty to use a temporary file.')
@click.pass_context
def direct_console(ctx, source, uuid, execute, output):
    vv = ctx.obj['CLIENT'].get_console_direct_vv(source, uuid)
    _vv_helper(execute, output, vv)


@console.command(name='proxy', help='Connect via the proxy to a console')
@click.argument('source', type=click.STRING)
@click.argument('uuid', type=click.STRING)
@click.option(
    '-e', '--execute', default='remote-viewer',
    help='The program to open the .vv file with, use "none" to not use a program.')
@click.option(
    '-o', '--output', default=None,
    help='Where to write the .vv file, leave empty to use a temporary file.')
@click.pass_context
def proxy_console(ctx, source, uuid, execute, output):
    vv = ctx.obj['CLIENT'].get_console_proxy_vv(source, uuid)
    _vv_helper(execute, output, vv)


@console.command(name='terminate', help='Terminate all sessions to this console')
@click.argument('source', type=click.STRING)
@click.argument('uuid', type=click.STRING)
@click.pass_context
def proxy_console(ctx, source, uuid):
    ctx.obj['CLIENT'].console_terminate(source, uuid)


@click.group(help='Session commands')
def session():
    pass


@session.command(name='list', help='List all active proxy sessions')
@click.pass_context
def list_sessions(ctx):
    sessions = ctx.obj['CLIENT'].get_sessions()
    if ctx.obj['OUTPUT'] == 'json':
        print(json.dumps(sessions, indent=4, sort_keys=True))
        return

    if ctx.obj['OUTPUT'] == 'simple':
        print('source,name,console uuid,session id,created,client ip')
        for s in sessions:
            created = time.time()
            for chan in sessions[s]['channels']:
                if chan['created'] < created:
                    created = chan['created']
            print('%s,%s,%s,%s,%s,%s'
                  % (sessions[s]['source'], sessions[s]['name'],
                     sessions[s]['uuid'], chan['session_id'],
                     created, chan['client_ip']))
        return

    x = PrettyTable()
    x.field_names = ['source', 'name', 'console uuid', 'session id', 'created',
                     'client ip']
    for s in sessions:
        created = datetime.datetime.now()
        for chan in sessions[s]['channels']:
            new_created = datetime.datetime.fromtimestamp(chan['created'])
            if new_created < created:
                created = new_created
        x.add_row([sessions[s]['source'], sessions[s]['name'],
                   sessions[s]['uuid'], chan['session_id'],
                   created, chan['client_ip']])
    print(x)


@session.command(name='show', help='Show details of a specific session')
@click.argument('session', type=click.STRING)
@click.pass_context
def show_session(ctx, session):
    sessions = ctx.obj['CLIENT'].get_sessions()
    s = sessions.get(session)
    if ctx.obj['OUTPUT'] == 'json':
        print(json.dumps(s, indent=4, sort_keys=True))
        return

    if ctx.obj['OUTPUT'] == 'simple':
        print('channel type,client ip,client port,created,node,pid')
        for chan in s:
            print('%s,%s,%s,%s,%s,%s'
                  % (chan['channel_type'], chan['client_ip'], chan['client_port'],
                     chan['created'], chan['node'], chan['pid']))
        return

    x = PrettyTable()
    x.field_names = ['channel type', 'client ip', 'client port', 'created',
                     'node', 'pid']
    for chan in s:
        created = datetime.datetime.fromtimestamp(chan['created'])
        x.add_row([chan['channel_type'], chan['client_ip'], chan['client_port'],
                    created, chan['node'], chan['pid']])
    print(x)





@session.command(name='terminate', help='Terinate a specific session')
@click.argument('session', type=click.STRING)
@click.pass_context
def terminate_session(ctx, session):
    ctx.obj['CLIENT'].session_terminate(session)


@cli.command(name='version', help='Output the version of the client')
@click.pass_context
def version(ctx):
    print(apiclient.get_user_agent())


cli.add_command(source)
cli.add_command(console)
cli.add_command(session)
cli.add_command(version)
