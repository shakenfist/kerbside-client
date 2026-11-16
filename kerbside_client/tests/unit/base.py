import json
import logging

import testtools

from kerbside_client import apiclient
from kerbside_client import main


class FakeResponse(object):
    """The parts of requests.Response that the client actually touches.

    The client reads status_code, text, headers and history, and calls
    json(). A mock.Mock would happily answer anything at all, including
    an attribute the real Response does not have; this class fails on
    those, which is what keeps the stub honest about the surface being
    relied on.
    """

    def __init__(self, status_code=200, body=None, text=None, headers=None,
                 history=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.history = history or []
        self._body = body

        if text is not None:
            self.text = text
        elif body is not None:
            self.text = json.dumps(body)
        else:
            self.text = ''

    def json(self):
        if self._body is not None:
            return self._body
        return json.loads(self.text)


class ApiClientStateTestCase(testtools.TestCase):
    """Base class which puts apiclient's module level state back.

    Two globals in apiclient outlive any one client. Client.__init__
    replaces LOG outright when it is handed a logger, and raises its
    level when verbose is set; get_user_agent() memoises the package
    version in VERSION_CACHE. Both are process wide, so a test which
    touches either has to hand the interpreter back what it was given
    or the next test inherits it.
    """

    def setUp(self):
        super().setUp()

        saved_log = apiclient.LOG
        saved_level = saved_log.level
        saved_cache = apiclient.VERSION_CACHE
        saved_propagate = saved_log.propagate

        # The verbose tests turn this logger up to DEBUG, and with no
        # handler of its own every record would reach logging's handler
        # of last resort on stderr -- outside stestr's per test capture
        # on the subunit stream, so it lands in the middle of the run's
        # output rather than attached to the test that produced it.
        null = logging.NullHandler()
        saved_log.addHandler(null)
        saved_log.propagate = False

        def restore():
            apiclient.LOG = saved_log
            saved_log.removeHandler(null)
            saved_log.propagate = saved_propagate
            saved_log.setLevel(saved_level)
            apiclient.VERSION_CACHE = saved_cache

        self.addCleanup(restore)


class MainStateTestCase(testtools.TestCase):
    """Base class which puts main's module level state back.

    The cli group stashes the constructed client in a module global as
    well as in the click context, and moves the console logger between
    INFO and DEBUG depending on --verbose.
    """

    def setUp(self):
        super().setUp()

        saved_client = main.CLIENT
        saved_level = main.LOG.logger.level

        def restore():
            main.CLIENT = saved_client
            main.LOG.setLevel(saved_level)

        self.addCleanup(restore)
