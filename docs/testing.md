# Testing kerbside-client

The suite lives in `kerbside_client/tests/unit/` and is run by
[stestr](https://stestr.readthedocs.io/) through tox, the same way
every other Shaken Fist Python project runs its tests.

```bash
tox -epy3                              # the whole suite
tox -epy3 -- test_main                 # one module
tox -epy3 -- SessionCommandTestCase    # one class
tox -ecover                            # coverage report, HTML in cover/
```

`tox -epy3` builds the package into its own environment first, so it
also proves the package still builds and imports. `ci.yml` runs
exactly this command.

## What is tested, and what is mocked

Both modules are tested in full, and the boundary mocked in each case
is the one immediately outside the code under test:

| Module | Test file | Mocked |
|--------|-----------|--------|
| `apiclient.py` | `test_apiclient.py` | `requests.request`, and nothing else |
| `main.py` | `test_main.py` | `apiclient.Client`, and `subprocess.run` for the viewer |

Nothing mocks the system under test. `test_apiclient.py` lets the real
`Client` build the real URL, headers and body and asserts on what
`requests` was handed; `test_main.py` lets the real click commands do
the real formatting and asserts on what they printed.

`base.FakeResponse` stands in for `requests.Response` rather than a
`mock.Mock`, deliberately: a `Mock` answers to any attribute at all,
including ones the real class does not have, so a test written against
one can pass against a response object that could never exist.

### Invoking commands without a server

The `cli` group's callback constructs an API client -- which probes the
server -- before click dispatches to any subcommand, so invoking a
command through the group needs a server. `CommandTestCase.invoke()`
therefore invokes the individual command objects directly, handing
them the context object the group would have built:

```python
CliRunner().invoke(main.list_sources, [],
                   obj={'OUTPUT': 'pretty', 'CLIENT': fake_client})
```

`CliGroupTestCase` is the exception: it tests the callback itself, and
patches `apiclient.Client` out to do so.

## Module level state

Three globals outlive any one test, and a test that touches one has to
put it back. `base.ApiClientStateTestCase` and `base.MainStateTestCase`
do that; inherit from one of them rather than from `testtools.TestCase`
directly.

| Global | Mutated by | Why it matters |
|--------|------------|----------------|
| `apiclient.LOG` | `Client.__init__`, which replaces it outright when handed a logger and raises its level when `verbose` is set | A leaked DEBUG level makes every later test log |
| `apiclient.VERSION_CACHE` | `get_user_agent()`, which memoises the package version | A leaked value makes the version tests pass or fail depending on order |
| `main.CLIENT` | the `cli` group callback | Holds a mock alive past the test that made it |

`ApiClientStateTestCase` also attaches a `NullHandler` to
`apiclient.LOG` and clears `propagate`, so that the tests which do turn
on DEBUG logging do not emit through logging's handler of last resort,
which writes to stderr outside stestr's per-test capture.

## Testing the package version

`get_user_agent()` reads `kerbside_client._version`, which
`setuptools_scm` writes at build time. Both halves of
`UserAgentTestCase._hide_version_module()` are needed to make that
import fail: once the submodule has been imported, `from
kerbside_client import _version` finds it as an *attribute of the
package* and never consults `sys.modules`, so the attribute has to be
removed as well as the `sys.modules` entry set to `None`. A tree that
has been `pip install`ed has been built, so this is the normal case,
not the exotic one.

## Known defects are expected failures

Four tests are marked `self.expectFailure()`. Each one asserts what the
command *should* do and is listed here with the defect that stops it.
testtools reports an expected failure that starts passing as an
unexpected success, which stestr fails the run on -- so fixing a defect
makes the suite fail until its `expectFailure` is removed, which is the
point.

| Test | Defect |
|------|--------|
| `VvCommandTestCase.test_output_with_a_viewer_is_broken` | [#17](https://github.com/shakenfist/kerbside-client/issues/17): `_vv_helper()` uses `temp_name` in the `--output` branch, where it is never bound |
| `VersionCommandTestCase.test_version_through_the_cli_group_is_broken` | [#18](https://github.com/shakenfist/kerbside-client/issues/18): the `cli` group builds a client before every subcommand, so `version` needs a server |
| `SessionCommandTestCase.test_show_is_broken` | [#30](https://github.com/shakenfist/kerbside-client/issues/30): `session show` iterates the session dict instead of its `channels` list, raising `TypeError` in every format but `--json` |
| `SessionCommandTestCase.test_list_with_no_channels_is_broken` | [#31](https://github.com/shakenfist/kerbside-client/issues/31): `session list` reads its loop variable after the loop, raising `UnboundLocalError` on a session with no channels |

Two further tests -- `EndpointTestCase.test_path_components_are_not_url_escaped`
and `GroupCatchExceptionsTestCase.test_an_unmapped_api_error_is_not_caught`
-- assert current behaviour that is defensible but surprising, and say
so in a comment. They are not expected failures, because nothing here
is yet decided to be wrong.

## Tests that fail when the code grows

Two tests exist to notice new code rather than to check old code, and
both fail by design when something is added:

* `EndpointTestCase.test_every_public_method_is_covered` compares the
  public methods of `Client` against the endpoint table above it, so a
  new endpoint without a row fails.
* `CommandCoverageTestCase.test_every_command_has_tests` compares the
  registered click commands against a list, so a new subcommand fails
  until it is added -- and a new subcommand means three new output
  format branches, which is where the formatting bugs are.

Adding the row or the name is the fix; adding it without tests is
missing the point.

## Coverage

The suite covers 100% of `apiclient.py` and 96% of `main.py`. The
uncovered lines in `main.py` are the two click group bodies, which are
`pass`, and the branches made unreachable by the defects in the table
above. Coverage is not a target here -- see
[the fleet's test coverage standard](https://github.com/shakenfist/development/blob/main/docs/audits/test-coverage.md)
-- but a drop in it is worth explaining.
