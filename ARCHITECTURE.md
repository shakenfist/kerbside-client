# Architecture

`kerbside-client` is the command line and REST client for
[Kerbside](https://github.com/shakenfist/kerbside), a SPICE VDI proxy.
It talks to a Kerbside API server over HTTP and, for the console
commands, hands the `.vv` file the server returns to a local SPICE
viewer. It holds no state of its own: there is no database, no cache on
disk and no daemon.

## Component inventory

| Component | File | Responsibility |
|-----------|------|----------------|
| CLI | `kerbside_client/main.py` | The `kerbside-client` entry point: a click command group per noun (`source`, `console`, `session`), output formatting, and launching the viewer |
| API client | `kerbside_client/apiclient.py` | `Client`, the HTTP layer: capability probe, authentication, request/response logging, status-code-to-exception mapping |
| Unit tests | `kerbside_client/tests/` | A package with no tests in it yet |

Two files, 650 lines. Anything that is not output formatting or a
click decorator belongs in `apiclient.py`, so that a caller embedding
the client in their own program gets it without importing the CLI.

## How a command reaches the server

1. The `cli` group constructs `apiclient.Client` with the URL from
   `--apiurl` or `KERBSIDE_API_URL`, before any subcommand runs, and
   puts it in the click context.
2. `Client.__init__` immediately `GET`s the base URL and records
   `capabilities` from the JSON it returns. `check_capability()` reads
   that list, so a command can refuse before making a request the
   server cannot serve.
3. On the first authenticated request, the client probes the base URL
   with redirects disabled. A `301` means the deployment has moved, and
   `base_url` is rewritten to the `Location` for the rest of the
   process.
4. It then `POST`s `OS_USERNAME` and `OS_PASSWORD` -- read from the
   environment, not from any flag or config file -- to `/auth`, and
   caches `Bearer <access_token>` in memory for the life of the
   process. A later `401` re-authenticates once and retries the
   request; a second failure propagates.
5. Responses are mapped to exceptions by status code, and the CLI group
   turns each into a one-line message and a non-zero exit:

   | Status | Exception |
   |--------|-----------|
   | 400 | `RequestMalformedException` |
   | 401 | `UnauthenticatedException` |
   | 403 | `UnauthorizedException` |
   | 404 | `ResourceNotFoundException` |
   | 500 | `InternalServerError` |
   | any other non-200 | `APIException` |

Every request carries a `User-Agent` built from the package version, so
a server's logs identify which client version spoke to it.

## Connecting to a console

`console direct` and `console proxy` differ only in which endpoint
produces the `.vv` file: `direct` returns connection details for the
hypervisor itself, `proxy` returns details for the Kerbside proxy.
Both then go through `_vv_helper()`, which writes the file -- to
`--output`, or to a temporary file it deletes afterwards -- and runs
`--execute` (`remote-viewer` by default) against it with
`shell=True`. `--execute none` writes the file and launches nothing.

This is the only place the client runs another program, and it is why
`--output` and `--execute` are worth reading carefully before being
changed.

## Output formats

Three mutually exclusive flags on the top-level group, carried in the
click context rather than passed down: `--pretty` (default, a
`PrettyTable`), `--simple` (comma separated, for scripts) and
`--json` (the server's JSON, re-indented). Every listing and show
command implements all three, and a new one is expected to.

## Supported platforms

The client must install and run on the system Python provided by each
distribution Shaken Fist builds images for
(<https://images.shakenfist.com/README>). The oldest Python in this
table determines the `requires-python` floor in `pyproject.toml` and
the `constraints.python` value in `renovate.json`.

| Distribution | Python version |
|--------------|----------------|
| Ubuntu 20.04 | 3.8 |
| Ubuntu 22.04 | 3.10 |
| Ubuntu 24.04 | 3.12 |
| Debian 11 | 3.9 |
| Debian 12 | 3.11 |
| Debian 13 | 3.13 |
| CentOS 9-stream | 3.9 |
| Fedora 41-43 | 3.13 |

**Current minimum: Python 3.8** (Ubuntu 20.04).

When a distribution leaves this table, `requires-python` and
`constraints.python` both move with it. The `python-version` audit
checks the two agree; it cannot check that the floor is the right one,
which is what this table is for.

## Packaging and distribution

`pyproject.toml` with `setuptools_scm`: the version comes from the most
recent `v*` tag and is written to `kerbside_client/_version.py` at build
time. There are no tags yet, so a build from this tree produces a
`0.1.devN` version and `get_user_agent()` reports "unreleased
development version" when run from a checkout that was never built.

Nothing publishes this package. There is no `release.yml`, no PyPI
project and no merge queue on `develop`, so the only way to install it
is from a git checkout. Adopting the fleet's release automation is
tracked as
[#16](https://github.com/shakenfist/kerbside-client/issues/16); until
then the `release-process` consistency criterion fails here by design.

## Continuous integration

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | pull request, push to `develop`, dispatch | pre-commit hooks, flake8 over changed files, then the shared automatic reviewer |
| `secret-scan.yml` | pull request, push to `develop` | gitleaks over all history reachable from `HEAD`, with a positive control |
| `codeql-analysis.yml` | pull request, push, weekly | CodeQL, skipped for review-only and docs-only changes and for forks |
| `pr-re-review.yml` | issue comment | re-runs the automatic review on request |
| `pr-retest.yml` | issue comment | dispatches the workflow named by `RETEST_WORKFLOW` |
| `renovate.yml` | hourly | dependency bumps |
| `export-repo-config.yml` | daily | writes GitHub settings into the tree as a pull request |
| `prune-reviews.yml` | push, schedule | maintains the human review marks |

Everything but the gitleaks job runs on the `static` runner pool,
because nothing else installs an OS package. gitleaks is only packaged
from Debian 13 onward, so its job takes a throwaway `vm` runner.

## Human review tracking

This repository carries the fleet's whole-file review tracking:
`REVIEWS.md` records which files have been reviewed at their current
content, `.vscode/*.weaudit*` holds the weAudit state behind it, and
`.vscode/review-scope.toml` decides which files are subject to review
at all. All of it is generated -- see
[the fleet documentation](https://github.com/shakenfist/development/blob/main/docs/code-review-tracking.md)
for how the attestations work and how to verify them.
