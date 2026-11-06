# Working in this repository

`kerbside-client` is the client for the Kerbside SPICE VDI proxy.
`ARCHITECTURE.md` describes what the two modules do and how a command
reaches the server; this file is the conventions and the traps, which
reading the code will not tell you.

## Code style

* Single quotes for every string except docstrings, which use double
  quotes. Never triple single quotes.
* Wrap at 120 characters. `flake8 --max-line-length=120` is the
  arbiter, and it is the only linter run over the Python.
* `%` formatting, not f-strings or `.format()`. The whole tree uses it
  and consistency is worth more here than the newer syntax; it is also
  what the Python 3.8 floor was written against.
* No trailing whitespace.

The tree is flake8 clean as of November 2026, which it had not been
before. Keep it that way: `tools/flake8wrap.sh` lints only the files a
change touched, so a violation introduced now fails CI on the change
that introduces it rather than sitting in the backlog.

## Before you commit

```bash
pre-commit run --all-files     # actionlint, shellcheck, skillsaw
tox -eflake8                   # flake8 over the files HEAD touched
```

Both run in CI. `tox -eflake8` diffs against `HEAD~1`, so it reports
nothing until the change is committed -- run it after committing, and
amend if it complains.

## There are no unit tests

`kerbside_client/tests/` is an empty package: no test modules, and no
`.stestr.conf` for stestr to read. `tox` with no environment, or
`tox -epy3`, therefore does not work, and `ci.yml` deliberately runs no
test step. Adding the first test means adding `.stestr.conf`, a test
step to `ci.yml`, and the lint job stays in the automatic reviewer's
`needs:` list alongside it.

Treat this as the largest gap in the repository rather than as a
convention to preserve.

## Version handling

The version is derived from git tags by `setuptools_scm` and written to
`kerbside_client/_version.py` at build time. Three consequences:

* Never commit `_version.py`. It is gitignored, and a tracked copy
  shadows the build-time value and ships a stale version.
* `get_user_agent()` imports it and falls back to "unreleased
  development version". Do not reintroduce `pbr`, which this used to
  read the version through; it left with `setup.py`.
* There are no `v*` tags yet. Do not create one: nothing publishes this
  package, and tagging without the release automation in place produces
  a version number for a release that does not exist.

## Repository settings that the files depend on

Two things live in GitHub rather than in the tree, and a change to the
tree cannot fix either:

* `RETEST_WORKFLOW` must be the repository variable `ci.yml`.
  `pr-retest.yml` is copied verbatim from the fleet template and
  dispatches whatever that variable names, defaulting to
  `functional-tests.yml`, which does not exist here.
* Fork pull requests must stay behind "require approval for all
  external contributors" in Settings > Actions. `ci.yml` runs
  pull-request-controlled code on the shared, persistent `static`
  runner pool, and that setting is the only thing in front of it. If it
  is ever relaxed, those jobs move to the throwaway `vm` pool.

## Keep these two numbers in step

`requires-python` in `pyproject.toml` and `constraints.python` in
`renovate.json` state the same fact, and the `python-version` audit
fails if they disagree. Both come from the supported platform table in
`ARCHITECTURE.md`; change the table first.

## Generated files not to edit by hand

* `REVIEWS.md` and `.vscode/*.weaudit*` -- the human review marks,
  maintained by `tools/review-tracking.sh` and `prune-reviews.yml`.
* `.github/exported-config/` -- written by the daily
  `export-repo-config.yml` run from the live GitHub settings. Changing
  a setting means changing it in GitHub and letting the export follow.
* `.vscode/review-scope.toml` is the exception: it is hand-written
  policy deciding which files get reviewed, and a change to it needs
  the same review as a change to code.

## Known defects

Neither is fixed, and both have an issue:

* [#17](https://github.com/shakenfist/kerbside-client/issues/17):
  `_vv_helper()` refers to `temp_name` in the branch where the caller
  passed `--output`, where that name was never bound, so
  `console direct -o file.vv` raises `NameError` instead of launching
  the viewer.
* [#18](https://github.com/shakenfist/kerbside-client/issues/18):
  `kerbside-client version` cannot run without a server. The `cli`
  group constructs the API client -- which probes the server for its
  capabilities -- before any subcommand, so printing the client's own
  version requires a reachable Kerbside API.

## Documentation

There is no `docs/` directory. `README.md` is a pitch and points at the
Kerbside repository for everything about the server. When this grows
documentation beyond the two files in the root, it goes in `docs/`,
with a summary and a link left behind here -- not another section in
this file, which is loaded into every session.
