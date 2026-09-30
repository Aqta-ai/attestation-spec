#!/usr/bin/env bash
# One release, in the order that keeps the CHANGELOG true: packages first, main
# after, so "the published verifiers are fixed" is a fact when the commit
# claiming it lands on main. Every gate runs again immediately before
# publishing, because a green run from yesterday is not evidence about today's
# bytes.
#
# 1.2.7 carries the whole-string, ASCII-only matching fix. The Python package is
# the one whose verdicts change: until it is on PyPI, a record with a trailing
# line feed in a hash or timestamp, or non-ASCII digits in a timestamp, verifies
# for every pip user and fails for every npx user. npm carries the shared
# outcome reason, the tree head surrogate check and the history bundles.
#
# How each registry is reached (.github/PUBLISHING.md):
#   PyPI  trusted publishing (OIDC) in .github/workflows/release-pypi.yml,
#         started by pushing the tag pyverify-v1.2.7. No PyPI token is used.
#   npm   from this machine after `npm login`, as 1.2.6 was. publish.yml (npm
#         over OIDC on a GitHub Release) has failed with E404 on every run since
#         12 August 2026 because npm trusted publishing is not configured for
#         the package, so this script creates no GitHub Release. It pushes no
#         tsverify-v tag either, which would start release-npm.yml.
#
# PyPI goes first: it carries the fix and it is the less certain path. If its
# workflow fails, nothing has reached npm and main has not moved. Pushing the
# tag does make the release commit visible on GitHub under that tag before main
# moves; main moves only once both registries serve the version.
#
#   git switch main && git merge --ff-only release/1.2.7
#   npm login
#   bash scripts/release-1.2.7.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=packages/verify-receipt-py/src
VERSION=1.2.7
TAG="pyverify-v$VERSION"

fail() { echo "release-$VERSION: $*" >&2; exit 1; }

echo "== preconditions"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || fail "run from main, fast-forwarded to release/$VERSION"
[ -z "$(git status --porcelain)" ] || fail "the working tree is not clean"
command -v gh >/dev/null || fail "gh is needed to follow the PyPI workflow"
npm whoami >/dev/null || fail "npm is not logged in: run npm login first"
git fetch --quiet origin main
git merge-base --is-ancestor origin/main HEAD || fail "origin/main is not an ancestor of HEAD, so pushing main would not fast-forward"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then fail "$TAG already exists locally"; fi
[ -z "$(git ls-remote --tags origin "refs/tags/$TAG")" ] || fail "$TAG already exists on origin"
grep -q "\"version\": \"$VERSION\"" packages/verify-receipt/package.json || fail "package.json is not $VERSION"
grep -q "^version = \"$VERSION\"" packages/verify-receipt-py/pyproject.toml || fail "pyproject.toml is not $VERSION"
grep -q "^__version__ = \"$VERSION\"" packages/verify-receipt-py/src/aqta_verify_receipt/__init__.py || fail "__init__.py is not $VERSION"
grep -q "^## \[$VERSION\]" CHANGELOG.md || fail "CHANGELOG.md has no $VERSION entry"

echo "== gates"
( cd packages/verify-receipt && npm run build >/dev/null && npm test 2>&1 | grep -E "^ℹ (pass|fail)" )
python3 -m pytest packages -q -p no:fast_array_utils | tail -1
node scripts/make-interop-fixture.mjs | tail -1
node scripts/action-interop-sweep.mjs | tail -1
node scripts/bytes-interop-sweep.mjs | tail -1
node scripts/transparency-interop-sweep.mjs | tail -1
node scripts/differential-fuzz.mjs | tail -1
python3 scripts/proof-fuzz.py | tail -1
python3 scripts/conformance-report.py | tail -1
# The report is committed with the release; a rerun may move its date and nothing else.
changed=$(git diff -U0 -- CONFORMANCE-REPORT.md | grep -E '^[-+][^-+]' | grep -v '| Generated |' || true)
[ -z "$changed" ] || fail "CONFORMANCE-REPORT.md changed beyond its date: regenerate and commit it first"
git checkout -- CONFORMANCE-REPORT.md
( cd packages/verify-receipt-py && rm -rf dist build && python3 -m build >/dev/null && python3 -m twine check dist/* && rm -rf dist build )
[ -z "$(git status --porcelain)" ] || { git status --short; fail "the gates left the tree dirty"; }

echo "== pypi: push $TAG to start release-pypi.yml"
git tag -a "$TAG" -m "aqta-verify-receipt $VERSION (PyPI)" HEAD
git push origin "refs/tags/$TAG"
run=""
for _ in $(seq 1 24); do
  run=$(gh run list --workflow=release-pypi.yml --branch "$TAG" --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)
  [ -n "$run" ] && break
  sleep 5
done
[ -n "$run" ] || fail "no release-pypi.yml run appeared for $TAG; check Actions. npm and main are untouched"
gh run watch "$run" --exit-status || fail "release-pypi.yml run $run failed. npm and main are untouched"
pypi=""
for _ in $(seq 1 30); do
  # curl, not urllib: this machine's python has no CA bundle for pypi.org.
  pypi=$(curl -sf https://pypi.org/pypi/aqta-verify-receipt/json | python3 -c "import sys,json;print(json.load(sys.stdin)['info']['version'])" || true)
  [ "$pypi" = "$VERSION" ] && break
  sleep 10
done
echo "pypi: $pypi"
[ "$pypi" = "$VERSION" ] || fail "PyPI does not serve $VERSION yet. npm and main are untouched"

echo "== npm"
npm whoami
( cd packages/verify-receipt && npm publish --access public )
npmv=""
for _ in $(seq 1 30); do
  npmv=$(npm view aqta-verify-receipt version 2>/dev/null || true)
  [ "$npmv" = "$VERSION" ] && break
  sleep 5
done
echo "npm: $npmv"
[ "$npmv" = "$VERSION" ] || fail "npm does not serve $VERSION yet. main is untouched"

echo "== both registries serve $VERSION: push main"
git push origin main
echo "done: PyPI and npm serve $VERSION, main pushed, $TAG marks the published commit"
