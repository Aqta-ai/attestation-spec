#!/usr/bin/env bash
# One release, in the order that keeps the CHANGELOG true: packages first, repo
# after, so "the published verifiers are fixed" is a fact when the commit
# claiming it lands. Every gate runs again immediately before publishing,
# because a green run from yesterday is not evidence about today's bytes.
#
#   npm login                       # or export NPM_TOKEN
#   export TWINE_USERNAME=__token__ # project-scoped PyPI token
#   export TWINE_PASSWORD=pypi-...
#   bash scripts/release-1.2.3.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== gates"
( cd packages/verify-receipt && npm run build >/dev/null && npm test 2>&1 | grep -E "^ℹ (pass|fail)" )
python3 -m pytest packages -q | tail -1
node scripts/differential-fuzz.mjs | tail -1
node scripts/action-interop-sweep.mjs | tail -1
node scripts/transparency-interop-sweep.mjs | tail -1
python3 scripts/proof-fuzz.py | tail -1
python3 scripts/conformance-report.py | tail -1

echo "== versions"
grep -m1 '"version"' packages/verify-receipt/package.json
grep -m1 '^version' packages/verify-receipt-py/pyproject.toml

echo "== npm"
npm whoami
( cd packages/verify-receipt && npm publish --access public )

echo "== pypi"
( cd packages/verify-receipt-py && rm -rf dist && python3 -m build && python3 -m twine upload dist/* )

echo "== confirm both registries serve 1.2.3, then push"
npm view aqta-verify-receipt version
python3 - <<'PY'
import json, urllib.request
print('pypi:', json.load(urllib.request.urlopen('https://pypi.org/pypi/aqta-verify-receipt/json'))['info']['version'])
PY
git push origin main
echo "done: packages published, repo pushed"
