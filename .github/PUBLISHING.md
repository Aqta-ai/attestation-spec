# Publishing setup

This document covers how to release new versions of the verifier
libraries from this repository, and how to fix the two credibility gaps
flagged in early reviews:

1. Personal PyPI / npm account ownership (low institutional trust).
2. No supply-chain provenance on releases.

Both are fixed by setting up **trusted publishing via GitHub Actions
OIDC**, which is a one-time configuration step.

---

## PyPI: trusted publishing (recommended)

Once configured, releases happen automatically from CI when a tag is
pushed. PyPI verifies via OIDC that the publish came from this
repository, attaches a Sigstore provenance attestation, and the
package's PyPI page displays a "verified publisher" badge.

### One-time setup

1. Sign in to PyPI as the current owner of `aqta-verify-receipt`.
2. Go to
   <https://pypi.org/manage/project/aqta-verify-receipt/settings/publishing/>
3. Click **Add a new publisher**.
4. Fill in:
   - **PyPI Project Name**: `aqta-verify-receipt`
   - **Owner**: `Aqta-ai`
   - **Repository name**: `attestation-spec`
   - **Workflow filename**: `release-pypi.yml`
   - **Environment name**: `pypi`
5. Save.
6. In this GitHub repository, go to **Settings → Environments → New
   environment** and create one called `pypi`. No secrets needed.

### Releasing a new version

```bash
# Bump version in:
#   packages/verify-receipt-py/pyproject.toml
#   packages/verify-receipt-py/src/aqta_verify_receipt/__init__.py
# Update CHANGELOG.md.
# Commit, then:

git tag pyverify-v1.0.3
git push origin pyverify-v1.0.3
```

GitHub Actions builds, validates, and publishes. No tokens involved.

### Migrating from the personal account (optional, recommended)

If `aqta-verify-receipt` is currently owned by a personal PyPI account,
PyPI Organisations (in beta) lets you transfer ownership to an
organisation account:

1. Sign up at <https://pypi.org/account/register/>, accept invitation
   to the `Aqta` organisation (or create it).
2. Add the personal account as a maintainer of the new organisation.
3. From the project's **Settings → Collaborators** page, transfer
   ownership to the organisation.
4. Remove the personal account once the organisation is verified to
   own the project.

This step is optional but improves institutional trust; auditors who
inspect the PyPI page see a corporate publisher rather than an
individual.

---

## npm: provenance via OIDC

Less mature than PyPI's trusted publishing (Trusted Publishing on npm
is in beta and may require token fallback), but `npm publish
--provenance` already attaches a Sigstore attestation linking the
package to this workflow run.

### One-time setup

1. Generate a granular access token at
   <https://www.npmjs.com/settings/aqtaai/tokens/granular-access-tokens/new>
   - **Scope**: read and write on `aqta-verify-receipt`
   - **Bypass 2FA**: enabled (account 2FA must be on)
2. In this GitHub repository, go to **Settings → Secrets and variables
   → Actions → New repository secret**.
3. Name: `NPM_TOKEN`, value: the granular token from step 1.
4. Create a GitHub environment called `npm` (Settings → Environments).

### Releasing a new version

```bash
# Bump version in:
#   packages/verify-receipt/package.json
# Update CHANGELOG.md.
# Commit, then:

git tag tsverify-v1.0.3
git push origin tsverify-v1.0.3
```

GitHub Actions builds, tests, and publishes with provenance.

### Migrating to an org-owned npm package (optional)

The `aqta-ai` organisation already exists at
<https://www.npmjs.com/settings/aqta-ai/packages>. To move the package
under it:

1. Add the `aqta-ai` organisation as an owner from the package
   settings page on npmjs.com.
2. Optionally remove the personal-account ownership.
3. Future publishes work the same way; the package page now shows the
   organisation as the publisher.

---

## Security: rotate any tokens that have been pasted to a third party

Tokens used during interactive setup (typed into chat windows, pasted
into config files, shared with collaborators, etc.) should be revoked
once trusted publishing is configured:

- **PyPI tokens**:
  <https://pypi.org/manage/account/token/> → delete each unused token.
- **npm classic tokens**:
  <https://www.npmjs.com/settings/aqtaai/tokens> → delete each.
- **npm 2FA recovery codes**: if you have pasted any anywhere,
  disable and re-enable 2FA to invalidate them, then save the new
  recovery codes in a password manager.

After this, the only path to publish new versions is via this
repository's CI on a tag push, which is auditable in the GitHub Actions
log.
