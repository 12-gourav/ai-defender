# Releasing AI Defender

This document is for maintainers. Publishing is always a manual, deliberate act: nothing in
this repository publishes on its own, and no npm token is stored anywhere.

## What is published

| Package | Contents | Installed by |
|---|---|---|
| `ai-defender` | The CLI (`build/src`), `release-keys.json` (public keys only), README, SECURITY, LICENSE | `npm install -g ai-defender` |
| `ai-defender-engine-linux-x64` | Static musl engine binary, signed `engine-manifest.json`, LICENSE | npm, as an optional dependency, only on Linux x64 |
| `ai-defender-engine-linux-arm64` | as above | Linux arm64 |
| `ai-defender-engine-darwin-x64` | as above | macOS x64 |
| `ai-defender-engine-darwin-arm64` | as above | macOS arm64 |

Why this design:
- **npm installs only the matching engine.** Each engine package declares its `os` and `cpu`,
  and `ai-defender` lists all four as `optionalDependencies` pinned to the same version.
- **Nothing is downloaded at install time and no install script runs.** That works with
  `--ignore-scripts`, mirrors and offline caches, and npm's integrity checks cover every
  tarball.
- **The CLI verifies the engine before every use.** It checks the manifest's Ed25519
  signature, the platform, the protocol and the SHA-256, so a compromised registry account or
  mirror cannot swap the binary without the offline release key.
- **Unscoped names need no npm organisation.**

Windows is not published; `ai-defender` declares `os: ["linux", "darwin"]`.

## One-time setup

1. **The release key.** On an offline or otherwise trusted machine:

   ```bash
   openssl genpkey -algorithm ed25519 -out ai-defender-release-ed25519.pem
   chmod 600 ai-defender-release-ed25519.pem
   node cli/scripts/sign-engine-manifest.mjs --print-public-key --key ai-defender-release-ed25519.pem
   ```

   Add the printed `publicKey` to `cli/release-keys.json`:
   ```json
   { "publicKey": "<hex>", "label": "release 2026" }
   ```
   Commit it. Keep the private key offline, with a backup. Never commit it, never paste it into
   an issue or a log.
2. **GitHub environments** (Settings → Environments):
   - `release-signing`: required reviewers (at least one maintainer). Secret
     `ENGINE_RELEASE_SIGNING_KEY` holds the PEM contents. Restrict it to tags `v*`.
   - `npm-publish`: required reviewers, restricted to tags `v*`.
3. **npm trusted publishing** (npmjs.com, for each of the five packages, once it exists):
   - Settings → Trusted publishing → GitHub Actions;
   - the repository, workflow `release.yml` and environment `npm-publish`.

   With trusted publishing, the workflow authenticates with OIDC and npm records provenance. No
   token is created. A package must exist before a trusted publisher can be attached, so the
   **first** release of each package is published manually (below).
4. **Pin actions.** Pin the third-party actions in `.github/workflows/*.yml` to commit SHAs.

## Every release

```bash
# 1. Version (package, engine crates and optional dependencies must agree; pack:check enforces it)
#    edit Cargo.toml [workspace.package] version, cli/package.json version and optionalDependencies
cargo check --locked                     # updates nothing; fails if Cargo.lock needs a refresh
# 2. Full local gate
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --release --locked -p agentguard-engine-cli
(cd cli && npm ci && npm run lint && npm test && npm run pack:check && npm run e2e:install)
# 3. Tag and push; the release workflow builds, signs (after approval) and publishes (after approval)
git tag -s v0.1.0 -m "AI Defender 0.1.0" && git push origin v0.1.0
```

The workflow (`.github/workflows/release.yml`) runs these jobs:
1. **verify:** the tag matches every version, plus the full gate.
2. **build:** static musl Linux binaries (x64 natively, arm64 with `cross`) and native macOS
   binaries. The macOS runners also run the Rust tests.
3. **package:** needs approval. It assembles each engine package, signs its manifest with the
   release key, verifies it exactly as the CLI will (`verify-engine-package.mjs`), packs the
   five tarballs, and writes `SHA256SUMS`.
4. **publish:** needs approval. It publishes the four engine packages first, then
   `ai-defender`, with `--provenance` over OIDC.

## First publication (manual)

Trusted publishing can only be attached to packages that exist, so the first version of each
package is published by a maintainer from the workflow's `npm-packages` artifact. The tarballs
were built, signed and verified in CI.

```bash
npm login                                   # interactive, with 2FA
npm whoami
# download the npm-packages artifact of the release run, then verify it:
sha256sum -c SHA256SUMS
for t in ai-defender-engine-*.tgz; do npm publish "$t" --access public; done
npm publish ai-defender-0.1.0.tgz --access public
npm logout
```

Then attach the trusted publisher to all five packages (setup step 3). Consider requiring 2FA
and disallowing tokens for publishing, in each package's settings.

## Checks before anyone installs

```bash
npm view ai-defender version dist.integrity
npm install -g ai-defender@0.1.0
ai-defender --version
ai-defender doctor          # "Engine binary: verified release"
```

## If something goes wrong

- **A bad release.** `npm deprecate ai-defender@<version> "<reason>"`, then release a fix.
  Unpublishing is restricted by npm and breaks installs; prefer deprecation.
- **A compromised release key.**
  1. Remove its public key from `cli/release-keys.json`.
  2. Generate a new key.
  3. Re-sign and release new versions of all packages.
  4. Deprecate every version signed with the old key.

  Installed CLIs keep trusting the keys they shipped with until upgraded.
- **A compromised npm account.** The CLI refuses any engine whose manifest is not signed by a
  trusted release key. Rotate the npm credentials and review what was published.
