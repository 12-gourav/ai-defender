# Releasing AI Defender

For maintainers. Publishing is a manual, deliberate act: nothing in this repository signs or
publishes on its own, and no signing key or npm credential is stored anywhere in it.

## What is published

One package, `ai-defender`:

| Path | Contents |
|---|---|
| `build/src/` | The CLI |
| `binaries/<platform>/bin/agentguard-engine` | The engine for that platform |
| `binaries/<platform>/engine-manifest.json` | Its version, platform, protocol and SHA-256, signed with the release key |
| `release-keys.json` | Public release keys only |
| `README.md`, `SECURITY.md`, `LICENSE` | Copied from the repository root by `npm run sync-docs` |

Released platforms: `linux-x64`, `linux-arm64` (static musl), `darwin-x64`, `darwin-arm64`.
`win32-x64` is not released yet: it needs a green `tests (win32-x64)` CI job, a Windows entry in
the release workflow, a Windows global-install test, and `win32` in `os` (KNOWN_LIMITATIONS L117
to L124).
`package.json` declares exactly those in `os` and `cpu`; `npm run pack:check -- --release` refuses
a package whose `os`/`cpu` and bundled engines differ. Windows is not released (see
`KNOWN_LIMITATIONS.md`).

Why one package with every engine: users install one name, nothing is downloaded or run at
install time, it works with `--ignore-scripts`, mirrors and offline caches, and npm's integrity
hash covers every engine. Each engine is 4 to 6 MB.

Why signing stays on the maintainer's machine: CI builds and tests each engine on its own
platform's runner, but the key that makes the CLI trust an engine never leaves the release
owner's computer. A compromised CI run can produce a bad binary; it cannot produce a trusted one.

## One-time setup

1. **Release key** (already done for 0.1.x; reuse it). Kept at `~/ai-defender-keys/release.pem`,
   mode 600, backed up offline. Its public key is in `cli/release-keys.json`. To create one:
   ```bash
   mkdir -p ~/ai-defender-keys && chmod 700 ~/ai-defender-keys
   node -e 'const {generateKeyPairSync}=require("crypto");const {privateKey}=generateKeyPairSync("ed25519");require("fs").writeFileSync(process.argv[1],privateKey.export({format:"pem",type:"pkcs8"}),{mode:0o600})' ~/ai-defender-keys/release.pem
   node cli/scripts/sign-engine-manifest.mjs --print-public-key --key ~/ai-defender-keys/release.pem
   ```
   Add the printed key to `cli/release-keys.json` as `{ "publicKey": "<hex>", "label": "..." }`.
2. **npm**: `npm login` on the release machine, with 2FA.

## Every release

```bash
# 1. Versions: Cargo.toml [workspace.package] and cli/package.json must match
#    (pack:check enforces it); refresh the lock files.
cargo check --workspace
(cd cli && npm install --package-lock-only)

# 2. Local gate
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
(cd cli && npm ci && npm run lint && npm test && npm run pack:check)

# 3. Commit, push, and tag. The tag starts the release-engines workflow, which on each
#    platform's runner runs the Rust suite, builds the release engine and runs the
#    global-install test with that exact binary.
git tag -a v0.2.0 -m "AI Defender 0.2.0" && git push origin main v0.2.0
```

When all four `engine *` jobs are green, download their artifacts (`engine-linux-x64`,
`engine-linux-arm64`, `engine-darwin-x64`, `engine-darwin-arm64`) into `artifacts/`, then:

```bash
V=0.2.0
rm -rf cli/binaries
for p in linux-x64 linux-arm64 darwin-x64 darwin-arm64; do
  (cd artifacts/engine-$p && shasum -a 256 -c agentguard-engine.sha256)
  node cli/scripts/stage-engine.mjs --platform $p --binary artifacts/engine-$p/agentguard-engine --version $V
  node cli/scripts/sign-engine-manifest.mjs --manifest cli/binaries/$p/engine-manifest.json --key ~/ai-defender-keys/release.pem
done
cd cli
npm run build
node scripts/verify-engine-package.mjs --all     # every engine verifies as the CLI will
npm run pack:check -- --release                   # os/cpu match the engines; no stray files
npm pack                                          # ai-defender-$V.tgz

# Install the exact tarball in a throwaway prefix and check it.
npm install -g --prefix /tmp/ad-check ./ai-defender-$V.tgz
HOME=/tmp/ad-check/home /tmp/ad-check/bin/ai-defender doctor   # "Engine binary: verified release"
```

Then publish, and check what npm serves:

```bash
npm view ai-defender@$V version 2>/dev/null && echo "already published: stop"
npm whoami
npm publish ./ai-defender-$V.tgz --access public
npm view ai-defender@$V dist.integrity
```

Publish exactly the tarball that was checked.

## If something goes wrong

- **A bad release.** `npm deprecate ai-defender@<version> "<reason>"`, then release a fix.
  Do not unpublish: npm then blocks the whole package name for 24 hours and the version number
  can never be reused (this happened to 0.1.0 and 0.1.1).
- **A compromised release key.** Remove its public key from `cli/release-keys.json`, create a
  new key, release a new version, and deprecate every version signed with the old key.
  Installed CLIs keep trusting the keys they shipped with until upgraded.
- **A compromised npm account.** The CLI refuses any engine whose manifest is not signed by a
  release key it ships with, but an attacker who can publish can also ship a new key list. Rotate
  the npm credentials, review what was published, and deprecate it.
