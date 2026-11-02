/**
 * Platform detection and where each platform's engine lives inside the `ai-defender` package.
 *
 * The single npm package carries one engine per released platform under
 * `binaries/<platform>/` (the binary and its signed manifest). Only platforms whose engine passed
 * the test suite on that platform are bundled; the others have no directory. Linux engines are
 * static musl builds with no glibc requirement.
 */

export type PlatformKey = "linux-x64" | "linux-arm64" | "darwin-x64" | "darwin-arm64" | "win32-x64";

export interface PlatformTarget {
  key: PlatformKey;
  /** Directory of this platform's engine, relative to the package root. */
  bundleDir: string;
  /** Binary file name inside that directory's `bin/`. */
  binaryName: string;
  /** Rust target triple the binary is built for. */
  rustTarget: string;
  /** Whether the engine is known to build and pass its tests on this platform. */
  status: "validated" | "untested" | "unsupported";
  /** Explanation when not validated. */
  note?: string;
}

const TARGETS: Record<PlatformKey, PlatformTarget> = {
  "linux-x64": {
    key: "linux-x64",
    bundleDir: "binaries/linux-x64",
    binaryName: "agentguard-engine",
    rustTarget: "x86_64-unknown-linux-musl",
    status: "validated",
  },
  "linux-arm64": {
    key: "linux-arm64",
    bundleDir: "binaries/linux-arm64",
    binaryName: "agentguard-engine",
    rustTarget: "aarch64-unknown-linux-musl",
    status: "untested",
    note: "built by the release workflow from the same code as linux-x64; not yet tested on ARM64 hardware",
  },
  "darwin-x64": {
    key: "darwin-x64",
    bundleDir: "binaries/darwin-x64",
    binaryName: "agentguard-engine",
    rustTarget: "x86_64-apple-darwin",
    status: "untested",
    note: "built and unit-tested by the release workflow on macOS runners; end-to-end behaviour on macOS is not yet validated",
  },
  "darwin-arm64": {
    key: "darwin-arm64",
    bundleDir: "binaries/darwin-arm64",
    binaryName: "agentguard-engine",
    rustTarget: "aarch64-apple-darwin",
    status: "untested",
    note: "built and unit-tested by the release workflow on macOS runners; end-to-end behaviour on macOS is not yet validated",
  },
  "win32-x64": {
    key: "win32-x64",
    bundleDir: "binaries/win32-x64",
    binaryName: "agentguard-engine.exe",
    rustTarget: "x86_64-pc-windows-msvc",
    status: "unsupported",
    note: "the engine's trust store relies on Unix file ownership and permissions; a Windows implementation (ACLs) is not available yet",
  },
};

/** All known targets. */
export function allTargets(): PlatformTarget[] {
  return Object.values(TARGETS);
}

/** The target for an OS/CPU pair, or `undefined` when there is none. */
export function detectPlatform(platform: string, arch: string): PlatformTarget | undefined {
  const key = `${platform}-${arch}`;
  return Object.prototype.hasOwnProperty.call(TARGETS, key) ? TARGETS[key as PlatformKey] : undefined;
}
