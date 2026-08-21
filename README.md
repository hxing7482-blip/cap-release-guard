# cap-release-guard

[![npm version](https://img.shields.io/npm/v/cap-release-guard)](https://www.npmjs.com/package/cap-release-guard)
[![CI](https://github.com/hxing7482-blip/cap-release-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/hxing7482-blip/cap-release-guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/npm/l/cap-release-guard)](LICENSE)
[![Node.js](https://img.shields.io/node/v/cap-release-guard)](package.json)

Catch unsafe Android and Capacitor release mistakes before they ship.

`cap-release-guard` (`crg`) is a CLI-first, local-first Android and Capacitor production release safety auditor. It checks project configuration, Android network policy, built web endpoints, APK manifest metadata, APK signatures, public signing certificates, and selected filing-helper values before a release leaves your machine.

- Node.js 20+
- No telemetry
- No cloud dependency
- No database
- No automatic Android SDK installation

## Project status

`v0.2.0` is published on npm. The project is early-stage, actively maintained, and evolving through public, reviewable releases. Public-safe issues and pull requests are welcome.

**Primary maintainer:** [@hxing7482-blip](https://github.com/hxing7482-blip)

## Why this exists

Production releases can accidentally retain debug signing, debuggable manifests, test endpoints, cleartext transport, or a certificate that does not match the expected public release certificate. These errors are inexpensive to detect before shipping and expensive to discover afterwards.

`cap-release-guard` provides repeatable checks suitable for local development and CI. It reports `PASS`, `WARN`, `BLOCKED`, or `TOOL_ERROR` without uploading artifacts.

## Features

- Detects Capacitor configuration and Android Gradle release/signing configuration.
- Audits release manifest and Android network-security XML cleartext settings.
- Never prints Gradle signing credential values.
- Reads APK package name, version, SDK levels, debuggable state, signer identity, certificate fingerprints, public-key information, and v1/v2/v3/v4 scheme status using locally installed Android tools.
- Blocks invalid APK signatures, debuggable APKs, and Android Debug signers.
- Scans built web assets for local, temporary-tunnel, non-production, cleartext HTTP, and policy-denied endpoints.
- Loads a versioned JSON-only project policy from `.releaseguard.json`.
- Compares an APK signer to a public certificate using MD5, SHA1, SHA256, and the public-key SPKI digest.
- Provides an explicitly experimental RSA public-data helper for filing workflows.
- Produces text, JSON, Markdown, and SARIF 2.1.0 reports with documented exit codes.

## Installation

```bash
npm install --global cap-release-guard
```

For repository development:

```bash
npm install
npm run build
node dist/cli/index.js --help
```

## Quick start

```bash
crg scan
crg scan --format sarif > cap-release-guard.sarif
crg endpoints ./dist --config .releaseguard.json
crg apk ./app-release.apk
crg compare --apk ./app-release.apk --cert ./release-public.cer
crg icp ./app-release.apk
```

## CLI commands

### `scan`

```bash
cap-release-guard scan --format text
cap-release-guard scan --config .releaseguard.json --format sarif
```

Scans the current directory for `capacitor.config.*`, the Android project directory, `applicationId`, Gradle release build type, `signingConfigs`, the release `signingConfig` binding, `usesCleartextTraffic`, and a referenced release network-security XML resource.

If a sensitive signing setting is referenced, only a generic warning is emitted; its value is never included. See [Android network security checks](docs/ANDROID_NETWORK_SECURITY.md).

### `apk`

```bash
cap-release-guard apk ./app-release.apk --format json
```

Uses Android SDK tools already present on the machine to inspect the manifest and validate the signature. It does not download an SDK.

### `endpoints`

```bash
cap-release-guard endpoints ./dist --allow 'approved-preview\\.example'
cap-release-guard endpoints ./dist --config .releaseguard.json
```

Scans common web text assets and reports only filename, stable rule ID, safe minimal context, and severity. A plain prose occurrence of the word `localhost` is not enough to fail: local-host findings require an endpoint URL or endpoint-style configuration assignment.

`--allow <pattern>` and `--deny <pattern>` may be repeated and accept case-insensitive regular expressions. Invalid regular expressions fall back to case-insensitive substring matching. Active deny patterns take precedence over active allow patterns.

### `compare`

```bash
cap-release-guard compare \
  --apk ./app-release.apk \
  --cert ./release-public.cer \
  --format markdown
```

Compares only public certificate material and reports `MATCH` or `MISMATCH`. Accepted certificate files are `.cer`, `.crt`, and `.der`.

### `icp`

```bash
cap-release-guard icp ./app-release.apk
```

For an RSA signer, the helper reports the Android package name, certificate MD5, RSA modulus decimal value, and RSA modulus hexadecimal value.

> Experimental helper. Always verify current filing-provider requirements.

This helper does not claim provider endorsement, government certification, or official filing certification.

## Project policy

A project may define a JSON-only `.releaseguard.json`:

```json
{
  "version": 1,
  "endpoints": {
    "allow": ["approved\\.example"],
    "deny": ["retired\\.example"]
  },
  "rules": {
    "android.cleartext-traffic": "blocked",
    "endpoint.cleartext-http": "warn"
  }
}
```

The CLI never executes project policy as JavaScript and does not perform environment or secret substitution. CLI overrides take precedence over configuration, which takes precedence over built-in defaults. See [Configuration](docs/CONFIGURATION.md).

## Output formats

Every command supports:

```bash
--format text
--format json
--format markdown
--format sarif
```

The JSON result model includes:

```json
{
  "status": "PASS",
  "checks": [],
  "summary": {
    "pass": 0,
    "warn": 0,
    "blocked": 0,
    "toolError": 0
  }
}
```

SARIF output follows SARIF 2.1.0, maps warnings and blocked findings to standard levels, uses stable rule IDs, and emits safe relative locations. See [SARIF output](docs/SARIF.md).

## Exit codes

| Code | Status       | Meaning                                                  |
| ---: | ------------ | -------------------------------------------------------- |
|    0 | `PASS`       | All completed checks passed.                             |
|    1 | `WARN`       | Review is recommended before release.                    |
|    2 | `BLOCKED`    | A definitive unsafe release condition was detected.      |
|    3 | `TOOL_ERROR` | Required input or a local analysis tool was unavailable. |

When both a definitive blocked condition and a tool error are present, `BLOCKED` takes precedence so a known unsafe artifact cannot be mistaken for an inconclusive run.

## GitHub Actions

The CI matrix runs on Node.js 20 and 22:

```bash
npm ci
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
```

The release workflow builds and uploads an npm package artifact for version tags. It does not publish to npm and does not require an npm publishing credential.

Example project gate after installing the package:

```yaml
- run: npx cap-release-guard scan --format sarif > cap-release-guard.sarif
  continue-on-error: true
- run: npx cap-release-guard endpoints ./dist --format markdown
```

## Security model

`cap-release-guard` never needs Android private signing keys.

By default, the project prohibits:

- Reading private signing keys.
- Reading keystore or signing credentials.
- Reading secret environment-file values.
- Telemetry or analytics.
- APK upload.
- Certificate upload.
- Cloud services or a database.

Runtime analysis is **100% local**. The `compare` command consumes only a public certificate. See [SECURITY.md](SECURITY.md).

## Android SDK requirements

For APK work, install the Android/JDK tooling through your normal trusted toolchain. `cap-release-guard` discovers existing executables from `PATH`, `ANDROID_SDK_ROOT`, or `ANDROID_HOME`:

- `apksigner` for signature verification and signer details.
- `apkanalyzer`, `aapt`, or `aapt2` for manifest metadata.
- `keytool` for the experimental public-certificate helper.

Missing tools produce `TOOL_ERROR`; the CLI never installs or downloads them.

## Capacitor usage

Run `crg scan` from the Capacitor project root after generating the Android platform. Run `crg endpoints` against the final web build directory, and run `crg apk` against the exact release artifact that will be distributed.

Static configuration files are parsed as text or JSON; JavaScript and TypeScript Capacitor configuration is not executed.

## Roadmap

### v0.2.0

- SARIF 2.1.0 reporting.
- Versioned project policy/configuration.
- Android release network-security checks.
- Expanded synthetic regression tests.

Future work may include broader manifest merging, more APK metadata fallbacks, baseline workflows for larger repositories, and reproducible release provenance helpers.

## Maintenance

- Use public GitHub issues for public-safe bug reports and feature proposals.
- Public-safe pull requests are welcome and must pass CI before release.
- Release changes require the complete format, lint, typecheck, test, and build gates.
- Security reports must follow [SECURITY.md](SECURITY.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) and use only synthetic, mock, or public-safe fixtures. Run all quality gates before opening a pull request.

## License

Apache License 2.0. See [LICENSE](LICENSE).
