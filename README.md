# cap-release-guard

Catch unsafe Android and Capacitor release mistakes before they ship.

`cap-release-guard` (`crg`) is a CLI-first, local-first Android and Capacitor production release safety auditor. It checks project configuration, built web endpoints, APK manifest metadata, APK signatures, public signing certificates, and selected filing-helper values before a release leaves your machine.

- Node.js 20+
- No telemetry
- No cloud dependency
- No database
- No automatic Android SDK installation

## Why this exists

Production releases can accidentally retain debug signing, debuggable manifests, test endpoints, cleartext transport, or a certificate that does not match the expected public release certificate. These errors are inexpensive to detect before shipping and expensive to discover afterwards.

`cap-release-guard` provides repeatable checks suitable for local development and CI. It reports `PASS`, `WARN`, `BLOCKED`, or `TOOL_ERROR` without uploading artifacts.

## Features

- Detects Capacitor configuration and Android Gradle release/signing configuration.
- Never prints Gradle signing password values.
- Reads APK package name, version, SDK levels, debuggable state, signer identity, certificate fingerprints, public-key information, and v1/v2/v3/v4 scheme status using locally installed Android tools.
- Blocks invalid APK signatures, debuggable APKs, and Android Debug signers.
- Scans built web assets for local, temporary-tunnel, non-production, and cleartext HTTP endpoints with an allowlist.
- Compares an APK signer to a public certificate using MD5, SHA1, SHA256, and the public-key SPKI digest.
- Provides an explicitly experimental RSA public-data helper for filing workflows.
- Produces text, JSON, and Markdown reports with documented exit codes.

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

## Quick Start

```bash
crg scan
crg endpoints ./dist
crg apk ./app-release.apk
crg compare --apk ./app-release.apk --cert ./release-public.cer
crg icp ./app-release.apk
```

## CLI Commands

### `scan`

```bash
cap-release-guard scan --format text
```

Scans the current directory for `capacitor.config.*`, the Android project directory, `applicationId`, Gradle release build type, `signingConfigs`, and the release `signingConfig` binding. If a `storePassword` or `keyPassword` reference exists, the only signing-secret-related message is `Sensitive signing configuration reference detected`; values are never included.

### `apk`

```bash
cap-release-guard apk ./app-release.apk --format json
```

Uses Android SDK tools already present on the machine to inspect the manifest and validate the signature. It does not download an SDK.

### `endpoints`

```bash
cap-release-guard endpoints ./dist --allow 'approved-preview\\.example'
```

Scans common web text assets and reports only filename, rule, safe minimal context, and severity. A plain prose occurrence of the word `localhost` is not enough to fail: local-host findings require an endpoint URL or endpoint-style configuration assignment.

`--allow <pattern>` may be repeated and accepts a case-insensitive regular expression. Invalid regular expressions fall back to case-insensitive substring matching.

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

## Output formats

Every command supports:

```bash
--format text
--format json
--format markdown
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

## Exit codes

| Code | Status       | Meaning                                                  |
| ---: | ------------ | -------------------------------------------------------- |
|    0 | `PASS`       | All completed checks passed.                             |
|    1 | `WARN`       | Review is recommended before release.                    |
|    2 | `BLOCKED`    | A definitive unsafe release condition was detected.      |
|    3 | `TOOL_ERROR` | Required input or a local analysis tool was unavailable. |

When both a definitive blocked condition and a tool error are present, `BLOCKED` takes precedence so a known unsafe artifact cannot be mistaken for an inconclusive run.

## GitHub Actions

A CI matrix for Node.js 20 and 22 runs:

```bash
npm ci
npm run lint
npm run typecheck
npm test
npm run build
```

The release workflow builds and uploads an npm package artifact for version tags. It does not publish to npm and does not require an npm publishing credential.

Example project gate after installing the package:

```yaml
- run: npx cap-release-guard scan --format markdown
- run: npx cap-release-guard endpoints ./dist --format markdown
```

## Security model

`cap-release-guard never needs Android private signing keys.`

By default, the project prohibits:

- Reading private signing keys.
- Reading keystore or key passwords.
- Reading secret `.env` values.
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

- Broader Android manifest and network-security checks.
- Machine-readable rule configuration.
- Baseline and policy files for larger repositories.
- More APK metadata fallbacks.
- Reproducible release provenance helpers.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) and use only synthetic, mock, or public-safe fixtures. Run all quality gates before opening a pull request.

## License

Apache License 2.0. See [LICENSE](LICENSE).
