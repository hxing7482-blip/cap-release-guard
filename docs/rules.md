# Rule reference

Rule IDs are stable public identifiers. Policy configuration and SARIF consumers should depend on the IDs rather than message text.

## Project and Android rules

| Rule ID                              | Default unsafe status | Purpose                                                                  |
| ------------------------------------ | --------------------- | ------------------------------------------------------------------------ |
| `android.debuggable`                 | `BLOCKED`             | Detects a debuggable APK.                                                |
| `android.debug-signer`               | `BLOCKED`             | Detects the Android Debug signer.                                        |
| `android.cleartext-traffic`          | `BLOCKED`             | Detects an effective release manifest that explicitly enables cleartext. |
| `android.network-security.cleartext` | `BLOCKED`             | Detects release network-security XML that permits cleartext.             |
| `android.signing.missing-release`    | `WARN`                | Detects a missing release signing binding in the Gradle file.            |

`scan` also detects Capacitor configuration, the Android platform directory, application identifiers, release build types, and signing configuration declarations. Signing credential values are never emitted.

## Endpoint rules

| Rule ID                   | Default unsafe status | Purpose                                           |
| ------------------------- | --------------------- | ------------------------------------------------- |
| `endpoint.localhost`      | `BLOCKED`             | Detects local hosts in endpoint contexts.         |
| `endpoint.cleartext-http` | `BLOCKED`             | Detects non-exempt cleartext HTTP URLs.           |
| `endpoint.tunnel`         | `BLOCKED` or `WARN`   | Detects temporary tunnel endpoints or references. |
| `endpoint.non-production` | `WARN`                | Detects test, local, UAT, or research hostnames.  |
| `endpoint.policy-deny`    | `BLOCKED`             | Detects a URL matched by the active deny policy.  |

`endpoints` inspects only common text assets, skips symbolic links, skips dependency and Git metadata directories, and ignores files larger than 5 MiB. Findings include a single truncated line with URL credentials and sensitive query values redacted. Standards namespace URLs are excluded from the default cleartext rule.

## Certificate comparison

`certificate.mismatch` blocks a mismatch between an APK signer and a public X.509 certificate. The comparison covers MD5, SHA1, SHA256, and the SHA256 digest of SubjectPublicKeyInfo. Any missing or unequal field results in `MISMATCH`.

## Informational and tool checks

Additional IDs cover passing metadata, missing inputs, and local tool failures. These IDs remain deterministic, but the policy-configurable security rules are the stable IDs listed above.
