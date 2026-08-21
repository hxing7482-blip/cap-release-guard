# Rule reference

## Project checks

`scan` detects Capacitor configuration, the Android platform directory, application identifiers, release build types, signing configuration declarations, and release signing bindings. Signing password values are never emitted.

## APK checks

`apk` validates the APK signature and blocks invalid signatures, `android:debuggable=true`, and certificates whose subject identifies the Android Debug signer. Manifest metadata and signature-scheme availability are included when local tools expose them.

## Endpoint checks

`endpoints` inspects only common text assets, skips symbolic links, skips dependency and Git metadata directories, and ignores files larger than 5 MiB. Findings include a single truncated line with URL credentials and sensitive query values redacted.

Default rules cover endpoint URLs using local hosts, temporary tunnel domains, `.test`/`.local` names, `uat`/`research` environment labels, and cleartext HTTP. Standards namespace URLs are excluded from the cleartext rule.

## Certificate comparison

`compare` verifies the APK first, parses a public X.509 certificate, and compares MD5, SHA1, SHA256, and the SHA256 digest of SubjectPublicKeyInfo. Any missing or unequal field results in `MISMATCH`.
