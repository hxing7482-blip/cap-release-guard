# Android network security checks

The `scan` command statically inspects Android release network policy without executing Gradle, Android configuration code, or XML entities.

## Manifest cleartext setting

The rule `android.cleartext-traffic` evaluates the effective release `<application>` setting:

```xml
<application android:usesCleartextTraffic="true" />
```

An explicit `true` is blocked by default. An explicit `false`, or an absent attribute, passes this check. A project policy can change the unsafe finding to `warn` or `off`.

The scanner reads only these production-relevant source sets:

- `android/app/src/main/AndroidManifest.xml`
- `android/app/src/release/AndroidManifest.xml`

A value from the release manifest takes precedence over the main manifest. Debug and test manifests are not treated as production inputs.

## Network security configuration

When the effective manifest references a static resource such as:

```xml
<application android:networkSecurityConfig="@xml/network_security_config" />
```

`scan` resolves `res/xml/network_security_config.xml`. A release source-set resource takes precedence over the main resource. The rule `android.network-security.cleartext` blocks:

- `<base-config cleartextTrafficPermitted="true">`
- `<domain-config cleartextTrafficPermitted="true">`
- domains explicitly included by such a domain configuration

A finding contains only the stable rule ID, relative XML path, reliable line number, severity, and a normalized domain when available. It never includes the full XML document.

## Debug-only overrides

`<debug-overrides>` is excluded from release cleartext evaluation. Its presence is reported as a passing informational check and is not mechanically treated as a production failure.

## Current limitations

- This is a conservative static analysis, not a full Android manifest merger.
- Only the conventional `main` and `release` source sets are evaluated.
- Resource references must use a static `@xml/name` form.
- Nested or generated variant-specific resources outside those source sets require separate review.
- Android platform defaults can vary by target SDK; the absent attribute is reported as not explicitly enabling cleartext rather than as a guarantee about runtime behavior.
