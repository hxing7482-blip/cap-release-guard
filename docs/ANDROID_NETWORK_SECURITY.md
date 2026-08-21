# Android network security checks

The `scan` command statically inspects Android release network policy without executing Gradle, Android configuration code, XML entities, or external resources.

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

`scan` resolves `res/xml/network_security_config.xml`. A release source-set resource takes precedence over the main resource. The rule `android.network-security.cleartext` blocks cleartext enabled by a `base-config` or by an effective `domain-config` policy.

Nested `domain-config` elements are supported. The scanner computes the effective `cleartextTrafficPermitted` value in this order:

1. `base-config`
2. top-level `domain-config`
3. nested `domain-config`
4. each deeper nested `domain-config`

An explicit child value overrides the inherited parent value. A child with no explicit value inherits its parent, and a top-level domain configuration with no explicit value inherits `base-config`. Only direct `domain` children belong to a given `domain-config`, so a more-specific nested child can safely override its parent without its domain being attributed to the parent. The `includeSubdomains` value is parsed as a boolean and included in unsafe domain finding details.

A finding contains only the stable rule ID, relative XML path, reliable line number, severity, and normalized public-safe details. It never includes the full XML document.

## Constrained, non-executing XML parser

The network security parser is deliberately small and structural. It understands `network-security-config`, `base-config`, `domain-config`, `domain`, `debug-overrides`, `cleartextTrafficPermitted`, and `includeSubdomains`. It tracks other ordinary element subtrees only to preserve XML nesting; it does not execute or semantically evaluate them.

The parser never resolves DTDs, declared entities, XInclude, processing instructions other than the XML declaration, or external resources. DTD, ENTITY, XInclude, unsupported entity references, malformed nesting, and other unsupported declaration constructs fail closed with a generic `TOOL_ERROR`. Error output does not echo the XML document.

## Debug-only overrides

`debug-overrides` and its complete subtree are excluded from release cleartext evaluation. Its presence is reported as a passing informational check and is not mechanically treated as a production failure.

## Current limitations

- This is a conservative static analysis, not a full Android manifest merger or a general-purpose XML implementation.
- Only the conventional `main` and `release` source sets are evaluated.
- Resource references must use a static `@xml/name` form.
- Generated variant-specific resources outside those source sets require separate review.
- Trust anchors, certificate pinning, certificate source semantics, and other network security fields are not audited in this release.
- Android platform defaults can vary by target SDK; an absent value with no inherited explicit value is reported as not explicitly enabling cleartext rather than as a guarantee about runtime behavior.
