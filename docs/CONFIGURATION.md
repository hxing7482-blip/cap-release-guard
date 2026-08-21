# Project configuration

`cap-release-guard` supports a versioned, JSON-only project policy in `.releaseguard.json`. Configuration is parsed as data and is never executed.

## Schema version 1

```json
{
  "version": 1,
  "endpoints": {
    "allow": [],
    "deny": []
  },
  "rules": {
    "android.debuggable": "blocked",
    "android.debugSigner": "blocked",
    "endpoint.cleartextHttp": "warn"
  }
}
```

The documented camel-case rule aliases are accepted and normalized to stable IDs:

- `android.debugSigner` → `android.debug-signer`
- `endpoint.cleartextHttp` → `endpoint.cleartext-http`

Rule values are `off`, `warn`, or `blocked`. Overrides apply only to an unsafe finding; they do not turn a passing check into a failure. `TOOL_ERROR` cannot be suppressed by a severity override.

## Loading and precedence

Commands automatically load `.releaseguard.json` from the current working directory when it exists. Use an explicit path when required:

```bash
cap-release-guard scan --config .releaseguard.json
cap-release-guard endpoints ./dist --config .releaseguard.json
```

Precedence, from highest to lowest, is:

1. CLI overrides.
2. `.releaseguard.json`.
3. Built-in v0.1-compatible defaults.

`--rule <id=severity>` may be repeated. If at least one `--allow` is provided, the complete CLI allow list replaces `endpoints.allow`; repeated CLI values form that replacement list. `--deny` behaves the same way. Within the active endpoint lists, deny takes precedence over allow.

```bash
cap-release-guard endpoints ./dist \
  --allow 'approved\\.example' \
  --deny 'retired\\.example' \
  --rule endpoint.cleartext-http=warn
```

## Validation and safety

- Invalid JSON, an unsupported schema version, unknown properties, unknown rule IDs, or invalid severity values produce `TOOL_ERROR`.
- The configuration format is JSON only. Explicit config paths must end in .json; JavaScript, TypeScript, environment files, and other formats are rejected before reading.
- Environment-variable and secret substitution are not supported.
- The loader does not read `.env` files.
- Endpoint patterns are case-insensitive regular expressions. Invalid expressions fall back to case-insensitive substring matching.
- Configuration errors report only a safe relative filename and never echo the configuration contents.
