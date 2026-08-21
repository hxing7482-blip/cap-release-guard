# SARIF output

`cap-release-guard` can emit deterministic SARIF 2.1.0 for GitHub Code Scanning and other SARIF consumers.

## Commands

SARIF is available through `--format sarif`, including for the primary release gates:

```bash
cap-release-guard scan --format sarif > cap-release-guard-scan.sarif
cap-release-guard apk ./app-release.apk --format sarif > cap-release-guard-apk.sarif
cap-release-guard endpoints ./dist --format sarif > cap-release-guard-endpoints.sarif
```

`PASS` checks do not create SARIF results. `WARN` maps to `warning`; `BLOCKED` and `TOOL_ERROR` map to `error`. Tool failures also set `executionSuccessful` to `false` and create an execution notification.

## GitHub Code Scanning

A workflow can upload the report with GitHub's SARIF action:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: 20
  - run: npm ci
  - run: npx cap-release-guard scan --format sarif > cap-release-guard.sarif
    continue-on-error: true
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: cap-release-guard.sarif
```

Keep the scan step's exit code available to a separate release gate when a blocked finding must fail the workflow.

## Output example

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "cap-release-guard",
          "rules": []
        }
      },
      "results": []
    }
  ]
}
```

## Safety and current limitations

- Rule IDs and result ordering are stable and deterministic.
- File locations use repository-relative paths. Absolute input paths are reduced to a safe filename.
- Reports contain finding messages and minimal locations, not full source or XML content.
- SARIF output does not merge multiple command runs; upload separate reports or combine them with a SARIF-aware tool.
- The CLI does not upload SARIF itself.
