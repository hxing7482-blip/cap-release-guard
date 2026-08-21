# Architecture

The CLI delegates to small local analyzers and converts every outcome into a common result model. Reporters do not invoke analysis tools. Android subprocesses use explicit argument arrays and bounded output. Capacitor configuration is never executed. Endpoint scanning is bounded by file type and size.

No component includes telemetry, analytics, remote storage, an upload path, or a database client.
