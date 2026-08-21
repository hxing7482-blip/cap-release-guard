# Security Policy

## Supported versions

Security fixes are provided for the latest released version.

## Local-first security model

`cap-release-guard never needs Android private signing keys.`

The tool must not read private keys, keystore passwords, key passwords, or secret `.env` values. It provides no telemetry or analytics and does not upload APKs or certificates. Analysis is performed locally using files the operator explicitly selects and Android SDK tools already installed on the machine.

## Reporting a vulnerability

Please report vulnerabilities through GitHub private vulnerability reporting when available. Do not include real credentials, private keys, proprietary APKs, or confidential project data in a report. Use synthetic reproduction material.
