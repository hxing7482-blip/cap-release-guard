#!/usr/bin/env node
import { resolve } from 'node:path';
import { Command } from 'commander';
import { analyzeApk } from '../android/apk.js';
import { compareApkAndCertificate } from '../android/compare.js';
import { inspectIcp } from '../android/icp.js';
import { scanCapacitorProject } from '../capacitor/scanner.js';
import { applyReleasePolicy, resolveReleasePolicy, type ReleasePolicy } from '../config/policy.js';
import { scanEndpoints } from '../endpoints/scanner.js';
import { render, isOutputFormat } from '../reporting/index.js';
import { exitCodeFor, toolError } from '../rules/result.js';
import type { AuditResult, OutputFormat } from '../types.js';
import { VERSION } from '../version.js';

interface FormatOptions {
  format: string;
}

interface PolicyOptions extends FormatOptions {
  config?: string;
  rule?: string[];
}

interface EndpointOptions extends PolicyOptions {
  allow?: string[];
  deny?: string[];
}

function output(result: AuditResult, requestedFormat: string): void {
  const format: OutputFormat = isOutputFormat(requestedFormat) ? requestedFormat : 'text';
  if (!isOutputFormat(requestedFormat)) {
    result = toolError('cli.format', 'Format must be text, json, markdown, or sarif.');
  }
  process.stdout.write(`${render(result, format)}\n`);
  process.exitCode = exitCodeFor(result.status);
}

async function runSafely(
  requestedFormat: string,
  operation: () => Promise<AuditResult>
): Promise<void> {
  try {
    output(await operation(), requestedFormat);
  } catch {
    output(toolError('cli.unexpected', 'The command could not complete safely.'), requestedFormat);
  }
}

async function runWithPolicy(
  options: PolicyOptions,
  endpointOverrides: Pick<EndpointOptions, 'allow' | 'deny'>,
  operation: (policy: ReleasePolicy) => Promise<AuditResult>
): Promise<void> {
  await runSafely(options.format, async () => {
    const resolution = await resolveReleasePolicy({
      cwd: process.cwd(),
      ...(options.config ? { configPath: options.config } : {}),
      cli: {
        ...(endpointOverrides.allow ? { allow: endpointOverrides.allow } : {}),
        ...(endpointOverrides.deny ? { deny: endpointOverrides.deny } : {}),
        ...(options.rule ? { rules: options.rule } : {}),
      },
    });
    if (!resolution.ok) return resolution.result;
    return applyReleasePolicy(await operation(resolution.policy), resolution.policy);
  });
}

function addFormatOption(command: Command): Command {
  return command.option(
    '--format <format>',
    'Output format: text, json, markdown, or sarif',
    'text'
  );
}

function collect(value: string, previous: string[] | undefined): string[] {
  return [...(previous ?? []), value];
}

function addPolicyOptions(command: Command): Command {
  return command
    .option('--config <path>', 'JSON policy path; defaults to .releaseguard.json when present')
    .option('--rule <id=severity>', 'Override a rule with off, warn, or blocked', collect);
}

const program = new Command();
program
  .name('cap-release-guard')
  .description('Catch unsafe Android and Capacitor release mistakes before they ship.')
  .version(VERSION);

addPolicyOptions(
  addFormatOption(
    program.command('scan').description('Scan the current Capacitor and Android project')
  )
).action(async (options: PolicyOptions) => {
  await runWithPolicy(options, {}, () => scanCapacitorProject(process.cwd()));
});

addPolicyOptions(
  addFormatOption(
    program
      .command('apk <apk>')
      .description('Inspect APK metadata, signing certificate, and schemes')
  )
).action(async (apk: string, options: PolicyOptions) => {
  await runWithPolicy(options, {}, () => analyzeApk(resolve(apk)));
});

addPolicyOptions(
  addFormatOption(
    program
      .command('endpoints <path>')
      .description('Scan built web assets for unsafe release endpoints')
      .option('--allow <pattern>', 'Replace configured allow patterns; repeatable', collect)
      .option('--deny <pattern>', 'Replace configured deny patterns; repeatable', collect)
  )
).action(async (path: string, options: EndpointOptions) => {
  await runWithPolicy(
    options,
    {
      ...(options.allow ? { allow: options.allow } : {}),
      ...(options.deny ? { deny: options.deny } : {}),
    },
    (policy) =>
      scanEndpoints(resolve(path), { allow: policy.endpointAllow, deny: policy.endpointDeny })
  );
});

addFormatOption(
  program
    .command('compare')
    .description('Compare an APK signer with a public certificate')
    .requiredOption('--apk <apk>', 'APK path')
    .requiredOption('--cert <cer>', 'Public .cer, .crt, or .der certificate path')
).action(async (options: FormatOptions & { apk: string; cert: string }) => {
  await runSafely(options.format, () =>
    compareApkAndCertificate(resolve(options.apk), resolve(options.cert))
  );
});

addFormatOption(
  program.command('icp <apk>').description('Show experimental RSA public filing helper values')
).action(async (apk: string, options: FormatOptions) => {
  await runSafely(options.format, () => inspectIcp(resolve(apk)));
});

await program.parseAsync(process.argv);
