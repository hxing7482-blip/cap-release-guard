#!/usr/bin/env node
import { resolve } from 'node:path';
import { Command } from 'commander';
import { analyzeApk } from '../android/apk.js';
import { compareApkAndCertificate } from '../android/compare.js';
import { inspectIcp } from '../android/icp.js';
import { scanCapacitorProject } from '../capacitor/scanner.js';
import { scanEndpoints } from '../endpoints/scanner.js';
import { render, isOutputFormat } from '../reporting/index.js';
import { exitCodeFor, toolError } from '../rules/result.js';
import type { AuditResult, OutputFormat } from '../types.js';

interface FormatOptions {
  format: string;
}

function output(result: AuditResult, requestedFormat: string): void {
  const format: OutputFormat = isOutputFormat(requestedFormat) ? requestedFormat : 'text';
  if (!isOutputFormat(requestedFormat)) {
    result = toolError('cli.format', 'Format must be text, json, or markdown.');
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

function addFormatOption(command: Command): Command {
  return command.option('--format <format>', 'Output format: text, json, or markdown', 'text');
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

const program = new Command();
program
  .name('cap-release-guard')
  .description('Catch unsafe Android and Capacitor release mistakes before they ship.')
  .version('0.1.0');

addFormatOption(
  program.command('scan').description('Scan the current Capacitor and Android project')
).action(async (options: FormatOptions) => {
  await runSafely(options.format, () => scanCapacitorProject(process.cwd()));
});

addFormatOption(
  program.command('apk <apk>').description('Inspect APK metadata, signing certificate, and schemes')
).action(async (apk: string, options: FormatOptions) => {
  await runSafely(options.format, () => analyzeApk(resolve(apk)));
});

addFormatOption(
  program
    .command('endpoints <path>')
    .description('Scan built web assets for unsafe release endpoints')
    .option('--allow <pattern>', 'Allow a matching endpoint or filename pattern', collect, [])
).action(async (path: string, options: FormatOptions & { allow: string[] }) => {
  await runSafely(options.format, () => scanEndpoints(resolve(path), options.allow));
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
