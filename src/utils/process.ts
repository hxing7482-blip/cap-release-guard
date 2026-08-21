import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { delimiter, extname, join } from 'node:path';

export interface ToolResult {
  code: number;
  stdout: string;
  stderr: string;
  error?: string;
}

export interface AndroidTools {
  apksigner?: string;
  apkanalyzer?: string;
  aapt?: string;
  aapt2?: string;
  keytool?: string;
}

function executableCandidates(name: string): string[] {
  if (process.platform !== 'win32') return [name];
  return [`${name}.exe`, `${name}.cmd`, `${name}.bat`, name];
}

export function findExecutable(
  name: string,
  pathValue = process.env.PATH ?? ''
): string | undefined {
  for (const directory of pathValue.split(delimiter).filter(Boolean)) {
    for (const candidate of executableCandidates(name)) {
      const fullPath = join(directory.replace(/^"|"$/g, ''), candidate);
      if (existsSync(fullPath)) return fullPath;
    }
  }
  return undefined;
}

function latestBuildToolsDirectory(sdkRoot: string): string | undefined {
  const buildTools = join(sdkRoot, 'build-tools');
  if (!existsSync(buildTools)) return undefined;
  const versions = readdirSync(buildTools, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort((left, right) => right.localeCompare(left, undefined, { numeric: true }));
  return versions[0] ? join(buildTools, versions[0]) : undefined;
}

function findInDirectory(directory: string | undefined, name: string): string | undefined {
  if (!directory) return undefined;
  for (const candidate of executableCandidates(name)) {
    const fullPath = join(directory, candidate);
    if (existsSync(fullPath)) return fullPath;
  }
  return undefined;
}

export function discoverAndroidTools(
  env: NodeJS.ProcessEnv = process.env,
  pathValue = env.PATH ?? ''
): AndroidTools {
  const conventionalSdkRoot = env.LOCALAPPDATA
    ? join(env.LOCALAPPDATA, 'Android', 'Sdk')
    : undefined;
  const sdkRoot = env.ANDROID_SDK_ROOT ?? env.ANDROID_HOME ?? conventionalSdkRoot;
  const buildTools = sdkRoot ? latestBuildToolsDirectory(sdkRoot) : undefined;
  const cmdlineLatest = sdkRoot ? join(sdkRoot, 'cmdline-tools', 'latest', 'bin') : undefined;
  const toolsBin = sdkRoot ? join(sdkRoot, 'tools', 'bin') : undefined;
  const javaBin = env.JAVA_HOME ? join(env.JAVA_HOME, 'bin') : undefined;

  const apksigner =
    findExecutable('apksigner', pathValue) ?? findInDirectory(buildTools, 'apksigner');
  const apkanalyzer =
    findExecutable('apkanalyzer', pathValue) ??
    findInDirectory(cmdlineLatest, 'apkanalyzer') ??
    findInDirectory(toolsBin, 'apkanalyzer');
  const aapt = findExecutable('aapt', pathValue) ?? findInDirectory(buildTools, 'aapt');
  const aapt2 = findExecutable('aapt2', pathValue) ?? findInDirectory(buildTools, 'aapt2');
  const keytool = findExecutable('keytool', pathValue) ?? findInDirectory(javaBin, 'keytool');

  return {
    ...(apksigner ? { apksigner } : {}),
    ...(apkanalyzer ? { apkanalyzer } : {}),
    ...(aapt ? { aapt } : {}),
    ...(aapt2 ? { aapt2 } : {}),
    ...(keytool ? { keytool } : {}),
  };
}

function quoteForCmd(value: string): string {
  const escaped = value.replaceAll('%', '%%').replaceAll('"', '""');
  return `"${escaped}"`;
}

export function runTool(executable: string, args: string[]): ToolResult {
  const isBatch =
    process.platform === 'win32' && ['.bat', '.cmd'].includes(extname(executable).toLowerCase());
  const command = isBatch ? (process.env.ComSpec ?? 'cmd.exe') : executable;
  const commandArgs = isBatch
    ? ['/d', '/s', '/c', [quoteForCmd(executable), ...args.map(quoteForCmd)].join(' ')]
    : args;
  const result = spawnSync(command, commandArgs, {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 30_000,
    maxBuffer: 10 * 1024 * 1024,
  });

  return {
    code: result.status ?? (result.error ? 3 : 0),
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    ...(result.error ? { error: result.error.message } : {}),
  };
}
