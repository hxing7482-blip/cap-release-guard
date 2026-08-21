import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';
import { createResult } from '../rules/result.js';
import { canonicalRuleId, type ConfigurableRuleId } from '../rules/ids.js';
import type { AuditResult, Check, Status } from '../types.js';

export type RuleSeverity = 'off' | 'warn' | 'blocked';

export interface ReleasePolicy {
  endpointAllow: string[];
  endpointDeny: string[];
  rules: Partial<Record<ConfigurableRuleId, RuleSeverity>>;
}

export interface PolicyCliOverrides {
  allow?: string[];
  deny?: string[];
  rules?: string[];
}

export interface ResolvePolicyOptions {
  cwd: string;
  configPath?: string;
  cli?: PolicyCliOverrides;
}

export type PolicyResolution =
  { ok: true; policy: ReleasePolicy; configLocation?: string } | { ok: false; result: AuditResult };

type ParsedConfig = { ok: true; policy: ReleasePolicy } | { ok: false; message: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function safeLocation(cwd: string, path: string): string {
  const candidate = relative(cwd, path).replaceAll('\\', '/');
  if (!candidate || candidate === '.') return '.releaseguard.json';
  if (candidate.startsWith('../') || candidate === '..') return basename(path);
  return candidate;
}

function configError(id: string, message: string, location: string): AuditResult {
  return createResult([{ id, status: 'TOOL_ERROR', message, location }]);
}

function parseSeverity(value: unknown): RuleSeverity | undefined {
  return value === 'off' || value === 'warn' || value === 'blocked' ? value : undefined;
}

export function parseReleaseGuardConfig(content: string): ParsedConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return { ok: false, message: 'Configuration must contain valid JSON.' };
  }

  if (!isRecord(parsed)) {
    return { ok: false, message: 'Configuration root must be a JSON object.' };
  }
  const topLevelKeys = Object.keys(parsed);
  if (topLevelKeys.some((key) => !['version', 'endpoints', 'rules'].includes(key))) {
    return { ok: false, message: 'Configuration contains an unsupported top-level property.' };
  }
  if (parsed.version !== 1) {
    return { ok: false, message: 'Configuration version must be 1.' };
  }

  const endpointAllow: string[] = [];
  const endpointDeny: string[] = [];
  if (parsed.endpoints !== undefined) {
    if (!isRecord(parsed.endpoints)) {
      return { ok: false, message: 'Configuration endpoints must be a JSON object.' };
    }
    const endpointKeys = Object.keys(parsed.endpoints);
    if (endpointKeys.some((key) => !['allow', 'deny'].includes(key))) {
      return { ok: false, message: 'Configuration endpoints contain an unsupported property.' };
    }
    if (parsed.endpoints.allow !== undefined && !stringArray(parsed.endpoints.allow)) {
      return { ok: false, message: 'Configuration endpoints.allow must be an array of strings.' };
    }
    if (parsed.endpoints.deny !== undefined && !stringArray(parsed.endpoints.deny)) {
      return { ok: false, message: 'Configuration endpoints.deny must be an array of strings.' };
    }
    endpointAllow.push(...(parsed.endpoints.allow ?? []));
    endpointDeny.push(...(parsed.endpoints.deny ?? []));
  }

  const rules: Partial<Record<ConfigurableRuleId, RuleSeverity>> = {};
  if (parsed.rules !== undefined) {
    if (!isRecord(parsed.rules)) {
      return { ok: false, message: 'Configuration rules must be a JSON object.' };
    }
    for (const [providedId, value] of Object.entries(parsed.rules)) {
      const id = canonicalRuleId(providedId);
      const severity = parseSeverity(value);
      if (!id) return { ok: false, message: `Unsupported rule ID: ${providedId}.` };
      if (!severity) {
        return { ok: false, message: `Rule ${providedId} must be off, warn, or blocked.` };
      }
      rules[id] = severity;
    }
  }

  return { ok: true, policy: { endpointAllow, endpointDeny, rules } };
}

function parseCliRules(
  values: readonly string[]
):
  | { ok: true; rules: Partial<Record<ConfigurableRuleId, RuleSeverity>> }
  | { ok: false; message: string } {
  const rules: Partial<Record<ConfigurableRuleId, RuleSeverity>> = {};
  for (const value of values) {
    const separator = value.lastIndexOf('=');
    const providedId = separator > 0 ? value.slice(0, separator) : '';
    const severityText = separator > 0 ? value.slice(separator + 1) : '';
    const id = canonicalRuleId(providedId);
    const severity = parseSeverity(severityText);
    if (!id || !severity) {
      return { ok: false, message: 'CLI rule overrides must use a supported id=severity value.' };
    }
    rules[id] = severity;
  }
  return { ok: true, rules };
}

export async function resolveReleasePolicy(
  options: ResolvePolicyOptions
): Promise<PolicyResolution> {
  const implicitPath = join(options.cwd, '.releaseguard.json');
  const selectedPath = options.configPath ? resolve(options.cwd, options.configPath) : implicitPath;
  const explicit = options.configPath !== undefined;
  const location = safeLocation(options.cwd, selectedPath);

  let policy: ReleasePolicy = { endpointAllow: [], endpointDeny: [], rules: {} };
  if (explicit || existsSync(selectedPath)) {
    let content: string;
    try {
      content = await readFile(selectedPath, 'utf8');
    } catch {
      return {
        ok: false,
        result: configError('config.read', 'Configuration file could not be read.', location),
      };
    }
    const parsed = parseReleaseGuardConfig(content);
    if (!parsed.ok) {
      return {
        ok: false,
        result: configError('config.invalid', parsed.message, location),
      };
    }
    policy = parsed.policy;
  }

  const cliRules = parseCliRules(options.cli?.rules ?? []);
  if (!cliRules.ok) {
    return {
      ok: false,
      result: configError('cli.rule', cliRules.message, 'command-line'),
    };
  }

  return {
    ok: true,
    policy: {
      endpointAllow: options.cli?.allow ?? policy.endpointAllow,
      endpointDeny: options.cli?.deny ?? policy.endpointDeny,
      rules: { ...policy.rules, ...cliRules.rules },
    },
    ...(explicit || existsSync(selectedPath) ? { configLocation: location } : {}),
  };
}

function statusForSeverity(severity: RuleSeverity): Extract<Status, 'PASS' | 'WARN' | 'BLOCKED'> {
  if (severity === 'off') return 'PASS';
  return severity === 'warn' ? 'WARN' : 'BLOCKED';
}

export function applyReleasePolicy(result: AuditResult, policy: ReleasePolicy): AuditResult {
  const checks = result.checks.map<Check>((check) => {
    if (check.status === 'PASS' || check.status === 'TOOL_ERROR') return check;
    const id = canonicalRuleId(check.id);
    const severity = id ? policy.rules[id] : undefined;
    if (!severity) return check;
    const status = statusForSeverity(severity);
    return {
      ...check,
      status,
      ...(severity === 'off'
        ? { message: `${check.message} Rule disabled by project policy.` }
        : {}),
    };
  });
  return createResult(checks);
}
