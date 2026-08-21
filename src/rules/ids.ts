export const RULE_IDS = {
  androidDebuggable: 'android.debuggable',
  androidDebugSigner: 'android.debug-signer',
  androidCleartextTraffic: 'android.cleartext-traffic',
  androidNetworkSecurityCleartext: 'android.network-security.cleartext',
  androidSigningMissingRelease: 'android.signing.missing-release',
  endpointLocalhost: 'endpoint.localhost',
  endpointCleartextHttp: 'endpoint.cleartext-http',
  endpointTunnel: 'endpoint.tunnel',
  endpointNonProduction: 'endpoint.non-production',
  endpointPolicyDeny: 'endpoint.policy-deny',
  certificateMismatch: 'certificate.mismatch',
} as const;

export type ConfigurableRuleId = (typeof RULE_IDS)[keyof typeof RULE_IDS];

const configurableIds = new Set<string>(Object.values(RULE_IDS));
const aliases = new Map<string, ConfigurableRuleId>([
  ['android.debugSigner', RULE_IDS.androidDebugSigner],
  ['endpoint.cleartextHttp', RULE_IDS.endpointCleartextHttp],
]);

export function canonicalRuleId(value: string): ConfigurableRuleId | undefined {
  const id = value.trim();
  const alias = aliases.get(id);
  if (alias) return alias;
  return configurableIds.has(id) ? (id as ConfigurableRuleId) : undefined;
}
