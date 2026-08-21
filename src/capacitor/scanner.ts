import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createResult } from '../rules/result.js';
import type { AuditResult, Check } from '../types.js';

const capacitorConfigNames = [
  'capacitor.config.ts',
  'capacitor.config.js',
  'capacitor.config.mjs',
  'capacitor.config.cjs',
  'capacitor.config.json',
];

function extractCapacitorAppId(content: string, isJson: boolean): string | undefined {
  if (isJson) {
    try {
      const parsed = JSON.parse(content) as { appId?: unknown };
      return typeof parsed.appId === 'string' ? parsed.appId : undefined;
    } catch {
      return undefined;
    }
  }
  return content.match(/\bappId\s*:\s*['"]([^'"]+)['"]/)?.[1];
}

function extractGradleApplicationId(content: string): string | undefined {
  return content.match(/\bapplicationId\s*(?:=\s*)?['"]([^'"]+)['"]/)?.[1];
}

export async function scanCapacitorProject(root: string): Promise<AuditResult> {
  const checks: Check[] = [];
  const configName = capacitorConfigNames.find((name) => existsSync(join(root, name)));
  const androidDirectory = join(root, 'android');
  const androidExists = existsSync(androidDirectory);

  if (configName) {
    checks.push({
      id: 'capacitor.config',
      status: 'PASS',
      message: 'Capacitor configuration detected.',
      location: configName,
    });
  } else {
    checks.push({
      id: 'capacitor.config',
      status: 'WARN',
      message: 'No capacitor.config.* file was detected.',
    });
  }

  checks.push({
    id: 'capacitor.android-directory',
    status: androidExists ? 'PASS' : 'WARN',
    message: androidExists
      ? 'Android project directory detected.'
      : 'Android directory was not detected.',
    ...(androidExists ? { location: 'android' } : {}),
  });

  let capacitorAppId: string | undefined;
  if (configName) {
    try {
      const configContent = await readFile(join(root, configName), 'utf8');
      capacitorAppId = extractCapacitorAppId(configContent, configName.endsWith('.json'));
    } catch {
      checks.push({
        id: 'capacitor.config-read',
        status: 'TOOL_ERROR',
        message: 'Capacitor configuration could not be read.',
        location: configName,
      });
    }
  }

  const gradleCandidates = [
    join(androidDirectory, 'app', 'build.gradle'),
    join(androidDirectory, 'app', 'build.gradle.kts'),
  ];
  const gradlePath = gradleCandidates.find((candidate) => existsSync(candidate));
  let gradleApplicationId: string | undefined;

  if (!gradlePath) {
    checks.push({
      id: 'android.gradle',
      status: 'WARN',
      message: 'Android app Gradle build file was not detected.',
    });
  } else {
    const location = gradlePath.endsWith('.kts')
      ? 'android/app/build.gradle.kts'
      : 'android/app/build.gradle';
    let gradleContent = '';
    try {
      gradleContent = await readFile(gradlePath, 'utf8');
    } catch {
      checks.push({
        id: 'android.gradle-read',
        status: 'TOOL_ERROR',
        message: 'Android app Gradle build file could not be read.',
        location,
      });
    }

    if (gradleContent) {
      gradleApplicationId = extractGradleApplicationId(gradleContent);
      const hasReleaseBuildType = /\brelease\s*\{/m.test(gradleContent);
      const hasSigningConfigs = /\bsigningConfigs\s*\{/m.test(gradleContent);
      const releaseBlock = gradleContent.match(/\brelease\s*\{[\s\S]{0,3000}?\n\s*\}/m)?.[0] ?? '';
      const releaseSigningBinding = /\bsigningConfig\b/.test(releaseBlock);

      checks.push({
        id: 'android.release-build-type',
        status: hasReleaseBuildType ? 'PASS' : 'WARN',
        message: hasReleaseBuildType
          ? 'Gradle release build type detected.'
          : 'Gradle release build type was not detected.',
        location,
      });
      checks.push({
        id: 'android.signing-configs',
        status: hasSigningConfigs ? 'PASS' : 'WARN',
        message: hasSigningConfigs
          ? 'Gradle signingConfigs block detected.'
          : 'Gradle signingConfigs block was not detected.',
        location,
      });
      checks.push({
        id: 'android.release-signing-binding',
        status: releaseSigningBinding ? 'PASS' : 'WARN',
        message: releaseSigningBinding
          ? 'Release build type references a signing configuration.'
          : 'Release signingConfig binding was not detected.',
        location,
      });

      if (/\b(?:storePassword|keyPassword)\b/.test(gradleContent)) {
        checks.push({
          id: 'android.sensitive-signing-reference',
          status: 'WARN',
          message: 'Sensitive signing configuration reference detected',
          location,
        });
      }
    }
  }

  const applicationId = gradleApplicationId ?? capacitorAppId;
  checks.push({
    id: 'android.application-id',
    status: applicationId ? 'PASS' : 'WARN',
    message: applicationId
      ? 'Android application identifier detected.'
      : 'Application identifier not detected.',
    ...(applicationId ? { details: { applicationId } } : {}),
  });

  if (capacitorAppId && gradleApplicationId && capacitorAppId !== gradleApplicationId) {
    checks.push({
      id: 'capacitor.application-id-consistency',
      status: 'WARN',
      message: 'Capacitor appId and Android applicationId differ.',
      details: { capacitorAppId, androidApplicationId: gradleApplicationId },
    });
  }

  return createResult(checks);
}
