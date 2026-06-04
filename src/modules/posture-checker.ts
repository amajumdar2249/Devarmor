// ============================================================
// DevArmor — Posture Checker Module
// Audits developer workstation security posture.
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';
import {
  ScannerModule,
  ModuleResult,
  ScanFinding,
  ScanOptions,
  Severity,
} from '../types';

/** Common personal email domains to flag. */
const PERSONAL_EMAIL_DOMAINS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
  'aol.com', 'icloud.com', 'mail.com', 'protonmail.com',
  'live.com', 'msn.com', 'ymail.com', 'zoho.com',
];

/** Cloud CLI credential file locations relative to home directory. */
const CLOUD_CREDENTIAL_FILES = [
  { name: 'AWS Credentials', file: path.join('.aws', 'credentials') },
  { name: 'AWS Config', file: path.join('.aws', 'config') },
  { name: 'Azure CLI Config', file: path.join('.azure', 'config') },
  { name: 'Azure CLI Token', file: path.join('.azure', 'accessTokens.json') },
  { name: 'Azure CLI Profile', file: path.join('.azure', 'azureProfile.json') },
  { name: 'GCP Application Default Credentials', file: path.join('.config', 'gcloud', 'application_default_credentials.json') },
  { name: 'GCP Properties', file: path.join('.config', 'gcloud', 'properties') },
];

/** SSH key files to check. */
const SSH_KEY_FILES = [
  'id_rsa', 'id_ecdsa', 'id_ed25519', 'id_dsa',
];

/**
 * Safely executes a command and returns stdout, or null on failure.
 */
function safeExec(command: string): string | null {
  try {
    return execSync(command, { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return null;
  }
}

/**
 * PostureChecker — Audits developer workstation security posture
 * including git config, .gitignore, .npmrc, SSH keys, and cloud credentials.
 */
export class PostureChecker implements ScannerModule {
  name = 'PostureChecker' as const;
  label = '📋 Posture Checker';

  async scan(options: ScanOptions): Promise<ModuleResult> {
    const startTime = Date.now();
    const findings: ScanFinding[] = [];
    const homeDir = os.homedir();
    let itemsChecked = 0;

    // ── Check 1: Git config email exposure ──
    itemsChecked++;
    const gitEmail = safeExec('git config --global user.email');
    if (gitEmail) {
      const domain = gitEmail.split('@')[1]?.toLowerCase();
      if (domain && PERSONAL_EMAIL_DOMAINS.includes(domain)) {
        findings.push({
          module: this.name,
          severity: Severity.MEDIUM,
          title: 'Personal Email in Global Git Config',
          description: `Global git config uses personal email "${gitEmail}". This email appears in every commit and is publicly visible on pushed repositories.`,
          remediation: 'Use a work email or GitHub noreply address: git config --global user.email "user@users.noreply.github.com"',
        });
      } else if (gitEmail) {
        findings.push({
          module: this.name,
          severity: Severity.INFO,
          title: 'Git Email Configured',
          description: `Global git email is set to "${gitEmail}".`,
          remediation: 'No action needed — verify this email is appropriate for public commits',
        });
      }
    } else {
      findings.push({
        module: this.name,
        severity: Severity.LOW,
        title: 'No Global Git Email Configured',
        description: 'No global git user.email is set. Commits may use system defaults.',
        remediation: 'Set a git email: git config --global user.email "your-email@example.com"',
      });
    }

    // ── Check 2: .gitignore exists and covers .env ──
    itemsChecked++;
    const gitignorePath = path.join(options.path, '.gitignore');
    if (fs.existsSync(gitignorePath)) {
      let gitignoreContent: string;
      try {
        gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');
      } catch {
        gitignoreContent = '';
      }

      const hasEnvEntry = /^\.env$/m.test(gitignoreContent) ||
                          /^\.env\.\*$/m.test(gitignoreContent) ||
                          /^\.env\.local$/m.test(gitignoreContent) ||
                          /^\.env\*$/m.test(gitignoreContent);

      if (!hasEnvEntry) {
        findings.push({
          module: this.name,
          severity: Severity.HIGH,
          title: '.gitignore Missing .env Entry',
          description: '.gitignore exists but does not contain entries for .env files. Environment files with secrets may be accidentally committed.',
          filePath: gitignorePath,
          remediation: 'Add ".env" and ".env.*" to your .gitignore file',
        });
      } else {
        findings.push({
          module: this.name,
          severity: Severity.INFO,
          title: '.gitignore Covers .env Files',
          description: '.gitignore properly includes entries for .env files.',
          filePath: gitignorePath,
          remediation: 'No action needed',
        });
      }
    } else {
      findings.push({
        module: this.name,
        severity: Severity.HIGH,
        title: 'No .gitignore File Found',
        description: 'No .gitignore file exists in the project root. Sensitive files may be accidentally committed.',
        remediation: 'Create a .gitignore file with entries for .env, node_modules, and other sensitive paths',
      });
    }

    // ── Check 3: .npmrc for auth tokens ──
    itemsChecked++;
    const npmrcPaths = [
      path.join(options.path, '.npmrc'),
      path.join(homeDir, '.npmrc'),
    ];

    for (const npmrcPath of npmrcPaths) {
      if (!fs.existsSync(npmrcPath)) continue;

      let npmrcContent: string;
      try {
        npmrcContent = fs.readFileSync(npmrcPath, 'utf-8');
      } catch {
        continue;
      }

      // Check for _authToken
      const authTokenMatch = /_authToken\s*=\s*(.+)/i.exec(npmrcContent);
      if (authTokenMatch) {
        const token = authTokenMatch[1].trim();
        const isEnvVar = token.startsWith('${') && token.endsWith('}');

        if (!isEnvVar) {
          const upToMatch = npmrcContent.substring(0, authTokenMatch.index);
          const lineNumber = upToMatch.split('\n').length;

          findings.push({
            module: this.name,
            severity: Severity.HIGH,
            title: 'Hardcoded npm Auth Token',
            description: `Found a hardcoded _authToken in .npmrc. This token should use environment variable substitution.`,
            filePath: npmrcPath,
            line: lineNumber,
            evidence: '_authToken=****',
            remediation: 'Replace the hardcoded token with an env var: _authToken=${NPM_TOKEN}',
          });
        } else {
          findings.push({
            module: this.name,
            severity: Severity.INFO,
            title: 'npm Auth Token Uses Environment Variable',
            description: '.npmrc uses environment variable substitution for auth token.',
            filePath: npmrcPath,
            remediation: 'No action needed',
          });
        }
      }
    }

    // ── Check 4: SSH key file existence ──
    itemsChecked++;
    const sshDir = path.join(homeDir, '.ssh');
    if (fs.existsSync(sshDir)) {
      for (const keyFile of SSH_KEY_FILES) {
        const keyPath = path.join(sshDir, keyFile);
        if (!fs.existsSync(keyPath)) continue;

        // On non-Windows, we'd check permissions with stat
        // On Windows, report existence and recommend review
        const isWindows = os.platform() === 'win32';

        if (isWindows) {
          findings.push({
            module: this.name,
            severity: Severity.INFO,
            title: `SSH Private Key Found — ${keyFile}`,
            description: `SSH private key file detected at ${keyPath}. Verify that file ACLs are properly restricted.`,
            filePath: keyPath,
            remediation: 'Ensure only your user account has access: icacls <key> /inheritance:r /grant:r "%USERNAME%:R"',
          });
        } else {
          // Check Unix permissions
          try {
            const stat = fs.statSync(keyPath);
            const mode = (stat.mode & 0o777).toString(8);
            const isPermissive = (stat.mode & 0o077) !== 0; // group/other have any access

            if (isPermissive) {
              findings.push({
                module: this.name,
                severity: Severity.HIGH,
                title: `SSH Key Overly Permissive — ${keyFile}`,
                description: `SSH private key has permissions ${mode} — group/other users can read it.`,
                filePath: keyPath,
                evidence: `mode: ${mode}`,
                remediation: `Fix permissions: chmod 600 ${keyPath}`,
              });
            } else {
              findings.push({
                module: this.name,
                severity: Severity.INFO,
                title: `SSH Key Permissions OK — ${keyFile}`,
                description: `SSH private key has proper permissions (${mode}).`,
                filePath: keyPath,
                remediation: 'No action needed',
              });
            }
          } catch {
            // Skip inaccessible key files
          }
        }
      }
    }

    // ── Check 5: Cloud CLI credential files ──
    itemsChecked++;
    for (const cred of CLOUD_CREDENTIAL_FILES) {
      const credPath = path.join(homeDir, cred.file);
      if (!fs.existsSync(credPath)) continue;

      findings.push({
        module: this.name,
        severity: Severity.MEDIUM,
        title: `Cloud CLI Credentials Found — ${cred.name}`,
        description: `Cloud credential file detected at ${credPath}. Ensure these credentials follow least-privilege principles.`,
        filePath: credPath,
        remediation: 'Review cloud CLI credentials for excessive permissions. Use short-lived tokens or SSO where possible.',
      });

      // Additionally check AWS credentials for hardcoded keys
      if (cred.file.includes('.aws') && cred.file.endsWith('credentials')) {
        let content: string;
        try {
          content = fs.readFileSync(credPath, 'utf-8');
        } catch {
          continue;
        }

        if (/aws_access_key_id\s*=\s*AKIA[0-9A-Z]{16}/i.test(content)) {
          findings.push({
            module: this.name,
            severity: Severity.HIGH,
            title: 'Long-Lived AWS Access Key Detected',
            description: 'AWS credentials file contains a long-lived access key. Consider using IAM Identity Center (SSO) instead.',
            filePath: credPath,
            remediation: 'Migrate to AWS SSO/IAM Identity Center for short-lived credentials',
          });
        }
      }
    }

    return {
      module: this.name,
      label: this.label,
      success: true,
      durationMs: Date.now() - startTime,
      itemsScanned: itemsChecked,
      findings,
    };
  }
}
