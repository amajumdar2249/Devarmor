// ============================================================
// DevArmor — Secret Scanner Module
// Detects leaked API keys, tokens, passwords in config files.
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import {
  ScannerModule,
  ModuleResult,
  ScanFinding,
  ScanOptions,
  Severity,
} from '../types';

/** A secret detection pattern with metadata. */
interface SecretPattern {
  id: string;
  label: string;
  regex: RegExp;
  severity: Severity;
  remediation: string;
}

/**
 * Curated list of secret patterns to detect.
 * Covers major cloud providers, AI services, payment systems, and common credential formats.
 */
const SECRET_PATTERNS: SecretPattern[] = [
  // ── AI / LLM Service Keys ──
  {
    id: 'openai-api-key',
    label: 'OpenAI API Key',
    regex: /sk-[A-Za-z0-9_-]{20,}/g,
    severity: Severity.CRITICAL,
    remediation: 'Remove the key from this file and rotate it at https://platform.openai.com/api-keys',
  },
  {
    id: 'anthropic-api-key',
    label: 'Anthropic API Key',
    regex: /sk-ant-[A-Za-z0-9_-]{20,}/g,
    severity: Severity.CRITICAL,
    remediation: 'Remove the key and rotate it at https://console.anthropic.com/settings/keys',
  },
  {
    id: 'google-ai-api-key',
    label: 'Google AI API Key',
    regex: /AIza[A-Za-z0-9_-]{35}/g,
    severity: Severity.CRITICAL,
    remediation: 'Remove the key and rotate it in Google Cloud Console',
  },
  // ── Cloud Provider Keys ──
  {
    id: 'aws-access-key',
    label: 'AWS Access Key ID',
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: Severity.CRITICAL,
    remediation: 'Rotate this key immediately in AWS IAM Console',
  },
  {
    id: 'aws-secret-key',
    label: 'AWS Secret Access Key',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{40}/g,
    severity: Severity.CRITICAL,
    remediation: 'Rotate this key immediately in AWS IAM Console',
  },
  {
    id: 'azure-connection-string',
    label: 'Azure Connection String',
    regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}/g,
    severity: Severity.CRITICAL,
    remediation: 'Rotate the storage account key in Azure Portal',
  },
  // ── Payment / Financial ──
  {
    id: 'stripe-secret-key',
    label: 'Stripe Secret Key',
    regex: /sk_live_[A-Za-z0-9]{24,}/g,
    severity: Severity.CRITICAL,
    remediation: 'Rotate this key at https://dashboard.stripe.com/apikeys',
  },
  {
    id: 'stripe-publishable-key',
    label: 'Stripe Publishable Key',
    regex: /pk_live_[A-Za-z0-9]{24,}/g,
    severity: Severity.LOW,
    remediation: 'Publishable keys are client-safe, but verify this is intentional',
  },
  // ── Communication / Messaging ──
  {
    id: 'slack-token',
    label: 'Slack Token',
    regex: /xox[bpors]-[0-9]{10,}-[A-Za-z0-9-]+/g,
    severity: Severity.HIGH,
    remediation: 'Revoke and regenerate the Slack token',
  },
  {
    id: 'discord-token',
    label: 'Discord Bot Token',
    regex: /[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/g,
    severity: Severity.HIGH,
    remediation: 'Regenerate the Discord bot token',
  },
  {
    id: 'twilio-api-key',
    label: 'Twilio API Key',
    regex: /SK[0-9a-fA-F]{32}/g,
    severity: Severity.HIGH,
    remediation: 'Rotate the Twilio API key in your Twilio Console',
  },
  // ── Source Control / CI ──
  {
    id: 'github-pat',
    label: 'GitHub Personal Access Token',
    regex: /ghp_[A-Za-z0-9]{36,}/g,
    severity: Severity.CRITICAL,
    remediation: 'Revoke this token at https://github.com/settings/tokens',
  },
  {
    id: 'github-fine-grained-pat',
    label: 'GitHub Fine-Grained PAT',
    regex: /github_pat_[A-Za-z0-9_]{22,}/g,
    severity: Severity.CRITICAL,
    remediation: 'Revoke this token at https://github.com/settings/tokens',
  },
  {
    id: 'gitlab-pat',
    label: 'GitLab Personal Access Token',
    regex: /glpat-[A-Za-z0-9_-]{20,}/g,
    severity: Severity.CRITICAL,
    remediation: 'Revoke this token in GitLab → Settings → Access Tokens',
  },
  // ── Database ──
  {
    id: 'postgres-connection',
    label: 'PostgreSQL Connection String',
    regex: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/]+/g,
    severity: Severity.HIGH,
    remediation: 'Move database credentials to environment variables or a secrets manager',
  },
  {
    id: 'mongodb-connection',
    label: 'MongoDB Connection String',
    regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/]+/g,
    severity: Severity.HIGH,
    remediation: 'Move database credentials to environment variables or a secrets manager',
  },
  // ── Generic Patterns ──
  {
    id: 'generic-password',
    label: 'Hardcoded Password',
    regex: /(?:password|passwd|pwd|secret)\s*[=:]\s*["'][^"']{8,}["']/gi,
    severity: Severity.MEDIUM,
    remediation: 'Move passwords to environment variables or a secrets manager',
  },
  {
    id: 'private-key',
    label: 'Private Key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: Severity.CRITICAL,
    remediation: 'Remove private keys from this file and store them securely',
  },
  {
    id: 'bearer-token',
    label: 'Bearer Token',
    regex: /(?:bearer|authorization)\s*[=:]\s*["']?Bearer\s+[A-Za-z0-9._~+/=-]{20,}/gi,
    severity: Severity.HIGH,
    remediation: 'Remove hardcoded bearer tokens and use dynamic token generation',
  },
  {
    id: 'jwt-token',
    label: 'JWT Token',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    severity: Severity.HIGH,
    remediation: 'Remove hardcoded JWT tokens — they may contain sensitive claims',
  },
];

/** File extensions to scan for secrets. */
const SCAN_EXTENSIONS = new Set([
  '.env', '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf',
  '.properties', '.xml', '.ts', '.js', '.py', '.rb', '.go', '.rs',
  '.java', '.sh', '.bash', '.zsh', '.fish', '.ps1',
  '.tf', '.tfvars', '.hcl', // Terraform
  '.dockerfile', // Docker
]);

/** Files to scan regardless of extension. */
const SCAN_FILENAMES = new Set([
  '.env', '.env.local', '.env.production', '.env.development', '.env.staging',
  '.npmrc', '.pypirc', 'pip.conf', '.netrc', '.git-credentials',
  'credentials', 'config', '.bashrc', '.zshrc', '.profile',
  'docker-compose.yml', 'docker-compose.yaml',
  'Dockerfile',
]);

/** Directories to skip during scanning. */
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '__pycache__',
  '.next', '.nuxt', 'vendor', 'target', 'bin', 'obj', 'registry', 'packages',
]);

/** Maximum file size to scan (1MB). */
const MAX_FILE_SIZE = 1024 * 1024;

/**
 * Recursively collects scannable files from a directory.
 */
function collectFiles(dir: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        results.push(...collectFiles(fullPath));
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      const basename = entry.name.toLowerCase();

      // Check if file is scannable by extension or name
      if (SCAN_EXTENSIONS.has(ext) || SCAN_FILENAMES.has(basename)) {
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size <= MAX_FILE_SIZE && stat.size > 0) {
            results.push(fullPath);
          }
        } catch {
          // Skip inaccessible files
        }
      }
    }
  }

  return results;
}

/**
 * Redacts sensitive content for safe display in findings.
 * Shows first 4 and last 4 characters, masks the rest.
 */
function redact(value: string): string {
  if (value.length <= 12) return '****';
  return value.substring(0, 4) + '****' + value.substring(value.length - 4);
}

/**
 * SecretScanner — Detects leaked API keys, tokens, and passwords
 * across configuration files, dotfiles, and source code.
 */
export class SecretScanner implements ScannerModule {
  name = 'SecretScanner' as const;
  label = '🔑 Secret Scanner';

  async scan(options: ScanOptions): Promise<ModuleResult> {
    const startTime = Date.now();
    const findings: ScanFinding[] = [];

    const files = collectFiles(options.path);

    for (const filePath of files) {
      let content: string;
      try {
        content = fs.readFileSync(filePath, 'utf-8');
      } catch {
        continue; // Skip unreadable files
      }

      const lines = content.split('\n');

      for (const pattern of SECRET_PATTERNS) {
        // Reset regex state for each file
        pattern.regex.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = pattern.regex.exec(content)) !== null) {
          // Find line number
          const upToMatch = content.substring(0, match.index);
          const lineNumber = upToMatch.split('\n').length;

          findings.push({
            module: this.name,
            severity: pattern.severity,
            title: `${pattern.label} Detected`,
            description: `Found a potential ${pattern.label} in this file.`,
            filePath,
            line: lineNumber,
            evidence: redact(match[0]),
            remediation: pattern.remediation,
          });
        }
      }
    }

    return {
      module: this.name,
      label: this.label,
      success: true,
      durationMs: Date.now() - startTime,
      itemsScanned: files.length,
      findings,
    };
  }
}
