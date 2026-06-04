// ============================================================
// DevArmor — Agent Residue Scanner Module
// Scans AI agent history directories for leaked credentials.
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  ScannerModule,
  ModuleResult,
  ScanFinding,
  ScanOptions,
  Severity,
} from '../types';

/** Known AI agent directories relative to user home. */
const AGENT_DIRS = [
  { name: 'Claude Code', dir: '.claude' },
  { name: 'Cursor', dir: '.cursor' },
  { name: 'Codex (OpenAI)', dir: '.codex' },
  { name: 'Gemini (Google)', dir: '.gemini' },
  { name: 'GitHub Copilot', dir: '.github-copilot' },
  { name: 'Windsurf', dir: '.windsurf' },
  { name: 'Aider', dir: '.aider' },
  { name: 'Continue', dir: '.continue' },
];

/** Sensitive file patterns within agent directories. */
const SENSITIVE_FILE_PATTERNS = [
  'config.json',
  'auth.json',
  'credentials.json',
  'mcp.json',
  'settings.json',
  'claude_desktop_config.json',
];

/** Patterns that indicate credential leakage in conversation logs. */
const RESIDUE_PATTERNS = [
  {
    id: 'api-key-in-log',
    label: 'API Key in Conversation Log',
    regex: /(?:sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{35}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36,})/g,
    severity: Severity.CRITICAL,
    remediation: 'Clear agent history and rotate any exposed keys immediately',
  },
  {
    id: 'env-var-in-log',
    label: 'Environment Variable Value in Log',
    regex: /(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|DATABASE_URL|PRIVATE_KEY)\s*[=:]\s*["']?[A-Za-z0-9_/+=.-]{10,}/gi,
    severity: Severity.HIGH,
    remediation: 'Rotate the exposed credential and clear agent conversation history',
  },
  {
    id: 'password-in-log',
    label: 'Password Leaked in Conversation',
    regex: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{6,}["']/gi,
    severity: Severity.HIGH,
    remediation: 'Change the password immediately and clear agent history',
  },
  {
    id: 'connection-string-in-log',
    label: 'Database Connection String in Log',
    regex: /(?:postgres|mongodb|mysql|redis):\/\/[^:]+:[^@]+@[^\s"']+/gi,
    severity: Severity.HIGH,
    remediation: 'Rotate database credentials and clear agent history',
  },
  {
    id: 'private-key-in-log',
    label: 'Private Key Material in Log',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: Severity.CRITICAL,
    remediation: 'Regenerate the keypair immediately — the private key is compromised',
  },
  {
    id: 'jwt-in-log',
    label: 'JWT Token in Conversation Log',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    severity: Severity.MEDIUM,
    remediation: 'Verify if the JWT is still valid and revoke if necessary',
  },
];

/** Maximum file size to scan (5MB — logs can be large). */
const MAX_LOG_SIZE = 5 * 1024 * 1024;

/**
 * Redacts sensitive content for safe display.
 */
function redact(value: string): string {
  if (value.length <= 12) return '****';
  return value.substring(0, 4) + '****' + value.substring(value.length - 4);
}

/**
 * Recursively find files in a directory (shallow depth for logs).
 */
function findFiles(dir: string, maxDepth: number = 4, currentDepth: number = 0): string[] {
  const results: string[] = [];
  if (currentDepth > maxDepth || !fs.existsSync(dir)) return results;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      // Skip very deep or large directories
      if (entry.name !== 'node_modules' && entry.name !== '.git') {
        results.push(...findFiles(fullPath, maxDepth, currentDepth + 1));
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (['.json', '.jsonl', '.log', '.txt', '.yaml', '.yml', '.toml'].includes(ext) ||
          SENSITIVE_FILE_PATTERNS.includes(entry.name.toLowerCase())) {
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size <= MAX_LOG_SIZE && stat.size > 0) {
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
 * AgentResidueScanner — Detects credentials leaked in AI agent
 * conversation history, config files, and cache directories.
 */
export class AgentResidueScanner implements ScannerModule {
  name = 'AgentResidueScanner' as const;
  label = '🤖 Agent Residue Scanner';

  async scan(options: ScanOptions): Promise<ModuleResult> {
    const startTime = Date.now();
    const findings: ScanFinding[] = [];
    const homeDir = os.homedir();
    let totalFilesScanned = 0;

    // Phase 1: Check which agent directories exist
    for (const agent of AGENT_DIRS) {
      const agentPath = path.join(homeDir, agent.dir);

      if (!fs.existsSync(agentPath)) {
        continue; // Agent not installed, skip
      }

      // Report agent directory discovery
      findings.push({
        module: this.name,
        severity: Severity.INFO,
        title: `${agent.name} Directory Found`,
        description: `AI agent directory detected at ${agentPath}. This directory may contain conversation history with sensitive data.`,
        filePath: agentPath,
        remediation: 'Periodically review and clean agent history directories',
      });

      // Phase 2: Scan files within agent directory for leaked secrets
      const files = findFiles(agentPath);
      totalFilesScanned += files.length;

      for (const filePath of files) {
        let content: string;
        try {
          content = fs.readFileSync(filePath, 'utf-8');
        } catch {
          continue;
        }

        // Check for credential patterns in conversation logs
        for (const pattern of RESIDUE_PATTERNS) {
          pattern.regex.lastIndex = 0;

          let match: RegExpExecArray | null;
          while ((match = pattern.regex.exec(content)) !== null) {
            findings.push({
              module: this.name,
              severity: pattern.severity,
              title: `${pattern.label} — ${agent.name}`,
              description: `Found credential residue in ${agent.name} history file.`,
              filePath,
              evidence: redact(match[0]),
              remediation: pattern.remediation,
            });
          }
        }

        // Check for sensitive config files with hardcoded secrets
        const basename = path.basename(filePath).toLowerCase();
        if (SENSITIVE_FILE_PATTERNS.includes(basename)) {
          // Check for common dangerous patterns in config files
          if (content.includes('"apiKey"') || content.includes('"api_key"') ||
              content.includes('"secret"') || content.includes('"token"')) {

            // Only flag if it looks like it has an actual value (not empty/placeholder)
            const hasRealValue = /(?:apiKey|api_key|secret|token)\s*["']?\s*:\s*["'][A-Za-z0-9_/+=.-]{10,}["']/i.test(content);
            if (hasRealValue) {
              findings.push({
                module: this.name,
                severity: Severity.HIGH,
                title: `Hardcoded Credentials in ${agent.name} Config`,
                description: `Configuration file contains what appears to be hardcoded API keys or tokens.`,
                filePath,
                remediation: 'Move secrets to environment variables or a secrets manager',
              });
            }
          }
        }
      }
    }

    // Phase 3: Also scan the project directory for agent-generated residue
    const projectAgentDirs = [
      path.join(options.path, '.claude'),
      path.join(options.path, '.cursor'),
      path.join(options.path, '.codex'),
    ];

    for (const agentDir of projectAgentDirs) {
      if (!fs.existsSync(agentDir)) continue;

      const files = findFiles(agentDir, 2);
      totalFilesScanned += files.length;

      for (const filePath of files) {
        let content: string;
        try {
          content = fs.readFileSync(filePath, 'utf-8');
        } catch {
          continue;
        }

        for (const pattern of RESIDUE_PATTERNS) {
          pattern.regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.regex.exec(content)) !== null) {
            findings.push({
              module: this.name,
              severity: pattern.severity,
              title: `${pattern.label} — Project Agent Files`,
              description: `Found credential residue in project-level agent history.`,
              filePath,
              evidence: redact(match[0]),
              remediation: pattern.remediation,
            });
          }
        }
      }
    }

    return {
      module: this.name,
      label: this.label,
      success: true,
      durationMs: Date.now() - startTime,
      itemsScanned: totalFilesScanned,
      findings,
    };
  }
}
