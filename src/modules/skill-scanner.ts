// ============================================================
// DevArmor — Skill Scanner Module
// Detects malicious patterns in AI agent skill files.
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

/** Skill directories to scan, relative to project root. */
const SKILL_DIRS = [
  '.agents/skills',
  '.cursor/skills',
];

/** Prompt injection patterns. */
const PROMPT_INJECTION_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /ignore\s+previous\s+instructions/gi, label: 'Ignore previous instructions' },
  { regex: /ignore\s+all\s+prior/gi, label: 'Ignore all prior instructions' },
  { regex: /you\s+are\s+now/gi, label: 'Identity override (you are now)' },
  { regex: /override\s+your/gi, label: 'Override directive' },
  { regex: /disregard\s+your/gi, label: 'Disregard directive' },
  { regex: /forget\s+(everything|all|your)/gi, label: 'Memory wipe directive' },
  { regex: /new\s+instructions?\s*:/gi, label: 'New instructions injection' },
  { regex: /system\s*:\s*you\s+are/gi, label: 'System prompt override' },
];

/** Data exfiltration patterns. */
const DATA_EXFIL_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /fetch\s*\(\s*['"][^'"]*['"].*(?:file|content|secret|key|token|password)/gi, label: 'Fetch with sensitive data' },
  { regex: /https?:\/\/[^\s'"]+.*(?:readFile|readFileSync|file_contents)/gi, label: 'HTTP request with file contents' },
  { regex: /send\s+all/gi, label: 'Send all directive' },
  { regex: /\btransmit\b/gi, label: 'Transmit directive' },
  { regex: /\bexfiltrate\b/gi, label: 'Exfiltrate directive' },
  { regex: /upload.*(?:credentials|secrets|keys|tokens|\.env)/gi, label: 'Upload credentials' },
  { regex: /(?:curl|wget|fetch|http\.post)\s*.*(?:\.env|credentials|secrets)/gi, label: 'HTTP exfiltration of secrets' },
  { regex: /base64.*(?:send|post|fetch|curl)/gi, label: 'Base64 encode and send' },
];

/** System override / destructive command patterns. */
const SYSTEM_OVERRIDE_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /execute\s+command/gi, label: 'Execute command directive' },
  { regex: /run\s+shell/gi, label: 'Run shell directive' },
  { regex: /\brm\s+-rf\b/g, label: 'Recursive delete (rm -rf)' },
  { regex: /\bformat\s+c:/gi, label: 'Format drive (format c:)' },
  { regex: /delete\s+all/gi, label: 'Delete all directive' },
  { regex: /\bdrop\s+(?:table|database)\b/gi, label: 'SQL drop command' },
  { regex: /\bshutdown\b.*(?:\/s|now|-h)/gi, label: 'System shutdown' },
  { regex: /\bkill\s+-9\b/g, label: 'Force kill process' },
  { regex: /\bmkfs\b/g, label: 'Filesystem format (mkfs)' },
  { regex: /\bdd\s+if=/g, label: 'Disk destroyer (dd)' },
];

/** Directories to skip during recursive scanning. */
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '__pycache__',
]);

/** Maximum file size to scan (1MB). */
const MAX_FILE_SIZE = 1024 * 1024;

/** Scannable file extensions for skill files. */
const SCAN_EXTENSIONS = new Set([
  '.md', '.txt', '.yaml', '.yml', '.json', '.toml',
  '.js', '.ts', '.py', '.sh', '.bash', '.ps1',
]);

/**
 * Recursively collects skill files from a directory.
 */
function collectSkillFiles(dir: string): string[] {
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
        results.push(...collectSkillFiles(fullPath));
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SCAN_EXTENSIONS.has(ext)) {
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
 * Detects hidden instructions after large whitespace blocks.
 * Returns findings for execution hijacking via whitespace hiding.
 */
function checkWhitespaceHiding(content: string, filePath: string, moduleName: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  // Check for large blocks of whitespace (50+ consecutive blank lines or spaces)
  const largeWhitespace = /\n{50,}/g;
  let match: RegExpExecArray | null;
  while ((match = largeWhitespace.exec(content)) !== null) {
    // Check if there's non-whitespace content after the gap
    const after = content.substring(match.index + match[0].length).trim();
    if (after.length > 0) {
      const upToMatch = content.substring(0, match.index);
      const lineNumber = upToMatch.split('\n').length;

      findings.push({
        module: moduleName as 'SkillScanner',
        severity: Severity.HIGH,
        title: 'Hidden Instructions After Whitespace',
        description: 'Found content hidden after a large block of whitespace — a common prompt injection technique.',
        filePath,
        line: lineNumber,
        remediation: 'Remove the hidden content or consolidate whitespace in this skill file',
      });
    }
  }

  return findings;
}

/**
 * Detects base64 encoded commands that could hide malicious payloads.
 */
function checkBase64Payloads(content: string, filePath: string, moduleName: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  // Match base64 strings that are suspiciously long (likely encoded commands)
  const base64Pattern = /(?:base64|atob|btoa|decode)\s*\(?\s*['"]([A-Za-z0-9+/=]{40,})['"]/g;
  let match: RegExpExecArray | null;
  while ((match = base64Pattern.exec(content)) !== null) {
    const upToMatch = content.substring(0, match.index);
    const lineNumber = upToMatch.split('\n').length;

    findings.push({
      module: moduleName as 'SkillScanner',
      severity: Severity.HIGH,
      title: 'Base64 Encoded Payload Detected',
      description: 'Found a base64 encoded string that may conceal malicious commands.',
      filePath,
      line: lineNumber,
      evidence: match[0].substring(0, 40) + '...',
      remediation: 'Decode and inspect the base64 content. Remove if malicious.',
    });
  }

  return findings;
}

/**
 * SkillScanner — Detects malicious patterns in AI agent skill files
 * including prompt injection, data exfiltration, system override,
 * and execution hijacking via hidden instructions.
 */
export class SkillScanner implements ScannerModule {
  name = 'SkillScanner' as const;
  label = '🛡️ Skill Scanner';

  async scan(options: ScanOptions): Promise<ModuleResult> {
    const startTime = Date.now();
    const findings: ScanFinding[] = [];
    let totalFilesScanned = 0;

    for (const skillDir of SKILL_DIRS) {
      const fullSkillDir = path.join(options.path, skillDir);
      if (!fs.existsSync(fullSkillDir)) continue;

      // Report skill directory discovery
      findings.push({
        module: this.name,
        severity: Severity.INFO,
        title: `Skill Directory Found — ${skillDir}`,
        description: `AI agent skill directory detected at ${fullSkillDir}. Scanning for malicious patterns.`,
        filePath: fullSkillDir,
        remediation: 'Periodically audit third-party skills for malicious content',
      });

      const files = collectSkillFiles(fullSkillDir);
      totalFilesScanned += files.length;

      for (const filePath of files) {
        let content: string;
        try {
          content = fs.readFileSync(filePath, 'utf-8');
        } catch {
          continue; // Skip unreadable files
        }

        // Check prompt injection patterns
        for (const pattern of PROMPT_INJECTION_PATTERNS) {
          pattern.regex.lastIndex = 0;

          let match: RegExpExecArray | null;
          while ((match = pattern.regex.exec(content)) !== null) {
            const upToMatch = content.substring(0, match.index);
            const lineNumber = upToMatch.split('\n').length;

            findings.push({
              module: this.name,
              severity: Severity.CRITICAL,
              title: `Prompt Injection — ${pattern.label}`,
              description: `Detected a prompt injection pattern that attempts to override AI behavior.`,
              filePath,
              line: lineNumber,
              evidence: match[0],
              remediation: 'Remove or quarantine this skill file — it contains prompt injection attempts',
            });
          }
        }

        // Check data exfiltration patterns
        for (const pattern of DATA_EXFIL_PATTERNS) {
          pattern.regex.lastIndex = 0;

          let match: RegExpExecArray | null;
          while ((match = pattern.regex.exec(content)) !== null) {
            const upToMatch = content.substring(0, match.index);
            const lineNumber = upToMatch.split('\n').length;

            findings.push({
              module: this.name,
              severity: Severity.CRITICAL,
              title: `Data Exfiltration Risk — ${pattern.label}`,
              description: `Detected a pattern that may exfiltrate sensitive data to an external endpoint.`,
              filePath,
              line: lineNumber,
              evidence: match[0].substring(0, 80),
              remediation: 'Remove this skill immediately — it may be stealing sensitive data',
            });
          }
        }

        // Check system override / destructive patterns
        for (const pattern of SYSTEM_OVERRIDE_PATTERNS) {
          pattern.regex.lastIndex = 0;

          let match: RegExpExecArray | null;
          while ((match = pattern.regex.exec(content)) !== null) {
            const upToMatch = content.substring(0, match.index);
            const lineNumber = upToMatch.split('\n').length;

            findings.push({
              module: this.name,
              severity: Severity.HIGH,
              title: `System Override Risk — ${pattern.label}`,
              description: `Detected a destructive system command pattern in a skill file.`,
              filePath,
              line: lineNumber,
              evidence: match[0],
              remediation: 'Remove or quarantine this skill — it contains dangerous system commands',
            });
          }
        }

        // Check execution hijacking: hidden instructions after whitespace
        findings.push(...checkWhitespaceHiding(content, filePath, this.name));

        // Check execution hijacking: base64 encoded commands
        findings.push(...checkBase64Payloads(content, filePath, this.name));
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
