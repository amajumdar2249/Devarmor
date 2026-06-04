// ============================================================
// DevArmor — MCP Auditor Module
// Audits MCP server configurations for security issues.
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

/** MCP config files to look for. */
const MCP_CONFIG_FILENAMES = [
  'claude_desktop_config.json',
  '.mcp.json',
  'mcp.json',
];

/** Dangerous command patterns that indicate shell injection risk. */
const DANGEROUS_COMMANDS: { pattern: RegExp; label: string }[] = [
  { pattern: /\brm\s+-rf\b/gi, label: 'Recursive delete (rm -rf)' },
  { pattern: /\brm\s+/gi, label: 'File deletion (rm)' },
  { pattern: /\bdel\s+/gi, label: 'File deletion (del)' },
  { pattern: /\brmdir\s+/gi, label: 'Directory removal (rmdir)' },
  { pattern: /powershell\s+-[Ee]ncoded[Cc]ommand/g, label: 'PowerShell encoded command' },
  { pattern: /\bcurl\b.*\|\s*(?:sh|bash|zsh)\b/g, label: 'Curl piped to shell' },
  { pattern: /\bwget\b.*\|\s*(?:sh|bash|zsh)\b/g, label: 'Wget piped to shell' },
  { pattern: /\beval\s*\(/g, label: 'Dynamic eval execution' },
  { pattern: /\bexec\s+/gi, label: 'Process execution (exec)' },
  { pattern: /\bchmod\s+777\b/g, label: 'Overly permissive chmod 777' },
  { pattern: /\bnet\s+user\b/gi, label: 'Windows user management (net user)' },
  { pattern: /\breg\s+add\b/gi, label: 'Windows registry modification' },
];

/** Patterns that indicate hardcoded API keys/tokens in MCP configs. */
const SECRET_PATTERNS = [
  { regex: /sk-[A-Za-z0-9_-]{20,}/g, label: 'OpenAI API Key' },
  { regex: /sk-ant-[A-Za-z0-9_-]{20,}/g, label: 'Anthropic API Key' },
  { regex: /ghp_[A-Za-z0-9]{36,}/g, label: 'GitHub PAT' },
  { regex: /AKIA[0-9A-Z]{16}/g, label: 'AWS Access Key' },
  { regex: /glpat-[A-Za-z0-9_-]{20,}/g, label: 'GitLab PAT' },
  { regex: /(?:api_key|apikey|secret|token|password|auth_token)\s*[=:]\s*["'][A-Za-z0-9_/+=.-]{10,}["']/gi, label: 'Hardcoded Credential' },
];

/** Overly broad filesystem paths that grant too much access. */
const BROAD_FS_PATTERNS = [
  { pattern: /[\"']\/[\"']/g, label: 'Root filesystem (/)' },
  { pattern: /[\"']C:\\\\[\"']/gi, label: 'Root drive (C:\\)' },
  { pattern: /[\"']~[\"']/g, label: 'Home directory (~)' },
  { pattern: /[\"']\/home[\"']/g, label: 'All home directories (/home)' },
  { pattern: /[\"']\/Users[\"']/g, label: 'All user directories (/Users)' },
  { pattern: /[\"']\*[\"']/g, label: 'Wildcard glob (*)' },
];

/** Maximum file size to scan (512KB — configs should be small). */
const MAX_CONFIG_SIZE = 512 * 1024;

/**
 * Redacts sensitive content for safe display.
 */
function redact(value: string): string {
  if (value.length <= 12) return '****';
  return value.substring(0, 4) + '****' + value.substring(value.length - 4);
}

/**
 * Locates all MCP config files in common locations.
 */
function findMCPConfigs(projectPath: string): string[] {
  const results: string[] = [];
  const homeDir = os.homedir();

  // Search locations: home dir, common config dirs, project dir
  const searchRoots = [
    homeDir,
    path.join(homeDir, '.claude'),
    path.join(homeDir, '.cursor'),
    path.join(homeDir, '.config'),
    path.join(homeDir, 'AppData', 'Roaming', 'Claude'),
    path.join(homeDir, 'Library', 'Application Support', 'Claude'),
    projectPath,
    path.join(projectPath, '.claude'),
    path.join(projectPath, '.cursor'),
  ];

  for (const root of searchRoots) {
    if (!fs.existsSync(root)) continue;

    for (const filename of MCP_CONFIG_FILENAMES) {
      const filePath = path.join(root, filename);
      try {
        if (fs.existsSync(filePath)) {
          const stat = fs.statSync(filePath);
          if (stat.isFile() && stat.size <= MAX_CONFIG_SIZE && stat.size > 0) {
            // Avoid duplicates
            if (!results.includes(filePath)) {
              results.push(filePath);
            }
          }
        }
      } catch {
        // Skip inaccessible files
      }
    }
  }

  return results;
}

/**
 * MCPAuditor — Audits MCP server configurations for shell injection,
 * over-privileged tool access, hardcoded secrets, insecure transport,
 * and overly broad filesystem access.
 */
export class MCPAuditor implements ScannerModule {
  name = 'MCPAuditor' as const;
  label = '📡 MCP Auditor';

  async scan(options: ScanOptions): Promise<ModuleResult> {
    const startTime = Date.now();
    const findings: ScanFinding[] = [];

    const configFiles = findMCPConfigs(options.path);

    for (const filePath of configFiles) {
      let content: string;
      try {
        content = fs.readFileSync(filePath, 'utf-8');
      } catch {
        continue; // Skip unreadable files
      }

      // Report MCP config discovery
      findings.push({
        module: this.name,
        severity: Severity.INFO,
        title: 'MCP Configuration Found',
        description: `MCP configuration file detected at ${filePath}. Auditing for security issues.`,
        filePath,
        remediation: 'Periodically review MCP server configurations for security',
      });

      // Parse JSON to inspect structure
      let config: Record<string, unknown>;
      try {
        config = JSON.parse(content);
      } catch {
        findings.push({
          module: this.name,
          severity: Severity.LOW,
          title: 'Malformed MCP Configuration',
          description: 'Could not parse MCP config as valid JSON.',
          filePath,
          remediation: 'Fix JSON syntax errors in the MCP configuration',
        });
        continue;
      }

      // Check for shell injection in command args
      for (const pattern of DANGEROUS_COMMANDS) {
        pattern.pattern.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = pattern.pattern.exec(content)) !== null) {
          const upToMatch = content.substring(0, match.index);
          const lineNumber = upToMatch.split('\n').length;

          findings.push({
            module: this.name,
            severity: Severity.CRITICAL,
            title: `Shell Injection Risk — ${pattern.label}`,
            description: `Dangerous command pattern detected in MCP server configuration.`,
            filePath,
            line: lineNumber,
            evidence: match[0],
            remediation: 'Remove dangerous shell commands from MCP server arguments. Use dedicated tools instead of raw shell access.',
          });
        }
      }

      // Check for hardcoded API keys/tokens
      for (const pattern of SECRET_PATTERNS) {
        pattern.regex.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = pattern.regex.exec(content)) !== null) {
          const upToMatch = content.substring(0, match.index);
          const lineNumber = upToMatch.split('\n').length;

          findings.push({
            module: this.name,
            severity: Severity.CRITICAL,
            title: `Hardcoded Secret in MCP Config — ${pattern.label}`,
            description: `Found a potential ${pattern.label} hardcoded in MCP configuration.`,
            filePath,
            line: lineNumber,
            evidence: redact(match[0]),
            remediation: 'Use environment variables instead of hardcoding secrets in MCP configs',
          });
        }
      }

      // Check for overly broad filesystem access
      for (const fsPattern of BROAD_FS_PATTERNS) {
        fsPattern.pattern.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = fsPattern.pattern.exec(content)) !== null) {
          const upToMatch = content.substring(0, match.index);
          const lineNumber = upToMatch.split('\n').length;

          findings.push({
            module: this.name,
            severity: Severity.HIGH,
            title: `Overly Broad Filesystem Access — ${fsPattern.label}`,
            description: `MCP server is configured with access to ${fsPattern.label}, which grants excessive permissions.`,
            filePath,
            line: lineNumber,
            evidence: match[0],
            remediation: 'Restrict MCP server filesystem access to specific project directories only',
          });
        }
      }

      // Check for insecure stdio transport without validation
      const mcpServers = (config as Record<string, unknown>)['mcpServers'] ??
                          (config as Record<string, unknown>)['servers'] ?? {};
      if (typeof mcpServers === 'object' && mcpServers !== null) {
        for (const [serverName, serverConfig] of Object.entries(mcpServers as Record<string, unknown>)) {
          if (typeof serverConfig !== 'object' || serverConfig === null) continue;

          const sc = serverConfig as Record<string, unknown>;

          // Check transport type
          const transport = sc['transport'] ?? 'stdio';
          if (transport === 'stdio') {
            // stdio is default — check if there's any validation/sandboxing
            const hasEnvRestriction = sc['env'] !== undefined;
            const command = String(sc['command'] ?? '');

            if (command && !hasEnvRestriction) {
              findings.push({
                module: this.name,
                severity: Severity.MEDIUM,
                title: `Stdio Transport Without Environment Restrictions — ${serverName}`,
                description: `MCP server "${serverName}" uses stdio transport without explicit environment variable restrictions.`,
                filePath,
                remediation: 'Add explicit "env" configuration to restrict environment variable exposure to MCP servers',
              });
            }
          }

          // Check for over-privileged tool access (wildcard or excessive tool lists)
          const tools = sc['tools'] as string[] | undefined;
          if (Array.isArray(tools)) {
            if (tools.includes('*') || tools.includes('all')) {
              findings.push({
                module: this.name,
                severity: Severity.HIGH,
                title: `Over-Privileged Tool Access — ${serverName}`,
                description: `MCP server "${serverName}" has wildcard tool access, granting it all available tools.`,
                filePath,
                remediation: 'Restrict tool access to only the specific tools the server needs',
              });
            }
          }
        }
      }
    }

    return {
      module: this.name,
      label: this.label,
      success: true,
      durationMs: Date.now() - startTime,
      itemsScanned: configFiles.length,
      findings,
    };
  }
}
