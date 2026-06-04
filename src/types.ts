// ============================================================
// DevArmor — Shared Types
// One CLI command to secure your AI-powered developer workstation.
// ============================================================

/** Severity levels for scan findings, ordered by criticality. */
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO',
}

/** A single security finding discovered during a scan. */
export interface ScanFinding {
  /** Which scanner module produced this finding. */
  module: ModuleName;
  /** Severity of the finding. */
  severity: Severity;
  /** Human-readable title. */
  title: string;
  /** Detailed description of the issue. */
  description: string;
  /** Absolute file path where the issue was found (if applicable). */
  filePath?: string;
  /** Line number within the file (if applicable). */
  line?: number;
  /** The matched content snippet (redacted if sensitive). */
  evidence?: string;
  /** Suggested remediation action. */
  remediation?: string;
}

/** Names of all scanner modules. */
export type ModuleName =
  | 'SecretScanner'
  | 'AgentResidueScanner'
  | 'MCPAuditor'
  | 'SkillScanner'
  | 'PostureChecker';

/** Result returned by each scanner module after execution. */
export interface ModuleResult {
  /** Module identifier. */
  module: ModuleName;
  /** Human-readable module label. */
  label: string;
  /** Whether the module ran successfully. */
  success: boolean;
  /** Time taken in milliseconds. */
  durationMs: number;
  /** Number of files/items scanned. */
  itemsScanned: number;
  /** All findings from this module. */
  findings: ScanFinding[];
  /** Optional error message if the module failed. */
  error?: string;
}

/** Overall scan report aggregating all module results. */
export interface ScanReport {
  /** Timestamp when the scan started. */
  timestamp: string;
  /** Root path that was scanned. */
  scanPath: string;
  /** DevArmor version. */
  version: string;
  /** Total scan duration in milliseconds. */
  totalDurationMs: number;
  /** Results from each module. */
  modules: ModuleResult[];
  /** Aggregated summary counts. */
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

/** Configuration options for the scan command. */
export interface ScanOptions {
  /** Root directory to scan. */
  path: string;
  /** Report output format. */
  report: 'terminal' | 'html' | 'json';
  /** Whether to attempt auto-fix for certain issues. */
  fix: boolean;
  /** Specific modules to run (empty = all). */
  modules: ModuleName[];
  /** Verbose logging. */
  verbose: boolean;
}

/** Interface that all scanner modules must implement. */
export interface ScannerModule {
  /** Module name identifier. */
  name: ModuleName;
  /** Human-readable label. */
  label: string;
  /** Run the scan and return results. */
  scan(options: ScanOptions): Promise<ModuleResult>;
}
