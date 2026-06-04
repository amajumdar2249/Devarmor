// ============================================================
// DevArmor — Scanner Orchestrator
// Runs all scan modules and aggregates results into a report.
// ============================================================

import * as path from 'path';
import {
  ScanOptions,
  ScanReport,
  ScannerModule,
  ModuleResult,
  Severity,
} from './types';
import { SecretScanner } from './modules/secret-scanner';
import { AgentResidueScanner } from './modules/agent-residue';
import { MCPAuditor } from './modules/mcp-auditor';
import { SkillScanner } from './modules/skill-scanner';
import { PostureChecker } from './modules/posture-checker';

/** Dynamic import helpers for ESM-only packages. */
async function getChalk() { return (await import('chalk')).default; }
async function getOra() { return (await import('ora')).default; }

/** All available scanner modules in execution order. */
const ALL_MODULES: ScannerModule[] = [
  new SecretScanner(),
  new AgentResidueScanner(),
  new MCPAuditor(),
  new SkillScanner(),
  new PostureChecker(),
];

/**
 * Runs the DevArmor scan pipeline.
 *
 * Modules execute sequentially for cleaner terminal output.
 * Each module gets an ora spinner to show progress.
 */
export async function runScan(options: ScanOptions): Promise<ScanReport> {
  const chalk = await getChalk();
  const ora = await getOra();
  const startTime = Date.now();
  const resolvedPath = path.resolve(options.path);

  console.log(
    chalk.cyan('\n🔍 Scanning: ') + chalk.white(resolvedPath) + '\n',
  );

  // Filter to requested modules (empty = all)
  const modulesToRun =
    options.modules.length > 0
      ? ALL_MODULES.filter((m) => options.modules.includes(m.name))
      : ALL_MODULES;

  const results: ModuleResult[] = [];

  // Run each module sequentially
  for (const mod of modulesToRun) {
    const spinner = ora({
      text: `Running ${mod.label}...`,
      color: 'cyan',
    }).start();

    try {
      const result = await mod.scan({ ...options, path: resolvedPath });
      results.push(result);

      const findingCount = result.findings.length;
      const icon = findingCount > 0 ? '⚠' : '✔';
      const color = findingCount > 0 ? chalk.yellow : chalk.green;

      spinner.succeed(
        color(
          `${mod.label}  ${icon} ${findingCount} finding${findingCount !== 1 ? 's' : ''}  (${result.durationMs}ms)`,
        ),
      );
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);

      results.push({
        module: mod.name,
        label: mod.label,
        success: false,
        durationMs: Date.now() - startTime,
        itemsScanned: 0,
        findings: [],
        error: errorMsg,
      });

      spinner.fail(chalk.red(`${mod.label}  ✗ Error: ${errorMsg}`));
    }
  }

  // Aggregate summary counts
  const allFindings = results.flatMap((r) => r.findings);
  const summary = {
    totalFindings: allFindings.length,
    critical: allFindings.filter((f) => f.severity === Severity.CRITICAL).length,
    high: allFindings.filter((f) => f.severity === Severity.HIGH).length,
    medium: allFindings.filter((f) => f.severity === Severity.MEDIUM).length,
    low: allFindings.filter((f) => f.severity === Severity.LOW).length,
    info: allFindings.filter((f) => f.severity === Severity.INFO).length,
  };

  const totalDurationMs = Date.now() - startTime;

  // Print quick summary
  console.log(chalk.dim('\n' + '─'.repeat(50)));
  console.log(
    chalk.bold('\n📊 Scan Complete  ') +
    chalk.dim(`(${totalDurationMs}ms)\n`),
  );

  if (summary.totalFindings === 0) {
    console.log(chalk.green.bold('  ✔ No findings — workstation looks clean!\n'));
  } else {
    const parts: string[] = [];
    if (summary.critical > 0) parts.push(chalk.bgRed.white.bold(` ${summary.critical} CRITICAL `));
    if (summary.high > 0) parts.push(chalk.red.bold(`${summary.high} HIGH`));
    if (summary.medium > 0) parts.push(chalk.yellow.bold(`${summary.medium} MEDIUM`));
    if (summary.low > 0) parts.push(chalk.blue(`${summary.low} LOW`));
    if (summary.info > 0) parts.push(chalk.dim(`${summary.info} INFO`));

    console.log(`  ${summary.totalFindings} finding${summary.totalFindings !== 1 ? 's' : ''}: ${parts.join(chalk.dim(' │ '))}\n`);
  }

  return {
    timestamp: new Date(startTime).toISOString(),
    scanPath: resolvedPath,
    version: '1.0.0',
    totalDurationMs,
    modules: results,
    summary,
  };
}
