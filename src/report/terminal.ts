// ============================================================
// DevArmor — Terminal Report Generator
// Rich colored output with box-drawing characters.
// ============================================================

import { ScanReport, ScanFinding, Severity } from '../types';

/** Dynamic import helper for ESM-only chalk. */
async function getChalk() { return (await import('chalk')).default; }

/** Severity display order — most critical first. */
const SEVERITY_ORDER: Severity[] = [
  Severity.CRITICAL,
  Severity.HIGH,
  Severity.MEDIUM,
  Severity.LOW,
  Severity.INFO,
];

/**
 * Returns a colored severity badge string.
 */
function severityBadge(chalk: any, severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
      return chalk.bgRed.white.bold(` ${severity} `);
    case Severity.HIGH:
      return chalk.bgRedBright.white.bold(` ${severity} `);
    case Severity.MEDIUM:
      return chalk.bgYellow.black.bold(` ${severity} `);
    case Severity.LOW:
      return chalk.bgBlue.white(` ${severity} `);
    case Severity.INFO:
      return chalk.bgGray.white(` ${severity} `);
    default:
      return chalk.dim(severity);
  }
}

/**
 * Renders a full terminal report for a completed scan.
 */
export async function renderTerminalReport(report: ScanReport): Promise<void> {
  const chalk = await getChalk();
  const line = chalk.dim('─'.repeat(60));
  const doubleLine = chalk.dim('═'.repeat(60));

  // ── Header ──
  console.log('\n' + doubleLine);
  console.log(chalk.bold.cyan('  📋 DevArmor Scan Report'));
  console.log(doubleLine);

  console.log(chalk.dim('  Timestamp:  ') + chalk.white(report.timestamp));
  console.log(chalk.dim('  Scan Path:  ') + chalk.white(report.scanPath));
  console.log(chalk.dim('  Duration:   ') + chalk.white(`${report.totalDurationMs}ms`));
  console.log(chalk.dim('  Version:    ') + chalk.white(report.version));

  // ── Module Results ──
  console.log('\n' + line);
  console.log(chalk.bold('  Module Results'));
  console.log(line);

  for (const mod of report.modules) {
    const icon = mod.success
      ? (mod.findings.length > 0 ? chalk.yellow('⚠') : chalk.green('✔'))
      : chalk.red('✗');

    const status = mod.success
      ? chalk.green('passed')
      : chalk.red('failed');

    const findingStr = mod.findings.length > 0
      ? chalk.yellow(` (${mod.findings.length} finding${mod.findings.length !== 1 ? 's' : ''})`)
      : chalk.dim(' (clean)');

    console.log(
      `  ${icon}  ${chalk.bold(mod.label)}  ${status}${findingStr}` +
      chalk.dim(`  ${mod.itemsScanned} items  ${mod.durationMs}ms`),
    );

    if (mod.error) {
      console.log(chalk.red(`     └─ Error: ${mod.error}`));
    }
  }

  // ── Findings by Severity ──
  const allFindings = report.modules.flatMap((m) => m.findings);

  if (allFindings.length > 0) {
    console.log('\n' + line);
    console.log(chalk.bold('  Findings'));
    console.log(line);

    for (const severity of SEVERITY_ORDER) {
      const findings = allFindings.filter((f) => f.severity === severity);
      if (findings.length === 0) continue;

      console.log(
        `\n  ${severityBadge(chalk, severity)}  ${chalk.bold(`${findings.length} finding${findings.length !== 1 ? 's' : ''}`)}`,
      );
      console.log(chalk.dim('  ' + '┄'.repeat(50)));

      for (let i = 0; i < findings.length; i++) {
        const f = findings[i];
        const isLast = i === findings.length - 1;
        const prefix = isLast ? '  └─' : '  ├─';
        const indent = isLast ? '    ' : '  │ ';

        console.log(`${chalk.dim(prefix)} ${chalk.bold(f.title)}`);

        if (f.filePath) {
          const location = f.line ? `${f.filePath}:${f.line}` : f.filePath;
          console.log(`${chalk.dim(indent)} ${chalk.dim('File:')} ${chalk.cyan(location)}`);
        }

        if (f.evidence) {
          console.log(`${chalk.dim(indent)} ${chalk.dim('Evidence:')} ${chalk.yellow(f.evidence)}`);
        }

        if (f.remediation) {
          console.log(`${chalk.dim(indent)} ${chalk.dim('Fix:')} ${chalk.green(f.remediation)}`);
        }
      }
    }
  }

  // ── Final Summary ──
  console.log('\n' + doubleLine);
  console.log(chalk.bold('  📊 Summary'));
  console.log(doubleLine);

  if (report.summary.totalFindings === 0) {
    console.log(chalk.green.bold('\n  ✔ No security findings — workstation is clean!\n'));
  } else {
    console.log(
      `\n  Total: ${chalk.bold(String(report.summary.totalFindings))} finding${report.summary.totalFindings !== 1 ? 's' : ''}\n`,
    );

    const counts: [string, number, (s: string) => string][] = [
      ['CRITICAL', report.summary.critical, (s) => chalk.bgRed.white.bold(` ${s} `)],
      ['HIGH',     report.summary.high,     (s) => chalk.red.bold(s)],
      ['MEDIUM',   report.summary.medium,   (s) => chalk.yellow.bold(s)],
      ['LOW',      report.summary.low,      (s) => chalk.blue(s)],
      ['INFO',     report.summary.info,     (s) => chalk.dim(s)],
    ];

    for (const [label, count, colorFn] of counts) {
      if (count > 0) {
        const bar = chalk.dim('█'.repeat(Math.min(count, 30)));
        console.log(`  ${colorFn(label.padEnd(9))} ${chalk.bold(String(count).padStart(3))}  ${bar}`);
      }
    }

    console.log('');
  }
}
