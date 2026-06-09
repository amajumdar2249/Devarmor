// ============================================================
// DevArmor — CLI Interface
// One CLI command to secure your AI-powered developer workstation.
// ============================================================

import { Command } from 'commander';
import { runScan } from './scanner';
import { renderTerminalReport } from './report/terminal';
import { renderJsonReport } from './report/json';
import { generateHtmlReport } from './report/html';
import { ScanOptions, ModuleName } from './types';

/** Dynamic import helper for ESM-only chalk. */
async function getChalk() { return (await import('chalk')).default; }

/** Valid module names for --modules flag validation. */
const VALID_MODULES: ModuleName[] = [
  'SecretScanner',
  'AgentResidueScanner',
  'MCPAuditor',
  'SkillScanner',
  'PostureChecker',
];

/** Prints the ASCII art banner. */
async function printBanner(): Promise<void> {
  const chalk = await getChalk();

  const banner = `
${chalk.cyan.bold('  ╔══════════════════════════════════════════════╗')}
${chalk.cyan.bold('  ║')}${chalk.white.bold('  ██████╗ ███████╗██╗   ██╗ █████╗ ██████╗  ')}${chalk.cyan.bold('║')}
${chalk.cyan.bold('  ║')}${chalk.white.bold('  ██╔══██╗██╔════╝██║   ██║██╔══██╗██╔══██╗ ')}${chalk.cyan.bold('║')}
${chalk.cyan.bold('  ║')}${chalk.white.bold('  ██║  ██║█████╗  ██║   ██║███████║██████╔╝ ')}${chalk.cyan.bold('║')}
${chalk.cyan.bold('  ║')}${chalk.white.bold('  ██║  ██║██╔══╝  ╚██╗ ██╔╝██╔══██║██╔══██╗ ')}${chalk.cyan.bold('║')}
${chalk.cyan.bold('  ║')}${chalk.white.bold('  ██████╔╝███████╗ ╚████╔╝ ██║  ██║██║  ██║ ')}${chalk.cyan.bold('║')}
${chalk.cyan.bold('  ║')}${chalk.white.bold('  ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝ ')}${chalk.cyan.bold('║')}
${chalk.cyan.bold('  ║')}${chalk.yellow.bold('       ─── ARMOR ───────────────────────────')}${chalk.cyan.bold('║')}
${chalk.cyan.bold('  ╚══════════════════════════════════════════════╝')}
${chalk.dim('  One CLI command to secure your AI-powered workstation.')}
${chalk.dim('  v1.0.0')}
`;

  console.log(banner);
}

/**
 * Parses a comma-separated module list and validates module names.
 */
function parseModules(value: string): ModuleName[] {
  if (!value) return [];
  const names = value.split(',').map((s) => s.trim());
  const invalid = names.filter((n) => !VALID_MODULES.includes(n as ModuleName));
  if (invalid.length > 0) {
    console.error(`Error: Unknown module(s): ${invalid.join(', ')}`);
    console.error(`Valid modules: ${VALID_MODULES.join(', ')}`);
    process.exit(1);
  }
  return names as ModuleName[];
}

/** Sets up and runs the CLI. */
export async function cli(): Promise<void> {
  await printBanner();

  const program = new Command();

  program
    .name('devarmor')
    .description('One CLI command to secure your entire AI-powered developer workstation.')
    .version('1.0.0');

  program
    .command('scan')
    .description('Scan your workstation for security issues')
    .option('-p, --path <dir>', 'Root directory to scan', '.')
    .option(
      '-r, --report <format>',
      'Report format: terminal, html, or json',
      'terminal',
    )
    .option('-f, --fix', 'Attempt to auto-fix certain issues', false)
    .option('-v, --verbose', 'Enable verbose logging', false)
    .option(
      '-m, --modules <list>',
      'Comma-separated list of modules to run (e.g. SecretScanner,MCPAuditor)',
      '',
    )
    .action(async (opts) => {
      const scanOptions: ScanOptions = {
        path: opts.path,
        report: opts.report as ScanOptions['report'],
        fix: opts.fix,
        verbose: opts.verbose,
        modules: parseModules(opts.modules),
      };

      // Validate report format
      if (!['terminal', 'html', 'json'].includes(scanOptions.report)) {
        console.error(`Error: Invalid report format "${scanOptions.report}". Use terminal, html, or json.`);
        process.exit(1);
      }

      const report = await runScan(scanOptions);

      // Render the requested report format
      switch (scanOptions.report) {
        case 'json':
          renderJsonReport(report);
          break;
        case 'html':
          generateHtmlReport(report, 'devarmor-report.html');
          console.log('\nHTML report generated at devarmor-report.html');
          break;
        case 'terminal':
        default:
          renderTerminalReport(report);
          break;
      }

      // Exit with non-zero code if critical findings exist
      if (report.summary.critical > 0) {
        process.exit(1);
      }
    });

  await program.parseAsync(process.argv);
}
