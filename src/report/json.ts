// ============================================================
// DevArmor — JSON Report Generator
// Outputs scan results as formatted JSON to stdout and file.
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import { ScanReport } from '../types';

/** Dynamic import helper for ESM-only chalk. */
async function getChalk() { return (await import('chalk')).default; }

/** Output filename for the JSON report. */
const REPORT_FILENAME = 'devarmor-report.json';

/**
 * Renders the scan report as JSON.
 *
 * - Prints the full JSON to stdout.
 * - Saves a copy to `devarmor-report.json` in the current directory.
 */
export async function renderJsonReport(report: ScanReport): Promise<void> {
  const chalk = await getChalk();
  const json = JSON.stringify(report, null, 2);

  // Print to stdout
  console.log(json);

  // Save to file
  const outPath = path.resolve(process.cwd(), REPORT_FILENAME);
  try {
    fs.writeFileSync(outPath, json, 'utf-8');
    console.log(
      chalk.dim(`\n📁 Report saved to ${outPath}\n`),
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(chalk.red(`\n⚠ Failed to save report: ${msg}\n`));
  }
}
