import { ScanReport } from '../types';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Generates an HTML report.
 */
export function generateHtmlReport(report: ScanReport, outputPath: string): void {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DevArmor Security Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 20px; background-color: #f9fafb; color: #111827; }
    h1 { color: #111827; }
    .summary { display: flex; gap: 20px; margin-bottom: 30px; }
    .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); flex: 1; }
    .metric { font-size: 2rem; font-weight: bold; }
    .critical { color: #dc2626; }
    .high { color: #ea580c; }
    .medium { color: #ca8a04; }
    .low { color: #2563eb; }
    .info { color: #4b5563; }
    .module-section { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #e5e7eb; }
    th { background-color: #f3f4f6; }
  </style>
</head>
<body>
  <h1>DevArmor Security Scan Report</h1>
  <p><strong>Path Scanned:</strong> ${report.scanPath}</p>
  <p><strong>Date:</strong> ${new Date(report.timestamp).toLocaleString()}</p>
  
  <div class="summary">
    <div class="card">
      <h3>Total Findings</h3>
      <div class="metric">${report.summary.totalFindings}</div>
    </div>
    <div class="card">
      <h3>Critical</h3>
      <div class="metric critical">${report.summary.critical}</div>
    </div>
    <div class="card">
      <h3>High</h3>
      <div class="metric high">${report.summary.high}</div>
    </div>
  </div>

  <h2>Module Results</h2>
  ${report.modules.map(mod => `
    <div class="module-section">
      <h3>${mod.label}</h3>
      <p>Duration: ${mod.durationMs}ms | Items Scanned: ${mod.itemsScanned}</p>
      ${mod.findings.length > 0 ? `
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Title</th>
              <th>File</th>
            </tr>
          </thead>
          <tbody>
            ${mod.findings.map(f => `
              <tr>
                <td class="${f.severity.toLowerCase()}">${f.severity}</td>
                <td>${f.title}</td>
                <td>${f.filePath || 'N/A'}${f.line ? `:${f.line}` : ''}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      ` : '<p>No issues found.</p>'}
    </div>
  `).join('')}
</body>
</html>`;

  fs.writeFileSync(path.resolve(outputPath), html, 'utf-8');
}
