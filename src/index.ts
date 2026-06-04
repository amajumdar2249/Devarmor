#!/usr/bin/env node
// ============================================================
// DevArmor — Entry Point
// One CLI command to secure your AI-powered developer workstation.
// ============================================================

import { cli } from './cli';

cli().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
