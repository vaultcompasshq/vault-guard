#!/usr/bin/env node

import { buildCli, handleFatalError } from './cli';

const nodeMajor = Number(process.versions.node.split('.')[0]);
if (nodeMajor < 22) {
  console.warn(
    `Warning: vault-guard requires Node.js 22 or later (current: ${process.version}). ` +
      'Some features may not work correctly.',
  );
}

const program = buildCli();

// npx (and some wrappers) forward a leading `--` into argv. Commander treats
// that as end-of-options, so `--format sarif` is ignored and text banners
// pollute machine-readable stdout. Drop a single leading separator.
if (process.argv[2] === '--') {
  process.argv.splice(2, 1);
}

// Parse arguments and execute command
// Exit 1 means findings only, so an escaped error is exit 2 (see handleFatalError).
program.parseAsync().catch(handleFatalError);
