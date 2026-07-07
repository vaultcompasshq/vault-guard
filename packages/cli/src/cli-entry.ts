#!/usr/bin/env node

import { buildCli } from './cli';

const nodeMajor = Number(process.versions.node.split('.')[0]);
if (nodeMajor < 22) {
  console.warn(
    `Warning: vault-guard requires Node.js 22 or later (current: ${process.version}). ` +
      'Some features may not work correctly.',
  );
}

const program = buildCli();

// Parse arguments and execute command
program.parseAsync().catch((error) => {
  // Handle errors
  console.error(error);
  process.exitCode = 1;
});
