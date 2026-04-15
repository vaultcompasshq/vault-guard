#!/usr/bin/env node

import { buildCli } from './cli';

const program = buildCli();

// Parse arguments and execute command
program.parseAsync().then(() => {
  // Successful completion
  process.exit(0);
}).catch((error) => {
  // Handle errors
  console.error(error);
  process.exit(1);
});
