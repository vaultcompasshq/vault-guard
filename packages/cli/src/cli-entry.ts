#!/usr/bin/env node

import { buildCli } from './cli';

const program = buildCli();
program.parse();
