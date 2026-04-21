const esbuild = require('esbuild');
const path = require('path');

esbuild
  .build({
    entryPoints: [path.join(__dirname, '..', 'src', 'index.ts')],
    bundle: true,
    platform: 'node',
    target: 'node18',
    format: 'cjs',
    outfile: path.join(__dirname, '..', 'dist', 'index.js'),
    packages: 'external',
    banner: { js: '#!/usr/bin/env node\n' },
  })
  .catch(() => process.exit(1));
