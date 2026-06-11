const esbuild = require('esbuild');
const path = require('path');
const pkg = require('../package.json');

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
    define: { __VG_MCP_VERSION__: JSON.stringify(pkg.version) },
  })
  .catch(() => process.exit(1));
