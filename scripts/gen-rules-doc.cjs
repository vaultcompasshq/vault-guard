'use strict';

/**
 * Regenerates docs/RULES.md from the built core package (single source of truth).
 * Run after `pnpm build` (or at least `pnpm --filter @vaultcompass/vault-guard-core build`).
 */

const fs = require('fs');
const path = require('path');

const coreIndex = path.join(__dirname, '..', 'packages', 'core', 'dist', 'index.js');

function escapeMdCell(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ');
}

function main() {
  if (!fs.existsSync(coreIndex)) {
    console.error(
      `Missing ${coreIndex}. Run \`pnpm build\` (or core build) before generating RULES.md.`,
    );
    process.exit(1);
  }

  const { getBuiltinPatternDocEntries } = require(coreIndex);
  const entries = getBuiltinPatternDocEntries();

  const lines = [];
  lines.push('# Built-in secret patterns');
  lines.push('');
  lines.push(
    'Generated from `BUILTIN_PATTERNS` in `packages/core/src/scanners/secret-scanner.ts`.',
  );
  lines.push('Run `pnpm build && node scripts/gen-rules-doc.cjs` after touching that map.',
  );
  lines.push('Do not hand-edit this file; CI rejects drift (see `.github/workflows/ci.yml`).');
  lines.push('');
  lines.push('## Pattern selection');
  lines.push('');
  lines.push(
    'The built-in set is deliberately narrow. Each entry either matches a structured token shape ' +
      '(`sk-`, `AKIA…`, `xox[baprs]-…`, `gh[pousor]_…`) or anchors a generic shape to a keyword ' +
      'context (`api_key=`, `password=`, `Bearer …`).',
  );
  lines.push('');
  lines.push(
    'Unanchored generic patterns (raw 32-char hex, MD5/SHA1 shapes, base64 blobs) are intentionally ' +
      'absent; they generate too many false positives on legitimate hashes, hex colors, and asset ' +
      'fingerprints to be useful as a default.',
  );
  lines.push('');
  lines.push('## Entropy gate');
  lines.push('');
  lines.push(
    'Patterns with a `Min entropy` value drop matches whose Shannon entropy falls below the threshold. ' +
      'This is what stops `password = "password123"` from being flagged as a `password-in-code` hit, ' +
      'and what keeps `api_key = "REPLACE_ME_BEFORE_PROD"` from setting off `api-key-generic`. ' +
      'Patterns without an entropy threshold are structured enough that the regex itself is the gate.',
  );
  lines.push('');
  lines.push('## Patterns');
  lines.push('');
  lines.push('| ID | Severity | Min entropy | Regex flags | Regex source |');
  lines.push('| --- | --- | --- | --- | --- |');

  for (const e of entries) {
    const entropy = e.minEntropy !== undefined ? String(e.minEntropy) : '-';
    lines.push(
      `| \`${escapeMdCell(e.id)}\` | ${escapeMdCell(e.severity)} | ${escapeMdCell(entropy)} | \`${escapeMdCell(e.regexFlags || '')}\` | \`${escapeMdCell(e.regexSource)}\` |`,
    );
  }
  lines.push('');

  const outPath = path.join(__dirname, '..', 'docs', 'RULES.md');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, lines.join('\n'), 'utf8');
}

main();
