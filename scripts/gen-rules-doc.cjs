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
  lines.push('## Sequential-run gate');
  lines.push('');
  // The example values are assembled from fragments for the same reason
  // bench/generate-fixtures.cjs does it: a contiguous alphabet run under a real
  // vendor prefix matches this scanner's own rules, and a committed copy would
  // be flagged by the pre-commit hook. Joined, they read normally in RULES.md.
  //
  // The two vendor examples are additionally cut short with an ellipsis. The
  // fragments keep the literal out of THIS file, but RULES.md is generated and
  // committed, so a complete provider-key shape would simply land in git
  // history there instead and trip push protection on the way up. Ending the
  // example early keeps the point without ever writing a whole key shape.
  const RUN_EXAMPLE = ['abcdefghijklm', 'nopqrstuvwxyz', '0123456789'].join('');
  const GH_RUN_EXAMPLE = ['gh', 'p_', 'abcdefghij'].join('') + '…';
  const AWS_RUN_EXAMPLE = ['AK', 'IA', 'ABCDEFGH'].join('') + '…';
  lines.push(
    'Shannon entropy counts how often each character occurs and throws the order away. A strict ' +
      'alphabet run uses every character exactly once, which is the flattest frequency distribution ' +
      `there is, so \`api_key = "${RUN_EXAMPLE}"\` scores at the top of the range ` +
      'and walks straight through the entropy gate. No threshold fixes that: order is the signal, and ' +
      'entropy does not look at order.',
  );
  lines.push('');
  lines.push(
    'A separate check runs ahead of the entropy gate and drops any value where at least 75% of the ' +
      'characters sit inside runs of three or more consecutive code points, ascending or descending. ' +
      'That covers `abcdef…`, `zyxwvu…`, and the same short run repeated. A value that is half run and ' +
      'half random scores 50% and survives, because a real credential can contain an incidental run. ' +
      'Values shorter than 12 characters are never checked: at that length coverage says nothing, ' +
      'since a four-character value is trivially "all run".',
  );
  lines.push('');
  lines.push(
    'Unlike the entropy gate this one applies to vendor-anchored patterns too, which have no entropy ' +
      `threshold of their own, and that is where it earns its keep, since \`${GH_RUN_EXAMPLE}\` and ` +
      `\`${AWS_RUN_EXAMPLE}\` are how a fake key gets typed by hand. It is safe there for the same ` +
      'reason it is useful: a real provider key comes from a random source and cannot be the alphabet. ' +
      'The fixed vendor prefix counts toward the length but is not itself a run, which is why the ' +
      'threshold sits at 75% rather than higher: `AKIA` plus a 16-character run is only 80% covered.',
  );
  lines.push('');
  lines.push(
    'That safety argument holds only for machine-issued credentials. For anything a person types, a ' +
      'run is a WEAK secret rather than a fake one, and suppressing it destroys the finding instead of ' +
      'demoting it. Rules whose value is human-chosen are therefore exempt from this check and are ' +
      'gated by entropy alone: `password-in-code`, and the four connection-string rules ' +
      '(`postgresql-url`, `mysql-url`, `mongodb-url`, `redis-url`), whose secret is the password ' +
      'component of the DSN. `password-in-code` matters most here, because its minimum capture is 12 ' +
      'characters, the same as this check\'s minimum value length, so an ordinary weak password sat ' +
      'exactly on the boundary.',
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
