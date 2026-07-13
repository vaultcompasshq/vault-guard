#!/usr/bin/env node
/*
 * Public-repo hygiene guard: fail CI if tracked files contain tokens whose
 * SHA-256 (lowercased) matches the blocklist below. Plaintext venture codenames
 * are never stored in this repo — only hashes. To add an entry locally:
 *
 *   node -e "const c=require('crypto');const t=process.argv[1];console.log(c.createHash('sha256').update(t.toLowerCase()).digest('hex'))" '<token>'
 *
 * Paste the hash into BANNED_HASHES. See CONTRIBUTING.md § Public repository hygiene.
 */
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// SHA-256(lowercase token) — no plaintext codenames in the repository.
const BANNED_HASHES = new Set([
  'bcbff8a223bdb66059e43ae951a28ed12598c9e782fb65c58dabcd347f65cabe',
  'ec4e8dbcdbe500197bb27e769cee7864c0a4b4876a604998a23c80bbcc979d4c',
  '8bb4b7a9e837acadf49af332f3211a29f98e2239aa985825f1fe62cdf780c068',
  'cd800cbc9cd106b8f8646762b9ba7c530812555958e019b97c0a9878b005c52f',
  '9f9f3ba21e38f52a4a40f521490c33c4a2da799b5235c53374ad159ea8d0000b',
  'd52aa800a6d18843a0369b60f374fefb59b2cb91318b83c040f9e9d561ee96c4',
  'e44dbe116f27c5aef9c3386906b82f94f8b557a48c4b036a248f3ba75ddaece1',
  '57cd823001a8558b03746dd1dac01fe13b4fc442728bed4b5840703a755b810e',
  '59f5eae64585bb2483b57c4618b144e92011ba0656565003a42db23f029f8bd5',
  'c227174107761c30f27338905527dc53032ac5daf6d225ce9561ba4110344d7d',
  'd792a2b651ecea40434f60efb0435efcef8eb60aaefaa85f0660e718d074de76',
]);

const ALLOWLIST = new Set(['CONTRIBUTING.md', 'scripts/check-private-names.cjs']);

// Generic internal monorepo path shape — no usernames or product names.
const INTERNAL_PATH = /\/Users\/[^/\s]+\/Desktop\/Projects\//i;

const TOKEN = /\b[a-z][a-z0-9]*(?:-[a-z0-9]+)*\b/gi;

function hashToken(token) {
  return crypto.createHash('sha256').update(token.toLowerCase()).digest('hex');
}

const files = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'buffer' })
  .toString('utf8')
  .split('\0')
  .filter(Boolean);

let failed = false;

for (const rel of files) {
  if (ALLOWLIST.has(rel)) continue;
  if (rel.startsWith('node_modules/')) continue;

  const abs = path.join(ROOT, rel);
  let text;
  try {
    text = fs.readFileSync(abs, 'utf8');
  } catch {
    continue;
  }

  const pathMatch = text.match(INTERNAL_PATH);
  if (pathMatch) {
    const line = text.slice(0, pathMatch.index).split('\n').length;
    console.error(`✗ ${rel}:${line}: internal workspace path`);
    failed = true;
  }

  for (const match of text.matchAll(TOKEN)) {
    const token = match[0];
    if (BANNED_HASHES.has(hashToken(token))) {
      const line = text.slice(0, match.index).split('\n').length;
      console.error(`✗ ${rel}:${line}: blocked token (hash match)`);
      failed = true;
    }
  }
}

if (failed) {
  console.error('\ncheck-private-names: remove private portfolio references from tracked files.');
  console.error('See CONTRIBUTING.md § Public repository hygiene.');
  process.exit(1);
}

console.log('check-private-names: no private portfolio references in tracked files.');
