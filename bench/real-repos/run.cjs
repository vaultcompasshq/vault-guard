'use strict';
/**
 * Real-repository validation for 1.10.0 (design 2026-10-12, section 8).
 *
 *   node bench/real-repos/run.cjs <benchDir> <outJson> <cli-1.9.1> <cli-adc39e5> <cli-branch>
 *
 * <benchDir> holds depth-1 clones named react, urllib3, gitleaks and
 * detect-secrets (origin removed), each with an untracked
 * vg-bench-marker.txt. The script commits that marker on a vg-bench branch so
 * --trust-base has a parent commit, then runs each CLI three times per mode
 * and records counts, every finding (never a value), wall times and the four
 * release-blocker conditions. See README.md beside this file.
 *
 * Real-repository validation for 1.11.0 (design 2026-10-17, section 10):
 *
 *   node bench/real-repos/run.cjs --design-2026-10-17 <benchDir> <outJson> <cli-1.10.0> <cli-branch>
 *
 * The same method on eight repositories (the four above plus learning-area,
 * font-awesome, howler and explore), comparing the published 1.10.0 with the
 * branch, plus the binary counts, the per-extension census, head_read_bytes
 * and a load run. See `main1110` below and README.md.
 *
 * Real-repository validation for 1.12.0 (design 2026-10-17 data files,
 * section 9):
 *
 *   node bench/real-repos/run.cjs --design-2026-10-17-data-files <benchDir> <outJson> <cli-1.11.0> <cli-branch>
 *
 * The four 1.10.0 repositories plus the notebook, data and search-chosen
 * repositories of section 9.1, comparing the published 1.11.0 with the
 * branch: the section 9.3 formulas, the demotions and groups, R_media and the
 * expected coincidence count, and the two planted cases. See `mainData`.
 */
const { spawn, spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ARGS = process.argv.slice(2);
const DESIGN_1110 = ARGS[0] === '--design-2026-10-17';
const DESIGN_DATA = ARGS[0] === '--design-2026-10-17-data-files';
const DRIFT = ARGS[0] === '--release-drift';
const [benchDir, outJson, cli191, cliAdc, cliBranch] = DESIGN_1110 || DESIGN_DATA || DRIFT ? [] : ARGS;
if (!DESIGN_1110 && !DESIGN_DATA && !DRIFT && !cliBranch) {
  process.stderr.write('usage: run.cjs <benchDir> <outJson> <cli-1.9.1> <cli-adc39e5> <cli-branch>\n');
  process.stderr.write('   or: run.cjs --design-2026-10-17 <benchDir> <outJson> <cli-1.10.0> <cli-branch>\n');
  process.stderr.write('   or: run.cjs --design-2026-10-17-data-files <benchDir> <outJson> <cli-1.11.0> <cli-branch>\n');
  process.exit(2);
}
const REPOS = ['react', 'urllib3', 'gitleaks', 'detect-secrets'];
const BUILDS = { '1.9.1': cli191, adc39e5: cliAdc, branch: cliBranch };
const RUNS = 3;
const TWO_LETTER = /^[a-z]{2}(?:[-_][A-Za-z]{2,4})?\.(json|ya?ml|ts|js|po|properties)$/;
const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: 'bench',
  GIT_AUTHOR_EMAIL: 'bench@example.invalid',
  GIT_COMMITTER_NAME: 'bench',
  GIT_COMMITTER_EMAIL: 'bench@example.invalid',
};

function git(cwd, args, input) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf-8', env: GIT_ENV, input, maxBuffer: 1 << 30 });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout;
}

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

function prepare(repo) {
  const branch = git(repo, ['rev-parse', '--abbrev-ref', 'HEAD']).trim();
  if (branch !== 'vg-bench') {
    git(repo, ['checkout', '-q', '-b', 'vg-bench']);
    git(repo, ['add', 'vg-bench-marker.txt']);
    git(repo, ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'benchmark marker']);
  }
  return { head: git(repo, ['rev-parse', 'HEAD']).trim(), base: git(repo, ['rev-parse', 'HEAD~1']).trim() };
}

/** Tracked files with a working-tree-encoding, eol/text or filter attribute. */
function transforms(repo) {
  const files = git(repo, ['ls-files', '-z']).split('\0').filter(Boolean);
  const out = git(
    repo,
    ['check-attr', '-z', '--stdin', 'working-tree-encoding', 'eol', 'text', 'filter'],
    files.map(f => `${f}\0`).join(''),
  );
  const parts = out.split('\0');
  const per = new Map();
  for (let i = 0; i + 2 < parts.length; i += 3) {
    const [f, attr, value] = [parts[i], parts[i + 1], parts[i + 2]];
    if (value === 'unspecified' || value === 'unset') continue;
    const e = per.get(f) || {};
    e[attr] = value;
    per.set(f, e);
  }
  const count = pred => [...per.values()].filter(pred).length;
  return {
    files: new Set(per.keys()),
    counts: {
      working_tree_encoding: count(e => e['working-tree-encoding'] !== undefined),
      eol_or_text: count(e => e.eol !== undefined || e.text !== undefined),
      filter: count(e => e.filter !== undefined),
    },
  };
}

function run(cli, repo, args) {
  const times = [];
  let last;
  for (let i = 0; i < RUNS; i++) {
    const t0 = process.hrtime.bigint();
    last = spawnSync(process.execPath, [cli, 'scan', '.', '--format', 'json', ...args], {
      cwd: repo,
      encoding: 'utf-8',
      env: { ...process.env, NO_COLOR: '1' },
      maxBuffer: 1 << 30,
    });
    times.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  let doc = null;
  try {
    doc = JSON.parse(last.stdout);
  } catch {
    doc = null;
  }
  const r = doc ? doc.run || {} : {};
  const findings = doc
    ? doc.results.flatMap(x =>
        x.matches.map(m => ({
          rule: m.type,
          file: x.file,
          line: m.line,
          severity: m.severity,
          source: m.source || '',
          fingerprint: m.fingerprint,
          content_fingerprint: m.content_fingerprint || '',
        })),
      )
    : [];
  findings.sort((a, b) => `${a.file}\0${a.line}\0${a.rule}`.localeCompare(`${b.file}\0${b.line}\0${b.rule}`));
  return {
    exit_code: last.status,
    wall_ms_median: Math.round(median(times)),
    wall_ms_runs: times.map(t => Math.round(t)),
    files_scanned: r.files_scanned,
    file_set: r.file_set,
    content_source: r.content_source,
    worktree_copies_scanned: r.worktree_copies_scanned,
    tracked_ignored_files_scanned: r.tracked_ignored_files_scanned,
    tracked_nested_vendored_scanned: r.tracked_nested_vendored_scanned,
    tracked_files_missing: r.tracked_files_missing,
    unscannable_files: r.unscannable_files,
    finding_count: findings.length,
    findings,
    parsed: doc !== null,
  };
}

const key = f => `${f.file}|${f.rule}|${f.line}|${f.severity}|${f.fingerprint}|${f.content_fingerprint}`;
const digest = list => crypto.createHash('sha256').update(list.map(key).sort().join('\n')).digest('hex');

/** The release-blocker comparison of adc39e5 with the branch for one mode. */
function compare(adc, branch, transformed) {
  const explained = f => TWO_LETTER.test(path.basename(f)) || transformed.has(f);
  const fpKey = f => `${f.file}|${f.rule}|${f.fingerprint}`;
  const branchKeys = new Set(branch.findings.map(fpKey));
  const adcKeys = new Set(adc.findings.map(fpKey));
  const lost = adc.findings.filter(f => !branchKeys.has(fpKey(f)) && !explained(f.file));
  // Per untransformed file, the multiset of (rule, positional, content)
  // fingerprints must be equal; two matches on one line are two entries.
  const perFile = list => {
    const m = new Map();
    for (const f of list) {
      const arr = m.get(f.file) || [];
      arr.push(`${f.rule}|${f.fingerprint}|${f.content_fingerprint}`);
      m.set(f.file, arr);
    }
    for (const arr of m.values()) arr.sort();
    return m;
  };
  const a = perFile(adc.findings);
  const b = perFile(branch.findings);
  const fpChanged = [...a.keys()]
    .filter(file => !explained(file) && b.has(file) && a.get(file).join('\n') !== b.get(file).join('\n'))
    .map(file => ({ file }));
  return {
    files_scanned_adc39e5: adc.files_scanned,
    files_scanned_branch: branch.files_scanned,
    fewer_files_scanned: (branch.files_scanned ?? 0) < (adc.files_scanned ?? 0),
    findings_lost_unexplained: lost.map(f => ({ rule: f.rule, file: f.file, line: f.line })),
    fingerprint_changes_untransformed: fpChanged,
    findings_only_in_branch: branch.findings
      .filter(f => !adcKeys.has(fpKey(f)))
      .map(f => ({ rule: f.rule, file: f.file, line: f.line, severity: f.severity })),
  };
}

/** Full findings for the branch build; a digest and the differences for the others. */
function compactMode(mode, plainBranchDigest) {
  const branch = mode.branch.findings;
  const branchKeys = new Set(branch.map(key));
  const out = {};
  for (const [build, r] of Object.entries(mode)) {
    const { findings, parsed, ...rest } = r;
    const c = { ...rest, findings_sha256: digest(findings) };
    if (!parsed) c.output_unparseable = true;
    if (build === 'branch') {
      if (plainBranchDigest !== undefined && c.findings_sha256 === plainBranchDigest) {
        c.same_findings_as_plain_scan = true;
      } else {
        c.findings = findings.map(f => [f.rule, f.file, f.line, f.severity, f.source, f.fingerprint, f.content_fingerprint]);
      }
    } else {
      const keys = new Set(findings.map(key));
      c.findings_not_in_branch = findings.filter(f => !branchKeys.has(key(f))).length;
      c.branch_findings_not_here = branch.filter(f => !keys.has(key(f))).length;
      c.same_findings_as_branch = c.findings_sha256 === digest(branch);
    }
    out[build] = c;
  }
  return out;
}

function main1100() {
const out = {
  design: 'docs/design/2026-10-12-blob-reads-baseline-symlinks-locale-basenames.md, section 8',
  generated_by: 'bench/real-repos/run.cjs',
  machine: {
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus().length,
    cpu: os.cpus()[0].model,
    node: process.version,
    git: git(benchDir, ['--version']).trim(),
  },
  runs_per_measurement: RUNS,
  builds: {
    '1.9.1': 'published @vaultcompass/vault-guard 1.9.1 from npm',
    adc39e5: 'main at adc39e5',
    branch: 'feat/audit-fix-forward-1b1',
  },
  finding_fields: ['rule', 'file', 'line', 'severity', 'source', 'fingerprint', 'content_fingerprint'],
  repositories: {},
};

for (const name of REPOS) {
  const repo = path.join(benchDir, name);
  const { head, base } = prepare(repo);
  const t = transforms(repo);
  const plain = {};
  const trustBase = {};
  for (const [build, cli] of Object.entries(BUILDS)) {
    plain[build] = run(cli, repo, []);
    trustBase[build] = run(cli, repo, ['--trust-base', base]);
  }
  const plainBranchDigest = digest(plain.branch.findings);
  out.repositories[name] = {
    clone_head: base,
    bench_branch_head: head,
    transform_attribute_counts: t.counts,
    release_blockers: {
      plain: compare(plain.adc39e5, plain.branch, t.files),
      trust_base: compare(trustBase.adc39e5, trustBase.branch, t.files),
    },
    plain: compactMode(plain),
    trust_base: compactMode(trustBase, plainBranchDigest),
  };
  process.stderr.write(`done ${name}\n`);
}

const react = out.repositories.react;
const ratio = react.plain.branch.wall_ms_median / react.plain.adc39e5.wall_ms_median;
const blockers = Object.values(out.repositories).flatMap(r => [r.release_blockers.plain, r.release_blockers.trust_base]);
out.release_blocker_summary = {
  file_scanned_by_adc39e5_not_by_branch: blockers.some(b => b.fewer_files_scanned),
  finding_lost_unexplained_by_transform: blockers.some(b => b.findings_lost_unexplained.length > 0),
  fingerprint_change_on_untransformed_file: blockers.some(b => b.fingerprint_changes_untransformed.length > 0),
  react_wall_time_ratio_branch_over_adc39e5: Math.round(ratio * 100) / 100,
  react_wall_time_over_1_5x: ratio > 1.5,
};

writeRecord(outJson, out);
process.stderr.write(`${JSON.stringify(out.release_blocker_summary, null, 2)}\n`);
}

/** One line per finding tuple, for a reviewable diff. */
function writeRecord(file, out) {
  const text = JSON.stringify(out, null, 2).replace(
    /\[\n\s+("[^"\n]*",?\n\s+|\d+,?\n\s+)+("[^"\n]*"|\d+)\n\s+\]/g,
    m => JSON.stringify(JSON.parse(m)),
  );
  fs.writeFileSync(file, `${text}\n`);
}

// ---------------------------------------------------------------------------
// 1.11.0 (design 2026-10-17, section 10)
// ---------------------------------------------------------------------------

const REPOS_1110 = {
  react: 'facebook/react',
  urllib3: 'urllib3/urllib3',
  gitleaks: 'gitleaks/gitleaks',
  'detect-secrets': 'Yelp/detect-secrets',
  'learning-area': 'mdn/learning-area',
  'font-awesome': 'FortAwesome/Font-Awesome',
  howler: 'goldfire/howler.js',
  explore: 'github/explore',
};
/** The four 1.10.0 repositories and github/explore carry the 1.15x wall-time gate. */
const WALL_GATED = ['react', 'urllib3', 'gitleaks', 'detect-secrets', 'explore'];
/** The media repositories get the load run. */
const LOAD_RUN = ['learning-area', 'font-awesome', 'howler'];
/** 1.10.0's lists, for the expected sets of section 10. */
const OLD_TYPE_FILTER = ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz'];
const OLD_BINARY = [...OLD_TYPE_FILTER, '.exe', '.dll', '.so', '.dylib', '.bin'];
const VENDORED = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo', '.yarn', 'vendor', '.venv', 'venv',
  '__pycache__', '.mypy_cache', '.pytest_cache', '.gradle', '.svelte-kit',
]);

/** Run one CLI once; `cwd` is outside the clone for a plain scan, the clone for --trust-base. */
function runOnce(cli, cwd, args, env = process.env) {
  const t0 = process.hrtime.bigint();
  const r = spawnSync(process.execPath, [cli, 'scan', ...args, '--format', 'json'], {
    cwd,
    encoding: 'utf-8',
    env: { ...env, NO_COLOR: '1' },
    maxBuffer: 1 << 30,
  });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  let doc = null;
  try {
    doc = JSON.parse(r.stdout);
  } catch {
    doc = null;
  }
  return { r, ms, doc };
}

function summarize(last, times) {
  const doc = last.doc;
  const r = doc ? doc.run || {} : {};
  const findings = doc
    ? doc.results.flatMap(x =>
        x.matches.map(m => ({
          rule: m.type,
          file: x.file,
          line: m.line,
          severity: m.severity,
          source: m.source || '',
          fingerprint: m.fingerprint,
          content_fingerprint: m.content_fingerprint || '',
        })),
      )
    : [];
  findings.sort((a, b) => `${a.file}\0${a.line}\0${a.rule}`.localeCompare(`${b.file}\0${b.line}\0${b.rule}`));
  const byKind = {};
  for (const u of r.unscannable || []) byKind[u.kind] = (byKind[u.kind] || 0) + 1;
  return {
    exit_code: last.r.status,
    wall_ms_median: Math.round(median(times)),
    wall_ms_runs: times.map(t => Math.round(t)),
    files_scanned: r.files_scanned,
    type_filtered_files: r.type_filtered_files,
    binary_files_skipped: r.binary_files_skipped,
    binary_files_skipped_by_family: r.binary_files_skipped_by_family,
    binary_worktree_copies_skipped: r.binary_worktree_copies_skipped,
    binary_type_mismatch_scanned: r.binary_type_mismatch_scanned,
    binary_type_mismatch: r.binary_type_mismatch,
    scan_budget_retimed: r.scan_budget_retimed,
    unscannable_by_kind: byKind,
    finding_count: findings.length,
    findings,
    parsed: doc !== null,
    first_stderr_line: (last.r.stderr || '').split('\n').find(l => l.trim().length > 0) || '',
  };
}

/** Three runs per build, the builds interleaved so machine load drifts over both alike. */
function runPair(builds, cwd, args, env) {
  const times = {};
  const last = {};
  for (let i = 0; i < RUNS; i++) {
    for (const [name, cli] of Object.entries(builds)) {
      const one = runOnce(cli, cwd, args, env);
      (times[name] = times[name] || []).push(one.ms);
      last[name] = one;
    }
  }
  const out = {};
  for (const name of Object.keys(builds)) out[name] = summarize(last[name], times[name]);
  return out;
}

/**
 * The per-extension census and the expected sets of section 10, from the
 * tracked files at the clone head and the branch's own classifier applied to
 * each file's first 4096 bytes (the clones are clean, so the disk copy is the
 * blob). Files under a vendored name at the root are left out, as both builds
 * skip them.
 */
function census(repo, core) {
  const files = git(repo, ['ls-files', '-z']).split('\0').filter(Boolean);
  const perExt = {};
  const sets = { M: [], T: [], I: [], B: [], X: [], new_media_mismatch: [] };
  for (const rel of files) {
    if (rel.includes('/') && VENDORED.has(rel.split('/')[0])) continue;
    const ext = path.extname(path.basename(rel));
    const lower = ext.toLowerCase();
    if (!core.BINARY_TYPES.has(lower)) continue;
    perExt[lower] = (perExt[lower] || 0) + 1;
    const abs = path.join(repo, rel);
    let head;
    try {
      const fd = fs.openSync(abs, 'r');
      try {
        const buf = Buffer.alloc(core.SNIFF_BYTES);
        const n = fs.readSync(fd, buf, 0, buf.length, 0);
        head = buf.subarray(0, n);
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      continue;
    }
    const agree = core.confirmsBinary(lower, head);
    const inT = OLD_TYPE_FILTER.includes(ext);
    const inB = !inT && OLD_BINARY.includes(lower);
    if (inT) sets.T.push(rel);
    if (inT && agree) sets.I.push(rel);
    if (inB) sets.B.push(rel);
    if ((inT || inB) && !agree) sets.X.push(rel);
    if (!inT && !inB && agree) sets.M.push(rel);
    if (!inT && !inB && !agree) sets.new_media_mismatch.push(rel);
  }
  return { tracked_files: files.length, per_extension: perExt, sets };
}

/** The section 10 expectations and release blockers for one mode. */
function check1110(old, branch, sets, prefix) {
  const p = f => `${prefix}${f}`;
  const inSet = list => new Set(list.map(p));
  const M = inSet(sets.M);
  const I = inSet(sets.I);
  const X = inSet(sets.X);
  const BX = sets.B.filter(f => sets.X.includes(f)).length;
  const key = f => `${f.file}|${f.rule}|${f.line}|${f.fingerprint}`;
  const oldKeys = new Set(old.findings.map(key));
  const branchKeys = new Set(branch.findings.map(key));
  const lost = old.findings.filter(f => !branchKeys.has(key(f)));
  const added = branch.findings.filter(f => !oldKeys.has(key(f)));
  const expected = {
    files_scanned: (old.files_scanned ?? 0) - sets.M.length + sets.X.length,
    binary_files_skipped: (old.binary_files_skipped ?? 0) + sets.M.length + sets.I.length - BX,
    type_filtered_files: (old.type_filtered_files ?? 0) - sets.T.length,
    binary_type_mismatch_scanned: sets.X.length + sets.new_media_mismatch.length,
  };
  const actual = {
    files_scanned: branch.files_scanned,
    binary_files_skipped: branch.binary_files_skipped,
    type_filtered_files: branch.type_filtered_files,
    binary_type_mismatch_scanned: branch.binary_type_mismatch_scanned,
  };
  return {
    expected,
    actual,
    counts_as_expected: Object.keys(expected).every(k => expected[k] === actual[k]),
    findings_lost: lost.map(f => ({ rule: f.rule, file: f.file, line: f.line, in_M_or_I: M.has(f.file) || I.has(f.file) })),
    findings_added: added.map(f => ({ rule: f.rule, file: f.file, line: f.line, in_X: X.has(f.file) })),
    blocker_lost_finding_outside_M_and_I: lost.some(f => !M.has(f.file) && !I.has(f.file)),
    blocker_new_finding_outside_X: added.some(f => !X.has(f.file)),
    blocker_fewer_files_scanned_outside_M:
      (branch.files_scanned ?? 0) < (old.files_scanned ?? 0) - sets.M.length,
  };
}

/** Body bytes piped through cat-file for head reads: a programmatic plain scan with the branch build. */
async function headReadBytes(cliBranchPath, repo) {
  const distDir = path.dirname(cliBranchPath);
  const utils = require(path.join(distDir, 'utils', 'scan-utils.js'));
  const core = require(require.resolve('@vaultcompass/vault-guard-core', { paths: [distDir] }));
  const content = utils.newContentReport();
  await utils.scanFilesAsync([repo], new core.SecretScanner(), {
    skipBinary: true,
    content,
    plainFileSet: core.newPlainFileSetInfo(),
    unreadable: [],
    skips: utils.newRunSkipCounts(),
  });
  return content.headReadBytes;
}

const strip = r => {
  const { findings, parsed, ...rest } = r;
  return { ...rest, findings_sha256: digest(findings), ...(parsed ? {} : { output_unparseable: true }) };
};

async function main1110(args) {
  const [dir, outFile, cli1100, cliBr] = args;
  if (!cliBr) {
    process.stderr.write('usage: run.cjs --design-2026-10-17 <benchDir> <outJson> <cli-1.10.0> <cli-branch>\n');
    process.exit(2);
  }
  const distDir = path.dirname(cliBr);
  const core = require(require.resolve('@vaultcompass/vault-guard-core', { paths: [distDir] }));
  const builds = { '1.10.0': cli1100, branch: cliBr };
  const out = {
    design: 'docs/design/2026-10-17-media-skip-budget-retime-upgrade-note.md, section 10',
    generated_by: 'bench/real-repos/run.cjs --design-2026-10-17',
    machine: {
      platform: os.platform(),
      arch: os.arch(),
      cpus: os.cpus().length,
      cpu: os.cpus()[0].model,
      node: process.version,
      git: git(dir, ['--version']).trim(),
      load_average_at_start: os.loadavg().map(x => Math.round(x * 100) / 100),
    },
    runs_per_measurement: RUNS,
    builds: { '1.10.0': 'published @vaultcompass/vault-guard 1.10.0 from npm', branch: 'feat/media-skip-and-budget' },
    method_notes: [
      'Plain scans run from the bench directory with the clone passed as an absolute path; --trust-base runs from inside the clone, because pull-request mode refuses a target outside the repository its base ref lives in. No code from a clone is executed.',
      'The builds are interleaved run by run, so load drift falls on both alike.',
      'Expected sets (M, T, I, B, X) come from the branch classifier applied to the first 4096 bytes of each tracked file at the clone head.',
    ],
    finding_fields: ['rule', 'file', 'line', 'severity', 'source', 'fingerprint', 'content_fingerprint'],
    repositories: {},
  };
  for (const [name, slug] of Object.entries(REPOS_1110)) {
    const repo = path.join(dir, name);
    const { head, base } = prepare(repo);
    const c = census(repo, core);
    const plain = runPair(builds, dir, [repo]);
    const trust = runPair(builds, repo, ['.', '--trust-base', base]);
    const prefix = `${name}/`;
    const rec = {
      repository: slug,
      clone_head: base,
      bench_branch_head: head,
      tracked_files: c.tracked_files,
      per_extension_tracked: c.per_extension,
      expected_sets: Object.fromEntries(Object.entries(c.sets).map(([k, v]) => [k, v.length])),
      X_files: c.sets.X,
      new_media_mismatch_files: c.sets.new_media_mismatch,
      head_read_bytes: await headReadBytes(cliBr, repo),
      checks: {
        plain: check1110(plain['1.10.0'], plain.branch, c.sets, prefix),
        trust_base: check1110(trust['1.10.0'], trust.branch, c.sets, ''),
      },
      wall_time_ratio_plain: Math.round((plain.branch.wall_ms_median / plain['1.10.0'].wall_ms_median) * 100) / 100,
      plain: { '1.10.0': strip(plain['1.10.0']), branch: { ...strip(plain.branch), findings: plain.branch.findings.map(f => [f.rule, f.file, f.line, f.severity, f.source, f.fingerprint, f.content_fingerprint]) } },
      trust_base: { '1.10.0': strip(trust['1.10.0']), branch: { ...strip(trust.branch), findings: trust.branch.findings.map(f => [f.rule, f.file, f.line, f.severity, f.source, f.fingerprint, f.content_fingerprint]) } },
    };
    if (LOAD_RUN.includes(name)) rec.load_run = await loadRun(builds, dir, repo);
    out.repositories[name] = rec;
    process.stderr.write(`done ${name}\n`);
  }
  out.machine.load_average_at_end = os.loadavg().map(x => Math.round(x * 100) / 100);
  const repos = Object.entries(out.repositories);
  const allChecks = repos.flatMap(([, r]) => [r.checks.plain, r.checks.trust_base]);
  out.release_blocker_summary = {
    lost_finding_outside_M_and_I: allChecks.some(c => c.blocker_lost_finding_outside_M_and_I),
    new_finding_outside_X: allChecks.some(c => c.blocker_new_finding_outside_X),
    file_scanned_by_1_10_0_not_by_branch_outside_M: allChecks.some(c => c.blocker_fewer_files_scanned_outside_M),
    counts_not_as_expected: repos.filter(([, r]) => !r.checks.plain.counts_as_expected || !r.checks.trust_base.counts_as_expected).map(([n]) => n),
    scan_budget_on_branch_in_load_run: repos.some(([, r]) => r.load_run && r.load_run.branch.scan_budget_entries > 0),
    wall_time_ratio_plain: Object.fromEntries(WALL_GATED.map(n => [n, out.repositories[n].wall_time_ratio_plain])),
    wall_time_over_1_15x: WALL_GATED.filter(n => out.repositories[n].wall_time_ratio_plain > 1.15),
  };
  writeRecord(outFile, out);
  process.stderr.write(`${JSON.stringify(out.release_blocker_summary, null, 2)}\n`);
}

/** The plain scan with twice as many busy processes as the machine has cores, three runs per build. */
async function loadRun(builds, dir, repo) {
  const busy = path.join(__dirname, 'busy.cjs');
  const procs = Array.from({ length: os.cpus().length * 2 }, () => spawn(process.execPath, [busy], { stdio: 'ignore' }));
  try {
    await new Promise(r => setTimeout(r, 1000));
    const res = runPair(builds, dir, [repo]);
    const out = {};
    for (const [b, r] of Object.entries(res)) {
      out[b] = {
        exit_code: r.exit_code,
        wall_ms_median: r.wall_ms_median,
        wall_ms_runs: r.wall_ms_runs,
        scan_budget_entries: r.unscannable_by_kind.scan_budget || 0,
        scan_budget_retimed: r.scan_budget_retimed,
        busy_processes: procs.length,
      };
    }
    return out;
  } finally {
    for (const p of procs) p.kill('SIGKILL');
  }
}

// ---------------------------------------------------------------------------
// 1.12.0 (design 2026-10-17 data files, section 9)
// ---------------------------------------------------------------------------

/** Section 9.1. `gated` repositories carry the 1.10x wall-time blocker. */
const REPOS_DATA = {
  react: { slug: 'facebook/react', gated: true, why: '1.10.0 and 1.11.0 runs, at the commit the 1.11.0 run used' },
  urllib3: { slug: 'urllib3/urllib3', gated: true, why: '1.10.0 and 1.11.0 runs, at the commit the 1.11.0 run used' },
  gitleaks: { slug: 'gitleaks/gitleaks', gated: true, why: '1.10.0 and 1.11.0 runs, at the commit the 1.11.0 run used' },
  'detect-secrets': { slug: 'Yelp/detect-secrets', gated: true, why: '1.10.0 and 1.11.0 runs, at the commit the 1.11.0 run used' },
  pdsh: { slug: 'jakevdp/PythonDataScienceHandbook', why: 'notebooks with image/png outputs and no data: prefix (bare runs)' },
  fastbook: {
    slug: 'fastai/fastbook',
    why: 'a second notebook corpus of the same kind; its bare-run R_media at the clone head is under 10 MB, so by the section 9.1 fallback rule handson-ml replaces it as the second corpus, and it stays in the record',
  },
  'handson-ml': {
    slug: 'ageron/handson-ml',
    why: 'the fallback for fastbook: a notebook corpus with committed image/png outputs',
    search: 'gh search code "iVBORw0KGgo" --extension ipynb --owner ageron --limit 10 (2026-10-17). A --size filter returns nothing, because code search does not index files that large',
  },
  'fivethirtyeight-data': { slug: 'fivethirtyeight/data', gated: true, why: 'hundreds of CSV files in varied dialects' },
  buyingtickets: {
    slug: 'jcarloshg/BuyingTickets-DistributedRateLimiter',
    why: 'chosen by search: login-results.csv, a load-test results table whose last column is a JWT per row (the scraped-CSV shape)',
    search: 'gh search code "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" --extension csv --size ">20000" --limit 30 (2026-10-17); hit: login-results.csv, 47221 bytes. Searched again because the first hit, sunbird-perf-tests, holds only two-line token CSVs',
  },
  'sunbird-perf-tests': {
    slug: 'Sunbird-Ed/sunbird-perf-tests',
    why: 'chosen by search for committed CSV files holding JWT-shaped values; its token CSVs turned out to be two lines each (a header and one row), under the 20-line threshold, so it does not have the grouping shape and is kept as a negative case',
    search: 'gh search code "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" --extension csv --limit 30 (2026-10-17); hits include sunbird-platform/tnc-accept/userToken.csv and four more userToken or userData CSVs in this repository',
  },
  tinyspy: {
    slug: 'tinylibs/tinyspy',
    why: 'chosen by search: an SVG carrying a data:image/png payload of 100 KB or more',
    search: 'gh search code "data:image/png;base64,iVBORw0KGgo" --extension svg --size ">100000" --limit 30 (2026-10-17); hit: banner.svg',
  },
};
const MEDIUM = 2;
const RANK = { low: 1, medium: 2, high: 3, critical: 4 };

/** The branch's own data-shape module and core, from its dist tree. */
function branchModules(cliBr) {
  const coreIndex = require.resolve('@vaultcompass/vault-guard-core', { paths: [path.dirname(cliBr)] });
  return {
    core: require(coreIndex),
    ds: require(path.join(path.dirname(coreIndex), 'utils', 'data-shape.js')),
  };
}

/**
 * Section 9.1's per-repository counts, from the tracked files at the clone
 * head: files dataShape calls delimited or long-line, and the characters of
 * runs of 1024 or more that decode to binary media (R_media), by reason and
 * alphabet. Files the scanner skips as binary, or over 32 MiB, are left out.
 */
function dataCensus(repo, mods) {
  const { core, ds } = mods;
  const files = git(repo, ['ls-files', '-z']).split('\0').filter(Boolean);
  const out = {
    tracked_files: files.length,
    text_files_examined: 0,
    delimited_files: 0,
    delimited_by_delimiter: { ',': 0, '\t': 0, ';': 0, '|': 0 },
    long_line_files: 0,
    r_media_chars: {
      'data-uri-binary-payload': { standard: 0, url_safe: 0 },
      'base64-binary-run': { standard: 0, url_safe: 0 },
    },
    r_media_by_format: {},
    runs_1024_or_more: 0,
    media_runs: 0,
    shape_ms: 0,
  };
  const shaped = new Set();
  for (const rel of files) {
    if (rel.includes('/') && VENDORED.has(rel.split('/')[0])) continue;
    const abs = path.join(repo, rel);
    let buf;
    try {
      const st = fs.lstatSync(abs);
      if (!st.isFile() || st.size > 32 * 1024 * 1024) continue;
      buf = fs.readFileSync(abs);
    } catch {
      continue;
    }
    const cand = core.binaryCandidate(rel);
    if (cand && core.confirmsBinary(cand.ext, buf.subarray(0, core.SNIFF_BYTES))) continue;
    const text = core.decodeTextBuffer(buf);
    out.text_files_examined++;
    const t0 = process.hrtime.bigint();
    const shape = ds.dataShape(text);
    out.shape_ms += Number(process.hrtime.bigint() - t0) / 1e6;
    if (shape.delimited) {
      out.delimited_files++;
      out.delimited_by_delimiter[shape.delimited.delimiter]++;
      shaped.add(rel);
    }
    if (shape.longLines.size > 0) {
      out.long_line_files++;
      shaped.add(rel);
    }
    const runs = ds.internals.sweepRuns(text);
    out.runs_1024_or_more += runs.length;
    const idx = new ds.RunIndex(text);
    for (const run of runs) {
      const v = idx.verdict(run);
      if (!v) continue;
      out.media_runs++;
      const slice = text.slice(run.start, run.end);
      const alphabet = /[-_]/.test(slice) ? 'url_safe' : 'standard';
      out.r_media_chars[v.reason][alphabet] += run.end - run.start;
      out.r_media_by_format[v.format] = (out.r_media_by_format[v.format] || 0) + (run.end - run.start);
    }
  }
  out.shape_ms = Math.round(out.shape_ms);
  const r = out.r_media_chars;
  const std = r['data-uri-binary-payload'].standard + r['base64-binary-run'].standard;
  const url = r['data-uri-binary-payload'].url_safe + r['base64-binary-run'].url_safe;
  // Section 1.2: a gcp-api-key window matches random standard base64 with
  // probability 64^-4 * (62/64)^35; URL-safe base64 has no character outside
  // the rule's class, so 64^-4 there.
  const e = 1.96e-8 * std + 5.96e-8 * url;
  out.expected_gcp_coincidences = Number(e.toFixed(4));
  out.r_media_bare_mb = Number(((r['base64-binary-run'].standard + r['base64-binary-run'].url_safe) / 1e6).toFixed(2));
  return { census: out, shaped };
}

/** Every finding of one run, with the fields section 9.2 records (never the value). */
function summarizeData(last, times) {
  const doc = last.doc;
  const r = doc ? doc.run || {} : {};
  const findings = [];
  const groups = [];
  for (const x of doc ? doc.results : []) {
    for (const g of x.groups || []) groups.push({ file: x.file, ...g });
    for (const m of x.matches) {
      const len = /\((\d+)c\)$/.exec(m.value || '');
      findings.push({
        rule: m.type,
        file: x.file,
        line: m.line,
        offset: m.offset,
        length: len ? Number(len[1]) : 0,
        severity: m.severity,
        source: m.source || '',
        fingerprint: m.fingerprint,
        content_fingerprint: m.content_fingerprint || '',
        ...(m.demotion ? { demotion: m.demotion } : {}),
        ...(m.group_id ? { group_id: m.group_id } : {}),
      });
    }
  }
  findings.sort((a, b) => `${a.file}\0${a.offset}\0${a.rule}`.localeCompare(`${b.file}\0${b.offset}\0${b.rule}`));
  return {
    exit_code: last.r.status,
    wall_ms_median: Math.round(median(times)),
    wall_ms_runs: times.map(t => Math.round(t)),
    files_scanned: r.files_scanned,
    fail_on: r.fail_on,
    blocking_matches: r.blocking_matches,
    secrets: doc ? doc.summary.secrets : undefined,
    demoted_matches: r.demoted_matches,
    demoted_by_reason: r.demoted_by_reason,
    match_groups: r.match_groups,
    grouped_matches: r.grouped_matches,
    unscannable_files: r.unscannable_files,
    findings,
    groups,
    parsed: doc !== null,
    first_stderr_line: (last.r.stderr || '').split('\n').find(l => l.trim().length > 0) || '',
  };
}

function runPairData(builds, cwd, args) {
  const times = {};
  const last = {};
  for (let i = 0; i < RUNS; i++) {
    for (const [name, cli] of Object.entries(builds)) {
      const one = runOnce(cli, cwd, args);
      (times[name] = times[name] || []).push(one.ms);
      last[name] = one;
    }
  }
  const out = {};
  for (const name of Object.keys(builds)) out[name] = summarizeData(last[name], times[name]);
  return out;
}

/**
 * The section 9.3 formulas for one mode. F11 and F12 are keyed by (rule,
 * file, line, offset, source, fingerprint, content fingerprint); `stage` is
 * not in the JSON output, and clean clones have no conflicts.
 */
function checkData(old, br, shaped, prefix) {
  const k = f => [f.rule, f.file, f.line, f.offset, f.source, f.fingerprint, f.content_fingerprint].join('|');
  const pool = new Map();
  for (const f of old.findings) {
    const list = pool.get(k(f)) || [];
    list.push(f);
    pool.set(k(f), list);
  }
  const paired = [];
  const added = [];
  for (const f of br.findings) {
    const list = pool.get(k(f));
    if (list && list.length > 0) paired.push([list.shift(), f]);
    else added.push(f);
  }
  const lost = [...pool.values()].flat();
  // Rst: a branch-only match overlapping a demoted branch match in the same file, itself not demoted.
  const demotedBr = br.findings.filter(f => f.demotion);
  const restored = [];
  const unexplainedAdded = [];
  for (const f of added) {
    const by = demotedBr.find(d => d.file === f.file && d.offset < f.offset + f.length && f.offset < d.offset + d.length);
    if (by && !f.demotion) restored.push({ rule: f.rule, file: f.file, line: f.line, offset: f.offset, displaced_by: { rule: by.rule, offset: by.offset } });
    else unexplainedAdded.push({ rule: f.rule, file: f.file, line: f.line, offset: f.offset, severity: f.severity });
  }
  // Swp: the same rule, value and position reported from another copy.
  const swaps = [];
  const lostLeft = [];
  for (const f of lost) {
    const s = unexplainedAdded.findIndex(a => a.rule === f.rule && a.file === f.file && a.offset === f.offset);
    if (s >= 0) swaps.push({ rule: f.rule, file: f.file, offset: f.offset, removed: unexplainedAdded.splice(s, 1)[0] });
    else lostLeft.push({ rule: f.rule, file: f.file, line: f.line, offset: f.offset, severity: f.severity });
  }
  const severityOutsideD = [];
  const badD = [];
  let dBlockingAtMedium = 0;
  for (const [o, n] of paired) {
    if (n.demotion) {
      const ok = n.severity === 'low' && o.severity !== 'low' && n.demotion.from === o.severity;
      if (!ok) badD.push({ rule: n.rule, file: n.file, offset: n.offset, sev11: o.severity, sev12: n.severity, from: n.demotion.from });
      if (RANK[o.severity] >= MEDIUM) dBlockingAtMedium++;
    } else if (o.severity !== n.severity) {
      severityOutsideD.push({ rule: n.rule, file: n.file, offset: n.offset, sev11: o.severity, sev12: n.severity });
    }
  }
  const dCount = br.findings.filter(f => f.demotion).length;
  const byReasonSum = br.demoted_by_reason ? Object.values(br.demoted_by_reason).reduce((a, b) => a + b, 0) : null;
  const badGroups = br.groups.filter(g => g.members < 5 || !shaped.has(g.file.startsWith(prefix) ? g.file.slice(prefix.length) : g.file));
  const defaultGate = old.fail_on === 'medium' && br.fail_on === 'medium';
  return {
    findings_lost: lostLeft,
    findings_added_unexplained: unexplainedAdded,
    restored_log: restored,
    swap_log: swaps,
    severity_changes_outside_D: severityOutsideD,
    D: dCount,
    D_by_rule: br.findings.filter(f => f.demotion).reduce((a, f) => ({ ...a, [f.rule]: (a[f.rule] || 0) + 1 }), {}),
    D_entries_not_as_expected: badD,
    blocking_expected: defaultGate ? (old.blocking_matches ?? 0) - dBlockingAtMedium : null,
    blocking_actual: br.blocking_matches,
    blocking_as_expected: defaultGate ? (old.blocking_matches ?? 0) - dBlockingAtMedium === br.blocking_matches : null,
    files_scanned_equal: old.files_scanned === br.files_scanned,
    secrets_as_expected: (old.secrets ?? 0) + restored.length === br.secrets,
    demoted_matches_equals_D: br.demoted_matches === dCount && byReasonSum === dCount,
    grouped_within_secrets: (br.grouped_matches ?? 0) <= (br.secrets ?? 0),
    groups_not_as_expected: badGroups.map(g => ({ file: g.file, rule: g.rule, members: g.members, basis: g.basis })),
  };
}

/** The two planted cases of section 9.4, built at run time in their own repositories. */
function plantedCases(dir, builds) {
  const key = ['AI', 'za'].join('') + 'Qm7Rk2Vx9Lp4Tz8Wn3Hb6Jd1Fc5Gs0Ye2Ua';
  const enc = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jwt = i => [enc({ alg: 'HS256', typ: 'JWT' }), enc({ sub: `planted-${i}` }), crypto.createHash('sha256').update(`s${i}`).digest('base64url')].join('.');
  const tok = (r, c) => crypto.createHash('sha256').update(`t${r}:${c}`).digest('base64').slice(0, 40);
  const rows = ['c0,c1,c2,c3,c4,c5,c6,c7'];
  for (let r = 0; r < 1000; r++) {
    rows.push(Array.from({ length: 8 }, (_, c) => (c === 6 ? jwt(r) : r === 501 && c === 2 ? key : tok(r, c))).join(','));
  }
  const p1 = rows.join('\n') + '\n';
  const p2a = `<a href="data:text/html,<script>var k='${key}'</script>">x</a>\n`;
  const json = Buffer.from(JSON.stringify({ items: Array.from({ length: 80 }, (_, i) => ({ id: i, name: `item ${i}` })) })).toString('base64').replace(/=/g, '');
  const p2b = `<script src="data:application/json;base64,${json.slice(0, 1200)}${key}${json.slice(1200, 2400)}"></script>\n`;
  const files = { 'data/p1.csv': p1, 'p2a.html': p2a, 'p2b.html': p2b };
  const results = {};
  for (const mode of ['plain', 'trust-base', 'staged']) {
    const repo = path.join(dir, `planted-${mode}`);
    fs.rmSync(repo, { recursive: true, force: true });
    fs.mkdirSync(path.join(repo, 'src'), { recursive: true });
    git(repo, ['init', '-q', '-b', 'main']);
    fs.writeFileSync(path.join(repo, 'src', 'ok.ts'), 'export const ok = 1;\n');
    git(repo, ['add', '-A']);
    git(repo, ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'base']);
    const base = git(repo, ['rev-parse', 'HEAD']).trim();
    for (const [rel, body] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(repo, rel)), { recursive: true });
      fs.writeFileSync(path.join(repo, rel), body);
    }
    git(repo, ['add', '-A']);
    if (mode !== 'staged') git(repo, ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'head']);
    const args = mode === 'plain' ? ['.'] : mode === 'trust-base' ? ['.', '--trust-base', base] : ['--staged'];
    results[mode] = {};
    for (const [name, cli] of Object.entries(builds)) {
      const one = runOnce(cli, repo, args);
      const doc = one.doc;
      const gcp = doc ? doc.results.flatMap(x => x.matches.filter(m => m.type === 'gcp-api-key').map(m => ({ file: x.file, ...m }))) : [];
      const at = f => gcp.filter(m => m.file === f).map(m => ({ severity: m.severity, demoted: Boolean(m.demotion), grouped: Boolean(m.group_id) }));
      const jwtGroups = doc ? doc.results.filter(x => x.file === 'data/p1.csv').flatMap(x => (x.groups || []).filter(g => g.rule === 'jwt-token')) : [];
      results[mode][name] = {
        exit_code: one.r.status,
        P1: at('data/p1.csv'),
        P2a: at('p2a.html'),
        P2b: at('p2b.html'),
        P1_jwt_groups: jwtGroups.map(g => g.members),
      };
    }
  }
  const ok = r => ['P1', 'P2a', 'P2b'].every(p => r[p].length === 1 && r[p][0].severity === 'critical' && !r[p][0].demoted && !r[p][0].grouped);
  return {
    results,
    branch_all_full_severity: Object.values(results).every(m => ok(m.branch)),
    mcp_scan_workspace: 'covered by packages/mcp/src/__tests__/data-file-false-positives.test.ts, "the planted cases"',
  };
}

/** For the record: findings of the branch, as tuples, never the value. */
const tuple = f => [f.rule, f.file, f.line, f.offset, f.severity, f.source, f.fingerprint, f.content_fingerprint, f.demotion || null, f.group_id || null];

/** Up to this many findings per repository are recorded in full. */
const FULL_FINDINGS = 1000;

/**
 * Every finding as a tuple when there are at most FULL_FINDINGS; otherwise
 * per file, rule and severity counts (the digest beside them covers the full
 * list), and every demoted or grouped finding in full either way.
 */
function compactFindings(findings) {
  if (findings.length <= FULL_FINDINGS) return { findings: findings.map(tuple) };
  const counts = {};
  for (const f of findings) {
    const k = `${f.file} ${f.rule} ${f.severity}`;
    counts[k] = (counts[k] || 0) + 1;
  }
  return {
    findings_by_file_rule_severity: counts,
    findings_demoted_or_grouped: findings.filter(f => f.demotion || f.group_id).map(tuple),
  };
}

async function mainData(args) {
  const [dir, outFile, cli1110, cliBr] = args;
  if (!cliBr) {
    process.stderr.write('usage: run.cjs --design-2026-10-17-data-files <benchDir> <outJson> <cli-1.11.0> <cli-branch>\n');
    process.exit(2);
  }
  const mods = branchModules(cliBr);
  const builds = { '1.11.0': cli1110, branch: cliBr };
  const out = {
    design: 'docs/design/2026-10-17-data-file-false-positives.md, section 9',
    generated_by: 'bench/real-repos/run.cjs --design-2026-10-17-data-files',
    machine: {
      platform: os.platform(),
      arch: os.arch(),
      cpus: os.cpus().length,
      cpu: os.cpus()[0].model,
      node: process.version,
      git: git(dir, ['--version']).trim(),
      load_average_at_start: os.loadavg().map(x => Math.round(x * 100) / 100),
    },
    runs_per_measurement: RUNS,
    builds: { '1.11.0': 'published @vaultcompass/vault-guard 1.11.0 from npm', branch: 'feat/data-file-false-positives' },
    method_notes: [
      'Clones are depth 1 with no origin remote. The four 1.10.0 repositories are fetched at the commits the 1.11.0 run used; the others at their default-branch head on the day of the run.',
      'Plain scans run from the bench directory with the clone passed as an absolute path; --trust-base runs from inside the clone, as in the 1.11.0 run. No code from a clone is executed.',
      'The builds are interleaved run by run, three runs each, median wall time.',
      'The census applies the branch data-shape module to every tracked text file at the clone head (the clones are clean, so the disk copy is the blob).',
      'F11 and F12 are keyed by rule, file, line, offset, source and both fingerprints; stage is not in the JSON output and the clones have no conflicts.',
    ],
    finding_fields: ['rule', 'file', 'line', 'offset', 'severity', 'source', 'fingerprint', 'content_fingerprint', 'demotion', 'group_id'],
    repositories: {},
  };
  for (const [name, meta] of Object.entries(REPOS_DATA)) {
    const repo = path.join(dir, name);
    if (!fs.existsSync(path.join(repo, 'vg-bench-marker.txt')) && !fs.existsSync(path.join(repo, '.git', 'refs', 'heads', 'vg-bench'))) {
      fs.writeFileSync(path.join(repo, 'vg-bench-marker.txt'), 'benchmark marker\n');
    }
    const { head, base } = prepare(repo);
    const { census, shaped } = dataCensus(repo, mods);
    const plain = runPairData(builds, dir, [repo]);
    const trust = runPairData(builds, repo, ['.', '--trust-base', base]);
    const rec = {
      repository: meta.slug,
      why: meta.why,
      ...(meta.search ? { search: meta.search } : {}),
      clone_head: base,
      bench_branch_head: head,
      census,
      checks: {
        plain: checkData(plain['1.11.0'], plain.branch, shaped, `${name}/`),
        trust_base: checkData(trust['1.11.0'], trust.branch, shaped, ''),
      },
      D_gcp_plain: plain.branch.findings.filter(f => f.demotion && f.rule === 'gcp-api-key').length,
      wall_time_ratio_plain: Math.round((plain.branch.wall_ms_median / plain['1.11.0'].wall_ms_median) * 100) / 100,
      plain: {
        '1.11.0': { ...strip(plain['1.11.0']), groups: undefined },
        branch: { ...strip(plain.branch), groups: plain.branch.groups, ...compactFindings(plain.branch.findings) },
      },
      trust_base: {
        '1.11.0': { ...strip(trust['1.11.0']), groups: undefined },
        branch: { ...strip(trust.branch), groups: trust.branch.groups.length, findings_sha256: digest(trust.branch.findings) },
      },
    };
    const e = census.expected_gcp_coincidences;
    rec.gcp_coincidence_check = {
      expected: e,
      demoted_gcp: rec.D_gcp_plain,
      investigate: rec.D_gcp_plain > e + 3 * Math.sqrt(e) + 3,
    };
    out.repositories[name] = rec;
    process.stderr.write(`done ${name}\n`);
  }
  out.planted = plantedCases(dir, builds);
  out.machine.load_average_at_end = os.loadavg().map(x => Math.round(x * 100) / 100);
  const repos = Object.entries(out.repositories);
  const checks = repos.flatMap(([, r]) => [r.checks.plain, r.checks.trust_base]);
  out.release_blocker_summary = {
    finding_added_or_lost: checks.some(c => c.findings_lost.length > 0 || c.findings_added_unexplained.length > 0),
    severity_change_outside_D: checks.some(c => c.severity_changes_outside_D.length > 0),
    D_entry_not_as_expected: checks.some(c => c.D_entries_not_as_expected.length > 0),
    blocking_not_as_expected: checks.some(c => c.blocking_as_expected === false),
    counts_not_as_expected: repos
      .filter(([, r]) => [r.checks.plain, r.checks.trust_base].some(c => !c.files_scanned_equal || !c.secrets_as_expected || !c.demoted_matches_equals_D || !c.grouped_within_secrets || c.groups_not_as_expected.length > 0))
      .map(([n]) => n),
    gcp_demotions_to_investigate: repos.filter(([, r]) => r.gcp_coincidence_check.investigate).map(([n]) => n),
    planted_cases_full_severity_on_branch: out.planted.branch_all_full_severity,
    wall_time_ratio_plain: Object.fromEntries(repos.filter(([n]) => REPOS_DATA[n].gated).map(([n, r]) => [n, r.wall_time_ratio_plain])),
    wall_time_over_1_10x: repos.filter(([n, r]) => REPOS_DATA[n].gated && r.wall_time_ratio_plain > 1.1).map(([n]) => n),
    hand_checked: 'demotion_explanations and group_explanations are added after reading the files; see README.md',
  };
  writeRecord(outFile, out);
  process.stderr.write(`${JSON.stringify(out.release_blocker_summary, null, 2)}\n`);
}

// ---------------------------------------------------------------------------
// Release drift (a release that is not meant to change detection)
// ---------------------------------------------------------------------------

/**
 * Every finding one build has and the other does not, keyed by rule, file,
 * line, offset, severity, source and both fingerprints, plus the run counts
 * that should not move. For a release whose design does not touch detection
 * the expected result is no difference at all, so nothing is "explained".
 */
function checkDrift(old, br) {
  const k = f => [f.rule, f.file, f.line, f.offset, f.severity, f.source, f.fingerprint, f.content_fingerprint].join('|');
  const pool = new Map();
  for (const f of old.findings) pool.set(k(f), (pool.get(k(f)) || 0) + 1);
  const added = [];
  for (const f of br.findings) {
    const n = pool.get(k(f)) || 0;
    if (n > 0) pool.set(k(f), n - 1);
    else added.push(tuple(f));
  }
  const lost = old.findings.filter(f => {
    const n = pool.get(k(f)) || 0;
    if (n > 0) {
      pool.set(k(f), n - 1);
      return true;
    }
    return false;
  }).map(tuple);
  return {
    findings_lost: lost,
    findings_added: added,
    exit_code_equal: old.exit_code === br.exit_code,
    files_scanned_equal: old.files_scanned === br.files_scanned,
    blocking_equal: old.blocking_matches === br.blocking_matches,
    demoted_equal: old.demoted_matches === br.demoted_matches,
    groups_equal: old.match_groups === br.match_groups,
    unscannable_equal: old.unscannable_files === br.unscannable_files,
  };
}

/**
 * `--release-drift <benchDir> <outJson> <old-label> <cli-old> <cli-branch> <name=owner/repo>...`
 *
 * Each named clone sits in benchDir under its name, prepared as for the other
 * modes (depth 1, no origin, the marker committed on vg-bench). Plain and
 * --trust-base, both builds interleaved, three runs each.
 */
async function mainDrift(args) {
  const [dir, outFile, oldLabel, cliOld, cliBr, ...named] = args;
  if (!cliBr || named.length === 0) {
    process.stderr.write('usage: run.cjs --release-drift <benchDir> <outJson> <old-label> <cli-old> <cli-branch> <name=owner/repo>...\n');
    process.exit(2);
  }
  const builds = { [oldLabel]: cliOld, branch: cliBr };
  const out = {
    generated_by: 'bench/real-repos/run.cjs --release-drift',
    machine: {
      platform: os.platform(),
      arch: os.arch(),
      cpus: os.cpus().length,
      cpu: os.cpus()[0].model,
      node: process.version,
      git: git(dir, ['--version']).trim(),
      load_average_at_start: os.loadavg().map(x => Math.round(x * 100) / 100),
    },
    runs_per_measurement: RUNS,
    // Labels only; the CLI paths are machine-specific and are not recorded. Fill in by hand.
    builds: { [oldLabel]: '', branch: '' },
    method_notes: [
      'Clones are depth 1 with no origin remote, each at the commit named as clone_head.',
      'Plain scans run from the bench directory with the clone passed as an absolute path; --trust-base runs from inside the clone against clone_head. No code from a clone is executed.',
      'The builds are interleaved run by run, three runs each, median wall time.',
      'Findings are compared keyed by rule, file, line, offset, severity, source and both fingerprints. No difference is explained away: a release that does not change detection should show none.',
    ],
    finding_fields: ['rule', 'file', 'line', 'offset', 'severity', 'source', 'fingerprint', 'content_fingerprint', 'demotion', 'group_id'],
    repositories: {},
  };
  for (const spec of named) {
    const [name, slug] = spec.split('=');
    const repo = path.join(dir, name);
    if (!fs.existsSync(path.join(repo, 'vg-bench-marker.txt'))) {
      fs.writeFileSync(path.join(repo, 'vg-bench-marker.txt'), 'benchmark marker\n');
    }
    const { head, base } = prepare(repo);
    const plain = runPairData(builds, dir, [repo]);
    const trust = runPairData(builds, repo, ['.', '--trust-base', base]);
    out.repositories[name] = {
      repository: slug,
      clone_head: base,
      bench_branch_head: head,
      checks: { plain: checkDrift(plain[oldLabel], plain.branch), trust_base: checkDrift(trust[oldLabel], trust.branch) },
      wall_time_ratio_plain: Math.round((plain.branch.wall_ms_median / plain[oldLabel].wall_ms_median) * 100) / 100,
      plain: {
        [oldLabel]: { ...strip(plain[oldLabel]), groups: plain[oldLabel].groups.length },
        branch: { ...strip(plain.branch), groups: plain.branch.groups.length, ...compactFindings(plain.branch.findings) },
      },
      trust_base: {
        [oldLabel]: { ...strip(trust[oldLabel]), groups: trust[oldLabel].groups.length },
        branch: { ...strip(trust.branch), groups: trust.branch.groups.length },
      },
    };
    process.stderr.write(`done ${name}\n`);
  }
  out.machine.load_average_at_end = os.loadavg().map(x => Math.round(x * 100) / 100);
  const checks = Object.values(out.repositories).flatMap(r => [r.checks.plain, r.checks.trust_base]);
  out.drift_summary = {
    any_finding_added_or_lost: checks.some(c => c.findings_lost.length > 0 || c.findings_added.length > 0),
    any_count_changed: checks.some(c => !c.exit_code_equal || !c.files_scanned_equal || !c.blocking_equal || !c.demoted_equal || !c.groups_equal || !c.unscannable_equal),
  };
  writeRecord(outFile, out);
  process.stderr.write(`${JSON.stringify(out.drift_summary, null, 2)}\n`);
}

if (DRIFT) {
  mainDrift(ARGS.slice(1)).catch(e => {
    process.stderr.write(`${e && e.stack ? e.stack : String(e)}\n`);
    process.exit(1);
  });
} else if (DESIGN_DATA) {
  mainData(ARGS.slice(1)).catch(e => {
    process.stderr.write(`${e && e.stack ? e.stack : String(e)}\n`);
    process.exit(1);
  });
} else if (DESIGN_1110) {
  main1110(ARGS.slice(1)).catch(e => {
    process.stderr.write(`${e && e.stack ? e.stack : String(e)}\n`);
    process.exit(1);
  });
} else {
  main1100();
}
