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
 */
const { spawn, spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ARGS = process.argv.slice(2);
const DESIGN_1110 = ARGS[0] === '--design-2026-10-17';
const [benchDir, outJson, cli191, cliAdc, cliBranch] = DESIGN_1110 ? [] : ARGS;
if (!DESIGN_1110 && !cliBranch) {
  process.stderr.write('usage: run.cjs <benchDir> <outJson> <cli-1.9.1> <cli-adc39e5> <cli-branch>\n');
  process.stderr.write('   or: run.cjs --design-2026-10-17 <benchDir> <outJson> <cli-1.10.0> <cli-branch>\n');
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

if (DESIGN_1110) {
  main1110(ARGS.slice(1)).catch(e => {
    process.stderr.write(`${e && e.stack ? e.stack : String(e)}\n`);
    process.exit(1);
  });
} else {
  main1100();
}
