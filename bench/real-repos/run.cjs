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
 */
const { spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const [benchDir, outJson, cli191, cliAdc, cliBranch] = process.argv.slice(2);
if (!cliBranch) {
  process.stderr.write('usage: run.cjs <benchDir> <outJson> <cli-1.9.1> <cli-adc39e5> <cli-branch>\n');
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

// One line per finding tuple, for a reviewable diff.
const text = JSON.stringify(out, null, 2).replace(
  /\[\n\s+("[^"\n]*",?\n\s+|\d+,?\n\s+)+("[^"\n]*"|\d+)\n\s+\]/g,
  m => JSON.stringify(JSON.parse(m)),
);
fs.writeFileSync(outJson, `${text}\n`);
process.stderr.write(`${JSON.stringify(out.release_blocker_summary, null, 2)}\n`);
