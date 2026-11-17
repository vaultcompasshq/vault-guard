/**
 * The HEAD tree of a repository whose object store is not trusted
 * (`scan --no-repo-controls`), read from raw git objects that are each hashed
 * against the id they were asked for.
 *
 * The commit is read and hashed, its `tree` line names the root tree, and the
 * file list is derived by parsing the verified raw tree bytes here, not from
 * `git ls-tree` output. `ls-tree -r -t -z HEAD` still runs, but only as a
 * hint: its tree ids seed the first batch read so a deep tree costs one
 * `cat-file --batch` call, not one per level. A tree it left out is read in a
 * further round, and a tree it invented is never used, because only ids named
 * by verified bytes are followed. The check is git's own hash (sha1 or
 * sha256, by id length), so it is as strong as that hash.
 */

import { spawnSync } from 'child_process';

import { gitObjectId, hashAlgorithmForOid } from './blob-reader';
import { fileSetGitEnv } from './git-env';

export interface VerifiedEntry {
  /** Six-digit octal as `ls-tree` prints it, `040000` for a tree. */
  mode: string;
  type: 'blob' | 'tree' | 'commit';
  oid: string;
  /** Root-relative, posix separators. */
  path: string;
}

/** A failure to read or verify the HEAD commit and its trees. */
export class ObjectStoreMismatch extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ObjectStoreMismatch';
  }
}

const MAX_BUFFER = 1024 * 1024 * 1024;
const REMEDY = 'Clone the repository fresh and assess the clone.';

function lie(what: string): ObjectStoreMismatch {
  return new ObjectStoreMismatch(
    `vault-guard: the object store does not hold what its ids claim: ${what}. ${REMEDY} Nothing was scanned.`,
  );
}

/** Raw `cat-file --batch` over `oids`: each verified against its id; type and bytes by id. */
function readVerified(
  cwd: string,
  oids: string[],
  alg: 'sha1' | 'sha256',
): Map<string, { type: string; bytes: Buffer }> {
  const out = new Map<string, { type: string; bytes: Buffer }>();
  if (oids.length === 0) return out;
  const r = spawnSync('git', ['-c', 'core.quotePath=false', 'cat-file', '--batch'], {
    cwd,
    env: fileSetGitEnv(),
    input: oids.map(o => `${o}\n`).join(''),
    stdio: ['pipe', 'pipe', 'pipe'],
    maxBuffer: MAX_BUFFER,
  });
  if (r.error !== undefined || r.status !== 0) {
    const stderr = Buffer.isBuffer(r.stderr) ? r.stderr.toString('utf-8').trim() : '';
    throw new ObjectStoreMismatch(
      `vault-guard: could not read the HEAD commit and trees (git cat-file --batch): ` +
        `${stderr.length > 0 ? stderr : String(r.error ?? `git exited with status ${String(r.status)}`)}. ` +
        'Nothing was scanned.',
    );
  }
  const buf = r.stdout;
  let pos = 0;
  for (const oid of oids) {
    const nl = buf.indexOf(0x0a, pos);
    if (nl === -1) throw lie(`git answered too few objects (at ${oid})`);
    const parts = buf.toString('utf-8', pos, nl).split(' ');
    if (parts.length !== 3 || parts[0] !== oid) {
      throw new ObjectStoreMismatch(
        `vault-guard: the object store has no usable object ${oid} (${parts.slice(1).join(' ')}). ` +
          `${REMEDY} Nothing was scanned.`,
      );
    }
    const size = Number.parseInt(parts[2], 10);
    const start = nl + 1;
    if (!Number.isFinite(size) || size < 0 || buf.length < start + size + 1) throw lie(`unreadable object ${oid}`);
    const bytes = buf.subarray(start, start + size);
    if (gitObjectId(alg, parts[1], bytes) !== oid) throw lie(`${parts[1]} ${oid} does not hash to its own id`);
    out.set(oid, { type: parts[1], bytes });
    pos = start + size + 1;
  }
  return out;
}

/** The tree ids `git ls-tree -r -t -z HEAD` names. A hint: any failure gives none. */
function treeIdHints(cwd: string): string[] {
  const r = spawnSync('git', ['-c', 'core.quotePath=false', 'ls-tree', '-r', '-t', '-z', 'HEAD'], {
    cwd,
    env: fileSetGitEnv(),
    stdio: ['ignore', 'pipe', 'ignore'],
    maxBuffer: 512 * 1024 * 1024,
  });
  if (r.error !== undefined || r.status !== 0) return [];
  const ids: string[] = [];
  for (const rec of r.stdout.toString('latin1').split('\0')) {
    const m = /^\d+ tree ([0-9a-f]+)\t/.exec(rec);
    if (m) ids.push(m[1]);
  }
  return ids;
}

const isTreeMode = (mode: string): boolean => mode === '40000' || mode === '040000';

/** Parse one raw tree: `<mode> <name>\0<raw id>` repeated. */
function parseTree(bytes: Buffer, rawLen: number, treeId: string): Array<{ mode: string; name: string; oid: string }> {
  const rows: Array<{ mode: string; name: string; oid: string }> = [];
  let p = 0;
  while (p < bytes.length) {
    const sp = bytes.indexOf(0x20, p);
    const nul = sp === -1 ? -1 : bytes.indexOf(0, sp);
    if (sp === -1 || nul === -1 || bytes.length < nul + 1 + rawLen) throw lie(`tree ${treeId} is malformed`);
    rows.push({
      mode: bytes.toString('latin1', p, sp),
      name: bytes.toString('utf-8', sp + 1, nul),
      oid: bytes.subarray(nul + 1, nul + 1 + rawLen).toString('hex'),
    });
    p = nul + 1 + rawLen;
  }
  return rows;
}

/**
 * Every non-tree entry of the HEAD commit's tree, recursive, from verified
 * raw objects. Throws {@link ObjectStoreMismatch}.
 */
export function readVerifiedHeadTree(repoRoot: string, headOid: string): VerifiedEntry[] {
  const alg = hashAlgorithmForOid(headOid);
  if (alg === null) throw lie(`HEAD ${headOid} is neither a sha1 nor a sha256 id`);
  const rawLen = alg === 'sha1' ? 20 : 32;
  const hexLen = rawLen * 2;

  const commit = readVerified(repoRoot, [headOid], alg).get(headOid);
  if (commit === undefined || commit.type !== 'commit') throw lie(`HEAD ${headOid} is not a commit`);
  const header = commit.bytes.toString('utf-8').split('\n')[0] ?? '';
  const m = /^tree ([0-9a-f]+)$/.exec(header);
  if (m === null || m[1].length !== hexLen) throw lie(`commit ${headOid} has no tree line`);
  const rootId = m[1];

  const trees = new Map<string, Buffer>();
  const want = (ids: string[]): string[] => [...new Set(ids)].filter(i => !trees.has(i));
  let next = want([rootId, ...treeIdHints(repoRoot).filter(i => i.length === hexLen)]);
  while (next.length > 0) {
    for (const [oid, o] of readVerified(repoRoot, next, alg)) {
      if (o.type !== 'tree') throw lie(`${o.type} ${oid} is where a tree is named`);
      trees.set(oid, o.bytes);
    }
    // Only ids named by verified tree bytes are followed.
    const named: string[] = [];
    for (const [oid, bytes] of trees) {
      for (const row of parseTree(bytes, rawLen, oid)) if (isTreeMode(row.mode)) named.push(row.oid);
    }
    next = want(named);
  }
  if (!trees.has(rootId)) throw lie(`root tree ${rootId} was not read`);

  // Iterative, so a deeply nested tree cannot overflow the call stack.
  const out: VerifiedEntry[] = [];
  const rowsOf = (id: string): ReturnType<typeof parseTree> => {
    if (!trees.has(id)) throw lie(`tree ${id} was not read`);
    return parseTree(trees.get(id) as Buffer, rawLen, id);
  };
  const stack = [{ rows: rowsOf(rootId), i: 0, prefix: '' }];
  while (stack.length > 0) {
    const top = stack[stack.length - 1];
    if (top.i >= top.rows.length) {
      stack.pop();
      continue;
    }
    const row = top.rows[top.i++];
    const p = top.prefix + row.name;
    if (isTreeMode(row.mode)) {
      stack.push({ rows: rowsOf(row.oid), i: 0, prefix: `${p}/` });
    } else if (row.mode === '160000') {
      out.push({ mode: '160000', type: 'commit', oid: row.oid, path: p });
    } else {
      out.push({ mode: row.mode.padStart(6, '0'), type: 'blob', oid: row.oid, path: p });
    }
  }
  return out;
}
