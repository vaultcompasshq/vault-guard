/**
 * The HEAD tree of a repository whose object store is not trusted
 * (`scan --no-repo-controls`), read from raw git objects that are each hashed
 * against the id they were asked for.
 *
 * The commit is read and hashed, its `tree` line names the root tree, and the
 * file list is derived by parsing the verified raw tree bytes here. `git
 * ls-tree` is not run at all. Trees are read one level per `cat-file --batch`
 * call, and only ids named by already-verified bytes are followed; each new
 * tree is parsed once, in the round it arrives. The cost is one call per
 * directory level (a few for a real repository), which the depth limit bounds
 * at 1000. The check is git's own hash (sha1 or sha256, by id length), so it
 * is as strong as that hash.
 */

import { spawnSync } from 'child_process';

import { gitObjectId, hashAlgorithmForOid } from './blob-reader';
import { fileSetGitEnv } from './git-env';
import { HEAD_TREE_LISTING_MAX_BYTES } from '../trust-base';

export interface VerifiedEntry {
  /** The mode as written in the tree, normalized to its octal value with at least six digits. */
  mode: string;
  /** `blob` is a regular file (any permission bits), `symlink` a link, `commit` a gitlink (submodule). */
  type: 'blob' | 'symlink' | 'commit';
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

/**
 * Limits on what a crafted store can make the listing do. Passing any of them
 * refuses the run (exit 2), never a truncated scan. The byte limit is the one
 * the old `ls-tree` listing had (`HEAD_TREE_LISTING_MAX_BYTES`, 512 MiB).
 */
/** Tree rows visited while walking, counting a shared tree once per parent that names it. */
export const MAX_TREE_ROWS_WALKED = 5_000_000;
/** Total bytes of the paths emitted. */
export const MAX_TREE_PATH_BYTES = HEAD_TREE_LISTING_MAX_BYTES;
/** Directory depth. */
export const MAX_TREE_DEPTH = 1000;
/** Raw bytes read from `cat-file --batch` in one call (commit and trees). */
const MAX_BUFFER = HEAD_TREE_LISTING_MAX_BYTES;
const REMEDY = 'Clone the repository fresh and assess the clone.';

function lie(what: string): ObjectStoreMismatch {
  return new ObjectStoreMismatch(
    `vault-guard: the object store does not hold what its ids claim: ${what}. ${REMEDY} Nothing was scanned.`,
  );
}

function tooLarge(what: string): ObjectStoreMismatch {
  return new ObjectStoreMismatch(
    `vault-guard: the HEAD tree is too large to list: ${what} (limits: ${MAX_TREE_ROWS_WALKED} tree rows walked, ` +
      `${MAX_TREE_PATH_BYTES} bytes of paths, depth ${MAX_TREE_DEPTH}). A tree that names the same subtree many times ` +
      'expands without bound. Nothing was scanned.',
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
  if ((r.error as NodeJS.ErrnoException | undefined)?.code === 'ENOBUFS') throw tooLarge(`the commit and trees are over ${MAX_BUFFER} bytes`);
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

type Row = { mode: string; kind: 'tree' | 'file' | 'symlink' | 'gitlink'; name: string; oid: string };

/**
 * Classify a tree entry's mode the way git does: as octal, by the file-type
 * bits (S_IFMT). A directory is a tree; a regular file is a file whatever its
 * permission bits (100664, 100600, 0100644 and so on); 120000 is a symlink;
 * 160000 is a gitlink. Any other mode, or text that is not octal, is refused:
 * nothing is skipped silently because of its mode.
 */
export function classifyMode(mode: string): Row['kind'] | null {
  if (!/^[0-7]{1,16}$/.test(mode)) return null;
  switch (Number.parseInt(mode, 8) & 0o170000) {
    case 0o040000:
      return 'tree';
    case 0o100000:
      return 'file';
    case 0o120000:
      return 'symlink';
    case 0o160000:
      return 'gitlink';
    default:
      return null;
  }
}

/** Parse one raw tree: `<mode> <name>\0<raw id>` repeated. */
function parseTree(bytes: Buffer, rawLen: number, treeId: string): Row[] {
  const rows: Row[] = [];
  let p = 0;
  while (p < bytes.length) {
    const sp = bytes.indexOf(0x20, p);
    const nul = sp === -1 ? -1 : bytes.indexOf(0, sp);
    if (sp === -1 || nul === -1 || bytes.length < nul + 1 + rawLen) throw lie(`tree ${treeId} is malformed`);
    const mode = bytes.toString('latin1', p, sp);
    const name = bytes.toString('utf-8', sp + 1, nul);
    const kind = classifyMode(mode);
    if (kind === null) {
      throw new ObjectStoreMismatch(
        `vault-guard: the HEAD tree has an entry with a mode this scan will not guess at: ${JSON.stringify(name)} ` +
          `has mode ${JSON.stringify(mode)} in tree ${treeId}, which is not a directory, a regular file, a symlink or a ` +
          'gitlink. Nothing was scanned.',
      );
    }
    rows.push({ mode, kind, name, oid: bytes.subarray(nul + 1, nul + 1 + rawLen).toString('hex') });
    p = nul + 1 + rawLen;
  }
  return rows;
}

/** `cat-file --batch-check` types for `oids`; an id git does not have is absent from the map. */
function objectTypes(cwd: string, oids: string[]): Map<string, string> {
  const out = new Map<string, string>();
  if (oids.length === 0) return out;
  const r = spawnSync('git', ['-c', 'core.quotePath=false', 'cat-file', '--batch-check'], {
    cwd,
    env: fileSetGitEnv(),
    input: oids.map(o => `${o}\n`).join(''),
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    maxBuffer: MAX_BUFFER,
  });
  if (r.error !== undefined || r.status !== 0) {
    throw new ObjectStoreMismatch(
      `vault-guard: could not check the type of the files in the HEAD tree (git cat-file --batch-check): ` +
        `${String(r.error ?? r.stderr).trim()}. Nothing was scanned.`,
    );
  }
  for (const line of r.stdout.split('\n')) {
    const parts = line.split(' ');
    if (parts.length === 3) out.set(parts[0], parts[1]);
  }
  return out;
}

/**
 * Every non-directory entry of the HEAD commit's tree, recursive, from
 * verified raw objects. Throws {@link ObjectStoreMismatch}.
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

  // Each tree id is read and parsed once, however many parents name it.
  const rowsById = new Map<string, Row[]>();
  const want = (ids: string[]): string[] => [...new Set(ids)].filter(i => !rowsById.has(i));
  let next = want([rootId]);
  // The read is bounded as well as the walk below. A round reads one level
  // of the tree, so a round past the depth limit is a tree deeper than the
  // limit; and the rows and bytes of the distinct trees read are counted, so
  // a store of very many or very large trees refuses here, before the walk.
  let rounds = 0;
  let rowsRead = 0;
  let bytesRead = 0;
  while (next.length > 0) {
    if (++rounds > MAX_TREE_DEPTH) throw tooLarge(`deeper than ${MAX_TREE_DEPTH} directories`);
    const named: string[] = [];
    for (const [oid, o] of readVerified(repoRoot, next, alg)) {
      if (o.type !== 'tree') throw lie(`${o.type} ${oid} is where a tree is named`);
      bytesRead += o.bytes.length;
      if (bytesRead > MAX_BUFFER) throw tooLarge(`the trees are over ${MAX_BUFFER} bytes`);
      const rows = parseTree(o.bytes, rawLen, oid);
      rowsRead += rows.length;
      if (rowsRead > MAX_TREE_ROWS_WALKED) throw tooLarge(`over ${MAX_TREE_ROWS_WALKED} tree rows`);
      rowsById.set(oid, rows);
      // Only ids named by verified tree bytes are followed.
      for (const row of rows) if (row.kind === 'tree') named.push(row.oid);
    }
    next = want(named);
  }
  if (!rowsById.has(rootId)) throw lie(`root tree ${rootId} was not read`);

  // Iterative, so a deeply nested tree cannot overflow the call stack, and
  // bounded: a tree shared by many parents is walked once per parent, which
  // is how a few small objects can name billions of paths.
  const out: VerifiedEntry[] = [];
  let walked = 0;
  let pathBytes = 0;
  const rowsOf = (id: string): Row[] => {
    const rows = rowsById.get(id);
    if (rows === undefined) throw lie(`tree ${id} was not read`);
    return rows;
  };
  const stack = [{ rows: rowsOf(rootId), i: 0, prefix: '' }];
  while (stack.length > 0) {
    const top = stack[stack.length - 1];
    if (top.i >= top.rows.length) {
      stack.pop();
      continue;
    }
    const row = top.rows[top.i++];
    if (++walked > MAX_TREE_ROWS_WALKED) throw tooLarge(`over ${MAX_TREE_ROWS_WALKED} tree rows`);
    const p = top.prefix + row.name;
    pathBytes += Buffer.byteLength(p);
    if (pathBytes > MAX_TREE_PATH_BYTES) throw tooLarge(`over ${MAX_TREE_PATH_BYTES} bytes of paths`);
    if (row.kind === 'tree') {
      if (stack.length >= MAX_TREE_DEPTH) throw tooLarge(`deeper than ${MAX_TREE_DEPTH} directories`);
      stack.push({ rows: rowsOf(row.oid), i: 0, prefix: `${p}/` });
    } else if (row.kind === 'gitlink') {
      out.push({ mode: '160000', type: 'commit', oid: row.oid, path: p });
    } else {
      out.push({ mode: row.mode, type: row.kind === 'symlink' ? 'symlink' : 'blob', oid: row.oid, path: p });
    }
  }

  // A file or symlink mode must name a blob. A tree where a file is claimed (or
  // the reverse, caught above where trees are read) is refused, not skipped.
  const types = objectTypes(repoRoot, [...new Set(out.filter(e => e.type !== 'commit').map(e => e.oid))]);
  for (const e of out) {
    if (e.type === 'commit') continue;
    const t = types.get(e.oid);
    if (t !== undefined && t !== 'blob') {
      throw new ObjectStoreMismatch(
        `vault-guard: the HEAD tree is inconsistent: ${JSON.stringify(e.path)} has mode ${e.mode}, which is a ` +
          `${e.type === 'symlink' ? 'symlink' : 'regular file'}, but its object ${e.oid} is a ${t}. Nothing was scanned.`,
      );
    }
  }
  return out;
}
