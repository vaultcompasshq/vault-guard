import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'child_process';

import { GitError } from '../errors';

/**
 * Reads git blobs by OBJECT ID ONLY, through at most two long-lived
 * `git cat-file` processes per repository (design 2026-10-12, section 2.3).
 *
 * A path never reaches git's revision grammar here: the caller hands over an
 * object id it took from a listing (`ls-files -s`, `ls-tree`, `diff --raw`),
 * so no attacker-controlled path text can steer which blob is read. That is
 * the property the staged path was moved off `git show :<path>` for.
 *
 * The environment the processes run with is a PARAMETER and is never chosen
 * here. Plain and pull-request runs pass a clean git environment; `--staged`
 * passes the inherited one on purpose, because a hook's `GIT_INDEX_FILE` or a
 * `GIT_DIR`-only repository is where its object ids came from.
 */

/** What `cat-file --batch-check` said about one object id. */
export type BlobCheck =
  | { kind: 'blob'; size: number }
  | { kind: 'missing' }
  | { kind: 'other'; type: string };

const BATCH_ARGS = ['-c', 'core.quotePath=false', 'cat-file'];

function readFailure(repoTop: string, detail: string, command: string, cause?: unknown): GitError {
  return new GitError(
    `vault-guard: could not read committed content for tracked files in ${repoTop}: ${detail}\n` +
      'Nothing was scanned. vault-guard does not fall back to the working-tree copy, because ' +
      'that copy is what a checkout transform can rewrite.',
    command,
    cause,
  );
}

/**
 * One `git cat-file --batch-check` over every object id given, deduplicated.
 * Throws {@link GitError} when the process cannot start, exits non-zero, or
 * answers in a shape that does not parse.
 */
export function batchCheckBlobs(
  repoTop: string,
  oids: Iterable<string>,
  env: NodeJS.ProcessEnv,
): Map<string, BlobCheck> {
  const unique = [...new Set(oids)];
  const out = new Map<string, BlobCheck>();
  if (unique.length === 0) return out;
  const argv = [...BATCH_ARGS, '--batch-check'];
  const r = spawnSync('git', argv, {
    cwd: repoTop,
    env,
    input: unique.map(o => `${o}\n`).join(''),
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    maxBuffer: 512 * 1024 * 1024,
  });
  const stderr = typeof r.stderr === 'string' ? r.stderr.trim() : '';
  if (r.error !== undefined || r.status !== 0) {
    throw readFailure(
      repoTop,
      stderr.length > 0 ? stderr : String(r.error ?? `git exited with status ${String(r.status)}`),
      `git ${argv.join(' ')}`,
      r.error,
    );
  }
  const lines = r.stdout.split('\n').filter(l => l.length > 0);
  if (lines.length !== unique.length) {
    throw readFailure(
      repoTop,
      `git cat-file --batch-check answered ${lines.length} lines for ${unique.length} object ids`,
      `git ${argv.join(' ')}`,
    );
  }
  for (let i = 0; i < unique.length; i++) {
    const parts = lines[i].split(' ');
    if (parts[0] !== unique[i]) {
      throw readFailure(
        repoTop,
        `git cat-file --batch-check answered out of order (expected ${unique[i]})`,
        `git ${argv.join(' ')}`,
      );
    }
    if (parts.length === 2 && parts[1] === 'missing') {
      out.set(unique[i], { kind: 'missing' });
      continue;
    }
    const size = Number.parseInt(parts[2] ?? '', 10);
    if (parts.length !== 3 || !Number.isFinite(size) || size < 0) {
      throw readFailure(repoTop, `unparseable cat-file answer: ${lines[i]}`, `git ${argv.join(' ')}`);
    }
    out.set(unique[i], parts[1] === 'blob' ? { kind: 'blob', size } : { kind: 'other', type: parts[1] });
  }
  return out;
}

interface Pending {
  oid: string;
  resolve: (b: Buffer) => void;
  reject: (e: Error) => void;
}

/**
 * A streaming `git cat-file --batch` for one repository.
 *
 * Requests are answered in order. At most `window` object ids are written
 * ahead of what has been consumed, so memory is bounded by the window times
 * the largest blob read. No `--buffer`: git flushes after each object, so a
 * windowed request is answered without waiting for stdin to close. Identical
 * object ids are read once and the bytes shared.
 */
export class BlobBatchReader {
  private proc: ChildProcessWithoutNullStreams | null = null;
  private readonly queue: Pending[] = [];
  private readonly inflight: Pending[] = [];
  private readonly chunks: Buffer[] = [];
  private buffered = 0;
  /** Size of the body being read, or -1 while waiting for a header. */
  private bodySize = -1;
  private stderr = '';
  private failed: GitError | null = null;
  private readonly shared = new Map<string, Promise<Buffer>>();
  private readonly argv = [...BATCH_ARGS, '--batch'];
  /** Processes started, for the call-count tests. */
  spawned = 0;
  /** Object ids written to git, for the call-count tests. */
  requested = 0;
  /** The most blobs ever held at once, for the memory-bound test. */
  maxHeld = 0;
  /** git processes started and not yet exited, for the leak tests. */
  liveChildren = 0;
  private closed = false;

  constructor(
    private readonly repoTop: string,
    private readonly env: NodeJS.ProcessEnv,
    private readonly window = 10,
  ) {}

  /** The bytes of one blob. Rejects with {@link GitError} on any failure. */
  read(oid: string): Promise<Buffer> {
    const hit = this.shared.get(oid);
    if (hit !== undefined) return hit;
    const p = new Promise<Buffer>((resolve, reject) => {
      if (this.failed) {
        reject(this.failed);
        return;
      }
      if (this.closed) {
        reject(readFailure(this.repoTop, 'read after the reader was closed', `git ${this.argv.join(' ')}`));
        return;
      }
      this.queue.push({ oid, resolve, reject });
      this.pump();
    });
    this.shared.set(oid, p);
    this.maxHeld = Math.max(this.maxHeld, this.shared.size);
    return p;
  }

  /**
   * Forget a blob's bytes once every path that shares it has been scanned.
   * Without this every blob stays referenced for the whole run, and memory
   * grows with the total tracked size instead of with the read window.
   */
  release(oid: string): void {
    this.shared.delete(oid);
  }

  /** Blobs currently held, for the memory-bound test. */
  get held(): number {
    return this.shared.size;
  }

  /**
   * End the run's reads. Reads still queued are rejected rather than sent:
   * without this, an answer to an in-flight read would pump the queue into a
   * NEW git process (the old one is no longer referenced), which nothing would
   * ever close. In-flight reads are still answered before git exits.
   */
  close(): void {
    this.closed = true;
    const queued = this.queue.splice(0);
    if (queued.length > 0) {
      const err = readFailure(
        this.repoTop,
        'the run ended before these blobs were read',
        `git ${this.argv.join(' ')}`,
      );
      for (const p of queued) p.reject(err);
    }
    if (this.proc) {
      this.proc.stdin.end();
      this.proc = null;
    }
  }

  private start(): ChildProcessWithoutNullStreams {
    if (this.proc) return this.proc;
    this.spawned++;
    const proc = spawn('git', this.argv, {
      cwd: this.repoTop,
      env: this.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.liveChildren++;
    proc.on('close', () => {
      this.liveChildren--;
    });
    proc.stdout.on('data', (chunk: Buffer) => this.onData(chunk));
    proc.stderr.on('data', (chunk: Buffer) => {
      this.stderr += chunk.toString('utf-8');
    });
    proc.on('error', err => this.fail(String(err), err));
    proc.on('close', code => {
      if (this.inflight.length > 0 || this.queue.length > 0) {
        this.fail(
          this.stderr.trim().length > 0
            ? this.stderr.trim()
            : `git cat-file --batch exited with status ${String(code)} before answering`,
        );
      }
    });
    proc.stdin.on('error', err => this.fail(String(err), err));
    this.proc = proc;
    return proc;
  }

  private pump(): void {
    while (!this.failed && !this.closed && this.inflight.length < this.window && this.queue.length > 0) {
      const next = this.queue.shift() as Pending;
      this.inflight.push(next);
      this.requested++;
      this.start().stdin.write(`${next.oid}\n`);
    }
  }

  private fail(detail: string, cause?: unknown): void {
    if (this.failed) return;
    this.failed = readFailure(this.repoTop, detail, `git ${this.argv.join(' ')}`, cause);
    for (const p of [...this.inflight.splice(0), ...this.queue.splice(0)]) p.reject(this.failed);
    if (this.proc) {
      this.proc.kill();
      this.proc = null;
    }
  }

  private take(n: number): Buffer {
    const all = this.chunks.length === 1 ? this.chunks[0] : Buffer.concat(this.chunks, this.buffered);
    const head = all.subarray(0, n);
    const rest = all.subarray(n);
    this.chunks.length = 0;
    this.buffered = rest.length;
    if (rest.length > 0) this.chunks.push(rest);
    return head;
  }

  private onData(chunk: Buffer): void {
    this.chunks.push(chunk);
    this.buffered += chunk.length;
    while (!this.failed) {
      if (this.bodySize < 0) {
        const joined = this.chunks.length === 1 ? this.chunks[0] : Buffer.concat(this.chunks, this.buffered);
        this.chunks.length = 0;
        this.chunks.push(joined);
        const nl = joined.indexOf(0x0a);
        if (nl === -1) return;
        const header = joined.subarray(0, nl).toString('utf-8');
        this.take(nl + 1);
        const expected = this.inflight[0];
        if (expected === undefined) {
          this.fail(`unexpected output from git cat-file --batch: ${header}`);
          return;
        }
        const parts = header.split(' ');
        if (parts[0] !== expected.oid) {
          this.fail(`git cat-file --batch answered ${parts[0]} while ${expected.oid} was expected`);
          return;
        }
        if (parts.length === 2 && parts[1] === 'missing') {
          this.fail(`object ${expected.oid} is missing from the object store`);
          return;
        }
        if (parts.length !== 3 || parts[1] !== 'blob') {
          this.fail(`object ${expected.oid} is not a blob (${header})`);
          return;
        }
        const size = Number.parseInt(parts[2], 10);
        if (!Number.isFinite(size) || size < 0) {
          this.fail(`unparseable cat-file header: ${header}`);
          return;
        }
        this.bodySize = size;
      }
      if (this.buffered < this.bodySize + 1) return;
      const body = this.take(this.bodySize + 1);
      if (body[this.bodySize] !== 0x0a) {
        this.fail('git cat-file --batch output lost its framing (no newline after an object)');
        return;
      }
      this.bodySize = -1;
      const done = this.inflight.shift() as Pending;
      done.resolve(Buffer.from(body.subarray(0, body.length - 1)));
      this.pump();
    }
  }
}
