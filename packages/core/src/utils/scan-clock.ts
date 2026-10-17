/**
 * The clock the per-file scan budget is measured with (design 2026-10-17,
 * section 6.2).
 *
 * The budget measures CPU time of the scanning thread during the scan of one
 * copy, not wall time: time the thread spent descheduled on a loaded machine
 * says nothing about the content. `process.threadCpuUsage()` gives that
 * directly, but only on newer Node lines. Where it is not known to be stable,
 * the measure is the smaller of process CPU time and wall time, which is never
 * below the thread's own CPU time (so it never under-measures a runaway) and
 * never above wall time (so it is never worse than the 1.10.0 measure).
 *
 * The choice is STATIC: made from whether the function exists and from
 * `process.versions.node`, never by calling the per-thread clock to see
 * whether it warns. A probe that emitted an ExperimentalWarning would itself
 * be a line on stderr before INCOMPLETE.
 */

export type ClockMeasure = 'thread-cpu' | 'min-process-cpu-wall';

/** Two cumulative readings in milliseconds and the rule that combines their deltas. */
export interface ScanClock {
  readonly measure: ClockMeasure;
  /** Cumulative CPU time: the thread's, or the process's (user plus system). */
  cpuMs(): number;
  /** Monotonic wall time. */
  wallMs(): number;
}

/**
 * Node lines on which `process.threadCpuUsage()` is documented and carries
 * no stability marking (so it is not experimental and emits no warning).
 * Source: the Node.js API documentation for `process.threadCpuUsage`,
 * "Added in: v23.9.0, v22.19.0", with no History table and no stability
 * index, on the v22 and the current (v26) documentation, read 2026-10-17.
 * This repository's CI matrix runs 22.x, 24.x and 25.x. A line not listed
 * here takes the process-CPU fallback.
 */
export const THREAD_CPU_STABLE_NODE: ReadonlyArray<{ readonly major: number; readonly from: string }> = Object.freeze([
  Object.freeze({ major: 22, from: '22.19.0' }),
  Object.freeze({ major: 23, from: '23.9.0' }),
  Object.freeze({ major: 24, from: '24.0.0' }),
  Object.freeze({ major: 25, from: '25.0.0' }),
  Object.freeze({ major: 26, from: '26.0.0' }),
]);

function parse(v: string): [number, number, number] | undefined {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(v);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : undefined;
}

/** Whether the per-thread clock is used, from facts read without calling it. */
export function threadCpuClockUsable(nodeVersion: string, hasThreadCpuUsage: boolean): boolean {
  if (!hasThreadCpuUsage) return false;
  const v = parse(nodeVersion);
  if (!v) return false;
  const row = THREAD_CPU_STABLE_NODE.find(r => r.major === v[0]);
  if (!row) return false;
  const from = parse(row.from) as [number, number, number];
  if (v[1] !== from[1]) return v[1] > from[1];
  return v[2] >= from[2];
}

const usec = (u: { user: number; system: number }): number => (u.user + u.system) / 1000;

let cached: ScanClock | undefined;

/** The process's scan clock, decided once. */
export function defaultScanClock(): ScanClock {
  if (cached) return cached;
  const proc = process as NodeJS.Process & { threadCpuUsage?: () => { user: number; system: number } };
  const thread = threadCpuClockUsable(process.versions.node, typeof proc.threadCpuUsage === 'function');
  cached = thread
    ? {
        measure: 'thread-cpu',
        cpuMs: () => usec((proc.threadCpuUsage as () => { user: number; system: number })()),
        wallMs: () => performance.now(),
      }
    : {
        measure: 'min-process-cpu-wall',
        cpuMs: () => usec(process.cpuUsage()),
        wallMs: () => performance.now(),
      };
  return cached;
}

/** One measured span: the deciding measure and the wall time it took. */
export function timeSpan<T>(clock: ScanClock, fn: () => T): { value: T; ms: number; wallMs: number } {
  const c0 = clock.cpuMs();
  const w0 = clock.wallMs();
  const value = fn();
  const cpu = clock.cpuMs() - c0;
  const wall = clock.wallMs() - w0;
  return { value, ms: clock.measure === 'thread-cpu' ? cpu : Math.min(cpu, wall), wallMs: wall };
}
