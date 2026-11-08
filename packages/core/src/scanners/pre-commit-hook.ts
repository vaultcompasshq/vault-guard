import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { createHash } from 'crypto';
import { HookError } from '../errors';
import { readRegularFileNoFollow, writeFileAtomically, type NoFollowRead } from '../utils/read-no-follow';

export type HookManager = 'native' | 'husky' | 'lefthook' | 'precommit';

export interface InstallHookOptions {
  manager?: HookManager;
  /**
   * Working directory. MUST be the git repository root -- the directory
   * containing `.git` -- not a package subdirectory in a monorepo, even
   * one that owns its own `.husky`. `install()`/`uninstall()` refuse
   * outright when `.git` is not directly present (see the check at the
   * top of each), and core.hooksPath is resolved relative to the
   * worktree root regardless of where a nested `.husky` lives, so running
   * from anywhere else either fails fast or resolves the wrong hooks
   * directory entirely. Defaults to `process.cwd()`.
   */
  cwd?: string;
  /**
   * install only: rewrite a hook vault-guard wrote that was edited after
   * install (it starts with a whole vault-guard script and has more after it)
   * from the current template, discarding the edits. Without it, install
   * refuses that hook and changes nothing.
   */
  force?: boolean;
  /**
   * uninstall only: decide and report what uninstall would do, and change
   * nothing. The answer (success, kept, message) is the one the real run gives.
   */
  dryRun?: boolean;
}

/** What install did. `discardedEdits` is set when --force rewrote a hook vault-guard wrote that was edited after install. */
export interface InstallHookResult {
  success: boolean;
  message: string;
  hookPath?: string;
  discardedEdits?: boolean;
}

/** What uninstall did. `kept` is set when the hook is left in place because it is not vault-guard's to remove. */
export interface UninstallHookResult {
  success: boolean;
  message: string;
  kept?: boolean;
}

/**
 * The header line of a hook file vault-guard writes WHOLE, from a template.
 * The line alone does not make a file vault-guard's: lines can be added to a
 * written hook, and a foreign hook can copy the line. A file is deleted
 * whole only when its bytes are a script vault-guard wrote (see
 * classifyPreCommitHook); a file that carries this line and is not such a
 * script is `claimed`, and the uninstallers refuse it.
 */
const VAULT_GUARD_HOOK_HEADER = '# vault-guard pre-commit (installed by @vaultcompass/vault-guard)';

/** The header the 1.0.x native template wrote; read the same way as VAULT_GUARD_HOOK_HEADER. */
const LEGACY_HOOK_HEADER = '# vault-guard pre-commit hook';

/** Begin and end of the stanza vault-guard adds to a hook it does not own. */
const STANZA_BEGIN = '# --- vault-guard ---';
const STANZA_END = '# --- end vault-guard ---';

/**
 * SHA-256 of every whole hook script a released vault-guard wrote, after
 * normalizeScript. A hook whose normalized bytes hash to one of these is a
 * script vault-guard rendered, so the whole file is vault-guard's. The current
 * templates are added at load time (OWNED_SCRIPT_HASHES below), so this list
 * only grows when a template changes in a release.
 */
const RELEASED_SCRIPT_SHA256: readonly string[] = [
  // native, the 1.0.x template (header `# vault-guard pre-commit hook`)
  'fb543a82c80a9d6789f7f663114cab0b08867420b266270a3f9090e7e4c89ae6',
  // native, 1.0.0 to 1.3.0
  'b79e2c3a014a0eff5a2891c17e500661a88a064fb7e106935717e6984abb78cb',
  // native, 1.4.0 to 1.4.5
  '3ffb98c516a789b39ec54036a3774e5f245e0438c66ef8737b56bfbcc635a4e3',
  // native, 1.4.6 to 1.8.1
  '4c1c2dc8935e4845ead584ff695600b2f36489648859abe82ab862fb7bff4b55',
  // native, 1.9.0 to 1.13.1
  'ac7d22b5b6d5db2991ef91198fbc1c0e3d92fc656868d3d88a653c99abcd3d15',
  // husky, 1.0.0 to 1.4.3
  'a22adc057011bfd5c78fd6f97890f056361c8d507b3e6a9822ab9750f1e81840',
  // husky, 1.4.4 to 1.4.5
  'a562b7f801f2b1a4b2134789b7c66775ea09f017fadaf257750cff848578f466',
  // husky, 1.4.6 to 1.13.1
  '3e3cba67d78e085b19d1d4127dd9858afe4ec5626c21a730d8eac52279557316',
];

/**
 * CRLF to LF, and all trailing whitespace dropped, so a checkout's line ends
 * or extra blank lines at the end do not change ownership. Trailing whitespace
 * cannot add a command.
 */
function normalizeScript(text: string): string {
  return text.replace(/\r\n/g, '\n').trimEnd();
}

function scriptHash(text: string): string {
  return createHash('sha256').update(normalizeScript(text), 'utf8').digest('hex');
}

const RELEASED_SCRIPT_HASHES: ReadonlySet<string> = new Set(RELEASED_SCRIPT_SHA256);

/** True when the hook is, after normalizeScript, a whole script a released version wrote (the table above only). */
export function isReleasedHookScript(text: string): boolean {
  return RELEASED_SCRIPT_HASHES.has(scriptHash(text));
}

/**
 * The signature lines of every whole script vault-guard writes or wrote, in
 * the order they appear: the header line and the scan command line of that
 * script. The 1.0.0 to 1.4.3 husky script has no header line, so its pair is
 * two lines only the husky scripts up to 1.4.5 have. None of these scan lines
 * is the stanza's (`|| vault_guard_status=$?`), and the stanza earlier
 * versions appended to a husky hook has the `|| {` line but not the success
 * line after it.
 */
const WRITTEN_SCRIPT_SIGNATURES: ReadonlyArray<readonly [string, string]> = [
  // native 1.4.6 and later, husky 1.4.6 and later (the current templates)
  [VAULT_GUARD_HOOK_HEADER, 'vault-guard scan --staged || status=$?'],
  // native 1.0.0 to 1.4.5
  [VAULT_GUARD_HOOK_HEADER, 'if vault-guard scan --staged; then'],
  // husky 1.4.4 to 1.4.5
  [VAULT_GUARD_HOOK_HEADER, 'vault-guard scan --staged || {'],
  // the 1.0.x native template
  [LEGACY_HOOK_HEADER, 'vault-guard scan'],
  // husky 1.0.0 to 1.4.3 (no header line)
  ['vault-guard scan --staged || {', 'echo "✅ vault-guard: no secrets in staged files"'],
];

/**
 * True when the hook holds, in order and as whole lines (surrounding
 * whitespace and CRLF aside), the signature lines of a script vault-guard
 * writes or wrote. Called only for a hook that is not `owned` and not a
 * complete stanza, so it is a hook vault-guard wrote and somebody edited after
 * install (lines added, inserted, removed or put before the shebang), which
 * still runs vault-guard's own scan. A hook with the header line and no such
 * scan line does not match: it gets the stanza.
 */
function isEditedWrittenScript(text: string): boolean {
  const lines = text.replace(/\r\n/g, '\n').split('\n').map(line => line.trim());
  return WRITTEN_SCRIPT_SIGNATURES.some(([first, second]) => {
    const at = lines.indexOf(first);
    return at !== -1 && lines.indexOf(second, at + 1) !== -1;
  });
}

/** The install refusal for a hook vault-guard wrote that was edited after install. */
function editedRefusal(display: string): string {
  return (
    `${display} is a hook vault-guard wrote that was edited after install. Leaving it unchanged: ` +
    'remove the edits, or pass --force to rewrite it from the vault-guard template (the edits are discarded).'
  );
}

/** The uninstall refusal for a hook vault-guard wrote that was edited after install. */
function editedUninstallRefusal(display: string): string {
  return (
    `${display} is a hook vault-guard wrote that was edited after install, so vault-guard did not write all of it. ` +
    'Leaving it unchanged. Remove the vault-guard lines by hand and keep your own, or delete the file if nothing ' +
    'in it is yours.'
  );
}

/** The install message after --force rewrote an edited hook. */
function editedRewritten(display: string): string {
  return `Rewrote ${display} from the vault-guard template; the edits in it were discarded`;
}

/** The uninstall refusal for a merged hook whose remainder is still a vault-guard script with edits. */
function remainderRefusal(display: string): string {
  return (
    `Removing the vault-guard stanza from ${display} would leave a file that is still a hook vault-guard wrote, ` +
    'with edits, and it would keep running the scan. Leaving it unchanged. Delete the file if nothing in it is ' +
    'yours, or remove the vault-guard lines by hand and keep your own.'
  );
}

/**
 * The stanza earlier versions appended to the end of a husky hook. It
 * has a begin marker and no end marker; the husky uninstaller removes it only
 * when the file ends with exactly these bytes.
 */
const LEGACY_HUSKY_APPEND =
  '\n# --- vault-guard ---\nvault-guard scan --staged || {\n  echo "❌ vault-guard blocked commit"\n  exit 1\n}\n';

/**
 * What a pre-commit hook file is, decided by the bytes and markers vault-guard
 * itself writes for ownership and idempotency, and by a text match only for
 * the message:
 *
 * - `empty`: nothing but whitespace; the full template may be written.
 * - `owned`: the bytes are a whole script vault-guard wrote (the current
 *   native or husky template, or one a released version wrote), compared
 *   after normalizeScript. Only this file is deleted whole on uninstall.
 * - `merged`: a whole line is the stanza begin marker and a later whole line
 *   is the end marker: we added a stanza to somebody else's hook.
 * - `damaged`: a begin marker with no end marker after it. Not installed;
 *   install adds a complete stanza, uninstall refuses.
 * - `claimed`: a whole line is a vault-guard header, but the file is not a
 *   script vault-guard wrote (lines added to it, or a foreign hook that copied
 *   the header). Not installed; install merges the stanza as for any foreign
 *   hook, except that an edited vault-guard script (the signature lines of a
 *   script it wrote, isEditedWrittenScript) is refused unless --force; uninstall refuses and
 *   changes nothing.
 * - `wired`: somebody else's hook where, after quoted strings and a trailing
 *   comment are removed from a line, the command `vault-guard scan --staged`
 *   sits at a command start. Reading is per line, so this also matches a
 *   heredoc body or a line inside a multi-line string, and it says nothing
 *   about whether the line blocks (`|| true`, dead code). The text match is
 *   used for the install message only; install adds its own stanza anyway, and
 *   the uninstaller has no stanza to remove.
 * - `foreign`: anything else. Never overwritten, never deleted.
 *
 * Ownership and idempotency are by the whole script's bytes and the complete
 * stanza only. A header line alone, or a mention of the command anywhere, in a
 * heredoc, a multi-line string, a comment or a live line, gets the stanza.
 *
 * One definition shared by the native and husky installers, `isInstalled`,
 * both uninstallers and `vault-guard init`, so they always agree.
 */
export type PreCommitHookOwnership = 'empty' | 'owned' | 'merged' | 'damaged' | 'claimed' | 'wired' | 'foreign';

export function classifyPreCommitHook(text: string): PreCommitHookOwnership {
  if (text.trim().length === 0) return 'empty';
  if (OWNED_SCRIPT_HASHES.has(scriptHash(text))) return 'owned';
  const lines = text.split('\n').map(line => line.trimEnd());
  const begin = lines.indexOf(STANZA_BEGIN);
  if (begin !== -1) {
    return lines.indexOf(STANZA_END, begin + 1) !== -1 ? 'merged' : 'damaged';
  }
  if (lines.some(line => line === VAULT_GUARD_HOOK_HEADER || line === LEGACY_HOOK_HEADER)) {
    return 'claimed';
  }
  // A mention shaped like an invocation: after quoted strings and any trailing
  // comment are removed from the line (codeOnly), the command sits where a
  // command can start (line start, or after && || ; | then do { ( !). Used for
  // the install message and init's no-conflict answer, never for ownership.
  const invocation =
    /(?:^|&&|\|\||;|\bthen\b|\bdo\b|[{(!|])\s*(?:(?:npx|pnpm exec|pnpm|yarn|npm exec)\s+)?vault-guard\s+scan\s+--staged(?:\s|$|[;&|)}])/;
  if (lines.some(line => invocation.test(codeOnly(line)))) {
    return 'wired';
  }
  return 'foreign';
}

/**
 * One shell line with its single- and double-quoted strings removed and any
 * trailing comment cut off (a `#` at line start or after whitespace, outside
 * quotes). Line-local: a string that spans lines is not tracked, so a line
 * inside a heredoc or a multi-line string is read as code. That is harmless
 * because a `wired` hook still gets the stanza.
 */
function codeOnly(line: string): string {
  let out = '';
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (quote === '"' && ch === '\\') i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) break;
    out += ch;
  }
  return out;
}

/**
 * The stanza added to a foreign native hook. It is placed right after the
 * shebang (see mergeStanza), so it runs before the foreign hook's own
 * commands and a trailing `exit 0` or `exec` there cannot skip it. On success
 * it falls through and the foreign hook runs and exits as it always did; on a
 * non-zero scan it blocks the commit.
 */
const NATIVE_HOOK_STANZA = `${STANZA_BEGIN}
if command -v vault-guard >/dev/null 2>&1; then
  vault_guard_status=0
  vault-guard scan --staged || vault_guard_status=$?
  if [ "$vault_guard_status" -ne 0 ]; then
    echo ""
    if [ "$vault_guard_status" -eq 2 ]; then
      echo "❌ COMMIT BLOCKED: vault-guard could not complete the scan"
      echo "   See the message above for what went unexamined. This commit has not been checked."
    else
      echo "❌ COMMIT BLOCKED: secrets detected in staged files"
      echo "💡 Fix or unstage, then retry. Emergency bypass (discouraged): git commit --no-verify"
    fi
    exit 1
  fi
else
  echo "❌ vault-guard: command not found (install: npm i -g @vaultcompass/vault-guard)"
  exit 1
fi
${STANZA_END}
`;

/** True when git would run this hook with a POSIX shell (no shebang counts: git falls back to sh). */
function isShellHook(text: string): boolean {
  if (!text.startsWith('#!')) return true;
  const firstLine = text.split('\n', 1)[0];
  return /^#!\s*(?:\/usr\/bin\/env\s+(?:-S\s+)?)?(?:\S*\/)?(?:sh|bash|dash|zsh|ksh|ash)(?:\s|$)/.test(firstLine);
}

/** Insert the stanza after the shebang line (or at the top when there is none). */
function mergeStanza(text: string): string {
  if (!text.startsWith('#!')) return NATIVE_HOOK_STANZA + text;
  const nl = text.indexOf('\n');
  if (nl === -1) return `${text}\n${NATIVE_HOOK_STANZA}`;
  return text.slice(0, nl + 1) + NATIVE_HOOK_STANZA + text.slice(nl + 1);
}

/**
 * SHA-256 of every stanza a released vault-guard merged into a hook it did not
 * write, after normalizeStanza. A hash list rather than a render function per
 * version, the same choice as RELEASED_SCRIPT_SHA256: the released bytes are
 * fixed, a hash is an explicit record of exactly them, and the checked-in
 * fixture (released-hook-scripts.json) holds the text each hash stands for.
 * The current NATIVE_HOOK_STANZA is added at load time (RELEASED_STANZA_HASHES
 * below); when the stanza changes in a release, its old hash stays here.
 */
const RELEASED_STANZA_SHA256: readonly string[] = [
  // native 1.13.1 to 1.13.2, and husky 1.13.2 (1.13.1 husky appended LEGACY_HUSKY_APPEND instead)
  'bf29511d37d34ceb01ffd8c8a003b80453e9a1a801af5eab6557efc5993e08b3',
];

/**
 * CRLF to LF and trailing whitespace dropped from every line, ending with one
 * newline, so a checkout's line ends or trailing spaces do not make a stanza
 * look edited. Trailing whitespace on a line of the stanza cannot add a command.
 */
function normalizeStanza(block: string): string {
  return `${block
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map(line => line.trimEnd())
    .join('\n')
    .trimEnd()}\n`;
}

function stanzaHash(block: string): string {
  return createHash('sha256').update(normalizeStanza(block), 'utf8').digest('hex');
}

const RELEASED_STANZA_TABLE: ReadonlySet<string> = new Set(RELEASED_STANZA_SHA256);

/** Every stanza vault-guard merges or has merged: the current one plus the released ones. */
const RELEASED_STANZA_HASHES: ReadonlySet<string> = new Set([stanzaHash(NATIVE_HOOK_STANZA), ...RELEASED_STANZA_SHA256]);

/** True when the marked block is, after normalizeStanza, a stanza a released version merged (the table above only). */
export function isReleasedHookStanza(block: string): boolean {
  return RELEASED_STANZA_TABLE.has(stanzaHash(block));
}

/** Where the first marked block starts and ends (its end marker line included), or undefined without both markers. */
function stanzaBounds(text: string): { start: number; end: number } | undefined {
  const begin = text.search(new RegExp(`^${STANZA_BEGIN}[ \\t\\r]*$`, 'm'));
  if (begin === -1) return undefined;
  const endMatch = new RegExp(`^${STANZA_END}[ \\t\\r]*(?:\\n|$)`, 'm').exec(text.slice(begin));
  if (!endMatch) return undefined;
  return { start: begin, end: begin + endMatch.index + endMatch[0].length };
}

/**
 * Remove the stanza vault-guard added, leaving every other byte, but only
 * when the marked block is byte-equal (normalizeStanza aside) to a stanza
 * vault-guard released and the file holds exactly one begin and one end
 * marker. A block with a line added, removed or changed between its markers
 * is `edited`: removing it would delete the user's edit. Two or more markers
 * of either kind are `multiple`: which block vault-guard wrote cannot be told.
 * Either way the caller refuses and changes nothing.
 */
function stripReleasedStanza(
  text: string,
): { kind: 'stripped'; text: string } | { kind: 'edited' } | { kind: 'multiple' } {
  const lines = text.split('\n').map(line => line.trimEnd());
  const begins = lines.filter(line => line === STANZA_BEGIN).length;
  const ends = lines.filter(line => line === STANZA_END).length;
  if (begins !== 1 || ends !== 1) return { kind: 'multiple' };
  const bounds = stanzaBounds(text);
  if (!bounds) return { kind: 'multiple' };
  if (!RELEASED_STANZA_HASHES.has(stanzaHash(text.slice(bounds.start, bounds.end)))) return { kind: 'edited' };
  return { kind: 'stripped', text: text.slice(0, bounds.start) + text.slice(bounds.end) };
}

/** The uninstall refusal for a merged hook whose stanza was edited after install. */
function editedStanzaRefusal(display: string): string {
  return (
    `The vault-guard stanza in ${display} was edited after install: the lines between its markers differ from ` +
    'every stanza vault-guard wrote, and removing the block would delete those edits. Leaving the hook unchanged. ' +
    'Move your lines out of the stanza, or remove the stanza by hand.'
  );
}

/**
 * True when a line of the hook, read as code (codeOnly), runs `vault-guard
 * scan` at a command start, with or without a package runner and with any
 * flags. Wider than the `wired` reading on purpose: it decides only whether
 * the uninstaller may say the hook is uninstalled, so a doubt reads as "still
 * runs" and the hook is reported as kept.
 */
function stillRunsScan(text: string): boolean {
  const invocation = /(?:^|&&|\|\||;|\bthen\b|\bdo\b|[{(!|])\s*(?:(?:npx|pnpm exec|pnpm|yarn|npm exec)\s+)?vault-guard\s+scan\b/;
  return text.split('\n').some(line => invocation.test(codeOnly(line.trimEnd())));
}

/** The uninstall result after the stanza came off a hook whose own lines still run vault-guard. */
function keptRemainder(display: string): string {
  return (
    `Removed the vault-guard stanza from ${display}, but the rest of the hook still runs vault-guard scan on a ` +
    'line vault-guard did not add, so the hook was left in place. Remove that line by hand if you want ' +
    'vault-guard gone.'
  );
}

/**
 * True when git would skip this native hook file for want of an execute bit.
 * Never on Windows, where the mode bits do not decide whether Git for Windows
 * runs a hook.
 */
function lacksExecuteBit(mode: number): boolean {
  return process.platform !== 'win32' && (mode & 0o111) === 0;
}

/** The install refusal for a hook somebody else wrote, or merged into, that git does not run because it is not executable. */
function notExecutableRefusal(display: string): string {
  return (
    `${display} is not executable, so git does not run it, and the vault-guard scan in it would not run either. ` +
    'Leaving it unchanged: making it executable would also start running the commands in it that are not ' +
    `vault-guard's. Run chmod +x ${display} if they should run, then install again, or delete the file if it ` +
    'is not in use.'
  );
}

/** The uninstall refusal for a hook that holds more than one stanza begin or end marker. */
function multipleStanzaRefusal(display: string): string {
  return (
    `${display} holds more than one vault-guard stanza marker, so vault-guard cannot tell which block it wrote. ` +
    'Leaving the hook unchanged; remove the extra stanza by hand.'
  );
}

/** The uninstall refusal for a hook that carries the vault-guard header but is not a script vault-guard wrote. */
function claimedRefusal(display: string): string {
  return (
    `${display} carries the vault-guard header, but vault-guard did not write all of it ` +
    '(it differs from every script vault-guard writes). Leaving it unchanged. Remove the vault-guard ' +
    'header and the lines vault-guard wrote by hand and keep your own, or delete the file if nothing ' +
    'in it is yours.'
  );
}

/**
 * Shell hook body for **native** Git hooks (`core.hooksPath` or `.git/hooks`).
 * Scans **staged files only** -- fast and matches what will actually be committed.
 */
const NATIVE_HOOK_SCRIPT = `#!/bin/sh
${VAULT_GUARD_HOOK_HEADER}
set -e

# Re-attach stdin for GUI git clients when possible.
# dash (Ubuntu /bin/sh) exits the whole shell on a failed \`exec </dev/tty\`
# even with \`|| true\` / \`set +e\` -- exit status 2. Probe in a subshell first;
# only \`exec\` in the current shell when that open succeeds. \`[ -r /dev/tty ]\`
# is not a usable guard: the node can exist and still fail open with ENXIO.
if [ ! -t 0 ]; then
  if (exec </dev/tty) 2>/dev/null; then
    exec </dev/tty
  fi
fi

if ! command -v vault-guard >/dev/null 2>&1; then
  echo "❌ vault-guard: command not found (install: npm i -g @vaultcompass/vault-guard)"
  exit 1
fi

echo "🔍 vault-guard: scanning staged files..."
# Capture the status rather than branching on \`if vault-guard ...\`: after a
# bare \`if\` with no else branch, \`$?\` is the IF STATEMENT's status (0), not
# the command's, so the exit code would be lost. \`|| status=$?\` also keeps
# \`set -e\` from aborting here, because the failure is handled.
status=0
vault-guard scan --staged || status=$?

if [ "$status" -eq 0 ]; then
  echo "✅ vault-guard: no secrets in staged files"
  exit 0
fi

echo ""
if [ "$status" -eq 2 ]; then
  # Exit 2 means vault-guard could not finish the scan, not that it found
  # something. Claiming secrets were detected would be false, and offering
  # --no-verify beside it would recommend skipping a check that never ran.
  echo "❌ COMMIT BLOCKED: vault-guard could not complete the scan"
  echo "   See the message above for what went unexamined. This commit has not been checked."
  exit 1
fi

echo "❌ COMMIT BLOCKED: secrets detected in staged files"
echo "💡 Fix or unstage, then retry. Emergency bypass (discouraged): git commit --no-verify"
exit 1
`;

/**
 * Optional `pre-commit.cmd` beside the POSIX hook. Git for Windows runs the
 * extensionless `pre-commit` via sh; a few clients may invoke `.cmd` directly.
 */
const NATIVE_HOOK_CMD = `@echo off
REM vault-guard pre-commit (installed by @vaultcompass/vault-guard)
where vault-guard >nul 2>&1
if errorlevel 1 (
  echo ❌ vault-guard: command not found ^(install: npm i -g @vaultcompass/vault-guard^)
  exit /b 1
)

echo 🔍 vault-guard: scanning staged files...
call vault-guard scan --staged
REM \`if errorlevel N\` is true for anything >= N, so 2 must be tested BEFORE
REM 1 or an incomplete scan would fall into the secrets-detected branch.
if errorlevel 2 (
  echo.
  echo ❌ COMMIT BLOCKED: vault-guard could not complete the scan
  echo    See the message above for what went unexamined. This commit has not been checked.
  exit /b 1
)
if errorlevel 1 (
  echo.
  echo ❌ COMMIT BLOCKED: secrets detected in staged files
  echo 💡 Fix or unstage, then retry. Emergency bypass ^(discouraged^): git commit --no-verify
  exit /b 1
)

echo ✅ vault-guard: no secrets in staged files
exit /b 0
`;

/** Husky-friendly hook (sources \`_/husky.sh\` when present). */
const HUSKY_HOOK_SCRIPT = `#!/usr/bin/env sh
${VAULT_GUARD_HOOK_HEADER}
if [ -f "$(dirname "$0")/_/husky.sh" ]; then
  . "$(dirname "$0")/_/husky.sh"
fi

if ! command -v vault-guard >/dev/null 2>&1; then
  echo "❌ vault-guard: command not found (install: npm i -g @vaultcompass/vault-guard)"
  exit 1
fi

echo "🔍 vault-guard: scanning staged files..."
status=0
vault-guard scan --staged || status=$?

if [ "$status" -eq 2 ]; then
  # Could not finish the scan, as opposed to finding something. No
  # --no-verify hint here: the check never ran, so bypassing it is not the
  # remedy. See the native template for the same reasoning.
  echo ""
  echo "❌ COMMIT BLOCKED: vault-guard could not complete the scan"
  echo "   See the message above for what went unexamined. This commit has not been checked."
  exit 1
fi

if [ "$status" -ne 0 ]; then
  echo ""
  echo "❌ COMMIT BLOCKED: secrets detected in staged files"
  echo "💡 git commit --no-verify to bypass (discouraged)"
  exit 1
fi
echo "✅ vault-guard: no secrets in staged files"
`;

/** Every whole script vault-guard writes or has written: the current templates plus the released ones. */
const OWNED_SCRIPT_HASHES: ReadonlySet<string> = new Set([
  scriptHash(NATIVE_HOOK_SCRIPT),
  scriptHash(HUSKY_HOOK_SCRIPT),
  ...RELEASED_SCRIPT_SHA256,
]);

const LEFTHOOK_LOCAL =`# Merged by Lefthook with lefthook.yml -- added by vault-guard install-hook
pre-commit:
  commands:
    vault-guard:
      run: vault-guard scan --staged
`;

const PRE_COMMIT_CONFIG = `# See https://pre-commit.com
repos:
  - repo: local
    hooks:
      - id: vault-guard
        name: Vault Guard (staged files)
        entry: vault-guard scan --staged
        language: system
        pass_filenames: false
`;

/** A hook-file read: its text, absent, or a refusal message naming the path. */
type HookRead = { kind: 'absent' } | { kind: 'file'; text: string; mode: number } | { kind: 'refused'; message: string };

/**
 * Read a hook file the installer may write, never through a link (design
 * 2026-10-12, section 13). A link (a dangling one included), anything that is
 * not a regular file, or a parent directory that is a link, is refused with a
 * message naming the path; nothing is changed.
 */
function readHookFile(filePath: string, display: string): HookRead {
  const dir = path.dirname(filePath);
  try {
    if (fs.lstatSync(dir).isSymbolicLink()) {
      return {
        kind: 'refused',
        message: `${path.dirname(display)} is a symlink, not a regular file; vault-guard does not write through a link`,
      };
    }
  } catch {
    // The directory does not exist yet: it is created as a real directory.
  }
  // A read error (not a link) is thrown, so each installer step reports it
  // through its own existing failure message.
  const r: NoFollowRead = readRegularFileNoFollow(filePath);
  if (r.kind === 'absent') return { kind: 'absent' };
  if (r.kind === 'refused') {
    return {
      kind: 'refused',
      message:
        r.what === 'symlink'
          ? `${display} is a symlink, not a regular file; vault-guard does not write through a link`
          : `${display} is not a regular file; vault-guard does not write through a link`,
    };
  }
  let mode = 0o644;
  try {
    mode = fs.lstatSync(filePath).mode & 0o777;
  } catch {
    // Keep the default.
  }
  return { kind: 'file', text: r.text, mode };
}

export class PreCommitHook {
  /**
   * Resolve the directory where Git expects the \`pre-commit\` executable.
   * Honors \`core.hooksPath\` (local then global).
   *
   * A RELATIVE \`core.hooksPath\` resolves against the WORKING-TREE ROOT,
   * not against the .git directory. This resolved against the .git
   * directory until a review caught it: husky 9 sets exactly this shape
   * (core.hooksPath=.husky/_), so a repository using husky 9 had its hook
   * written to a path git never reads, reported as installed, and never
   * ran. Verified by driving a real commit rather than by re-reading the
   * documentation that was misread the first time: with
   * core.hooksPath=.husky/_ and an executable hook planted at BOTH
   * .husky/_/pre-commit and .git/.husky/_/pre-commit, a commit runs the
   * former. pre-commit-hook.test.ts pins it the same way.
   *
   * An ABSOLUTE \`core.hooksPath\` is used exactly as given, and no
   * \`core.hooksPath\` at all still resolves against the git directory
   * (never the working-tree root) -- both of those are unaffected by the
   * bug above and must stay that way: a linked worktree or a submodule
   * has its own git directory that is not its working-tree root, and that
   * is precisely where an unset \`core.hooksPath\` needs to keep pointing.
   */
  getEffectiveHooksDir(cwd: string): { hooksDir: string; viaHooksPath: boolean } {
    const gitDirAbs = this.resolveGitDir(cwd);
    if (!gitDirAbs) {
      return { hooksDir: path.join(cwd, '.git', 'hooks'), viaHooksPath: false };
    }

    let hooksPath = '';
    try {
      hooksPath = execSync('git config --get core.hooksPath', {
        cwd,
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
    } catch {
      hooksPath = '';
    }

    if (!hooksPath) {
      return { hooksDir: path.join(gitDirAbs, 'hooks'), viaHooksPath: false };
    }

    if (path.isAbsolute(hooksPath)) {
      return { hooksDir: hooksPath, viaHooksPath: true };
    }

    const worktreeRoot = this.resolveWorktreeRoot(cwd) ?? cwd;
    return { hooksDir: path.join(worktreeRoot, hooksPath), viaHooksPath: true };
  }

  /**
   * Whether the resolved hooks directory is husky 9's GENERATED,
   * gitignored directory (\`.husky/_\` by default) rather than a real
   * hooks directory. Husky's own prepare script rewrites this directory on
   * every \`pnpm install\`, so nothing vault-guard writes there survives;
   * the durable, tracked hook lives one directory up at
   * \`.husky/<hookname>\`.
   *
   * This is deliberately narrow: the ONLY signal that may trigger the
   * redirect is the directory SHAPE -- a resolved basename of \`_\` under a
   * directory literally named \`.husky\`. Two false-positive shapes were
   * caught by review before shipping and must never redirect:
   *  - core.hooksPath pointing at an unrelated directory (e.g. .githooks)
   *    that happens to contain a file literally named \`h\` -- an \`h\` file
   *    is not evidence of husky on its own, only the directory shape is;
   *  - a dispatcher-shaped pre-commit file (the same two-line shebang
   *    body husky 9 writes) sitting somewhere that is NOT \`.husky/_\`
   *    (e.g. plain \`.git/hooks/pre-commit\`) -- content shape alone is not
   *    evidence either, since a foreign hook can coincidentally look like
   *    this.
   * Neither the \`h\` shim nor dispatcher-shaped content is checked at all
   * here; they would only ever have been used to confirm a shape match,
   * never to trigger one on their own, and the shape check alone is both
   * necessary and sufficient for every case this fix needs to handle.
   */
  isHuskyGeneratedHooksDir(hooksDir: string): boolean {
    const base = path.basename(hooksDir);
    const parentBase = path.basename(path.dirname(hooksDir));
    return base === '_' && parentBase === '.husky';
  }

  /**
   * Where husky's own \`h\` shim actually resolves and executes the tracked
   * hook, given a husky-generated hooksDir (isHuskyGeneratedHooksDir(hooksDir)
   * must already be true). Husky computes this as the PARENT of the
   * generated \`_\` directory -- fixed relative to hooksDir, never a fixed
   * \`<cwd>/.husky\`, because core.hooksPath can point at a NESTED
   * \`.husky/_\` (e.g. \`packages/app/.husky/_\`, the ordinary shape for a
   * monorepo package that owns husky's "prepare" script but is not itself
   * the git root). In that case husky's shim genuinely runs
   * \`packages/app/.husky/<hookname>\`, not \`<cwd>/.husky/<hookname>\` --
   * proven wrong by independent review with a functional shim and a real
   * commit before this was fixed. getPreCommitHookPath, installNative,
   * uninstallNative, and getPreCommitCmdPath all resolve through this one
   * place so the redirect target can never drift between them.
   */
  private resolveHuskyDir(hooksDir: string): string {
    return path.dirname(hooksDir);
  }

  /** \`absPath\`, relative to \`cwd\`, with forward slashes on every platform. */
  private relFromCwd(cwd: string, absPath: string): string {
    return path.relative(cwd, absPath).split(path.sep).join('/');
  }

  /**
   * Absolute path to the \`pre-commit\` hook file for the given manager.
   *
   * For the \`native\` manager, when the resolved hooks directory is
   * husky 9's generated directory (see isHuskyGeneratedHooksDir), this
   * resolves to the TRACKED hook file husky's own \`h\` shim actually runs
   * -- see resolveHuskyDir -- because nothing written under the generated
   * directory survives husky's prepare script. See install()'s
   * husky-delegation in installNative for the write side of this.
   */
  getPreCommitHookPath(cwd: string, manager: HookManager = 'native'): string {
    if (manager === 'husky') {
      return path.join(cwd, '.husky', 'pre-commit');
    }
    const { hooksDir } = this.getEffectiveHooksDir(cwd);
    if (this.isHuskyGeneratedHooksDir(hooksDir)) {
      return path.join(this.resolveHuskyDir(hooksDir), 'pre-commit');
    }
    return path.join(hooksDir, 'pre-commit');
  }

  /**
   * Absolute path to the Windows \`pre-commit.cmd\` companion (native manager
   * only). \`undefined\` under a husky-generated hooks directory: the .cmd
   * companion is native-only and installNative's husky-redirect never
   * writes one there (see installNative), so there is no meaningful path
   * to report. Callers that used to guard this getter with their own
   * isHuskyGeneratedHooksDir check (the CLI's foreignHookConflict did)
   * can drop that guard now that it lives here instead.
   */
  getPreCommitCmdPath(cwd: string): string | undefined {
    const { hooksDir } = this.getEffectiveHooksDir(cwd);
    if (this.isHuskyGeneratedHooksDir(hooksDir)) {
      return undefined;
    }
    return path.join(hooksDir, 'pre-commit.cmd');
  }

  install(options: InstallHookOptions = {}): InstallHookResult {
    const cwd = options.cwd ?? process.cwd();
    const manager = options.manager ?? 'native';

    if (!fs.existsSync(path.join(cwd, '.git'))) {
      return { success: false, message: 'Not a git repository' };
    }

    const force = Boolean(options.force);
    switch (manager) {
      case 'native':
        return this.installNative(cwd, force);
      case 'husky':
        return this.installHusky(cwd, undefined, force);
      case 'lefthook':
        return this.installLefthook(cwd);
      case 'precommit':
        return this.installPreCommitFramework(cwd);
      default:
        return { success: false, message: `Unknown hook manager: ${String(manager)}` };
    }
  }

  uninstall(options: InstallHookOptions = {}): UninstallHookResult {
    const cwd = options.cwd ?? process.cwd();
    const manager = options.manager ?? 'native';

    if (!fs.existsSync(path.join(cwd, '.git'))) {
      return { success: false, message: 'Not a git repository' };
    }

    const dryRun = Boolean(options.dryRun);
    switch (manager) {
      case 'native':
        return this.uninstallNative(cwd, dryRun);
      case 'husky':
        return this.uninstallHusky(cwd, undefined, dryRun);
      case 'lefthook':
        // The YAML managers are not classified; a dry run only says what it would try.
        if (dryRun) return { success: true, message: 'Would remove lefthook-local.yml if vault-guard wrote it' };
        return this.uninstallLefthook(cwd);
      case 'precommit':
        if (dryRun) return { success: true, message: 'Would remove .pre-commit-config.yaml if vault-guard wrote it' };
        return this.uninstallPreCommitFramework(cwd);
      default:
        return { success: false, message: `Unknown hook manager: ${String(manager)}` };
    }
  }

  isInstalled(options: InstallHookOptions = {}): boolean {
    const cwd = options.cwd ?? process.cwd();
    const manager = options.manager ?? 'native';
    const hookPath = this.getPreCommitHookPath(cwd, manager);

    const r = readHookFile(hookPath, hookPath);
    if (r.kind !== 'file') return false;
    // A native or husky hook is judged by classifyPreCommitHook, so a hook that
    // only mentions vault-guard, or only carries its header line, is not
    // "installed". Lefthook and pre-commit keep the substring test: their
    // files are YAML, not a hook script.
    if (manager === 'native' || manager === 'husky') {
      const ownership = classifyPreCommitHook(r.text);
      // `wired`, `claimed` and `damaged` are not installed: install adds a stanza.
      if (ownership !== 'owned' && ownership !== 'merged') return false;
      // A native hook git runs directly is not installed without its execute
      // bit (issue 232); install then sets it on a script vault-guard wrote, or
      // refuses. Husky 9 runs the tracked .husky/pre-commit through sh, so the
      // husky paths do not depend on the bit.
      if (manager === 'native' && !this.isHuskyGeneratedHooksDir(this.getEffectiveHooksDir(cwd).hooksDir)) {
        return !lacksExecuteBit(r.mode);
      }
      return true;
    }
    return r.text.includes('vault-guard') && r.text.includes('scan --staged');
  }

  // -------------------------------------------------------------------------
  // native (Git hooks / core.hooksPath)
  // -------------------------------------------------------------------------

  /**
   * Write or refresh our `pre-commit.cmd`. Never overwrites a foreign file.
   * @returns whether our companion is present afterwards
   */
  private writeNativeCmdCompanion(hooksDir: string): boolean {
    const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
    const r = readHookFile(cmdPath, cmdPath);
    if (r.kind === 'refused') return false;
    if (r.kind === 'file') {
      const isOurs = r.text.includes('vault-guard') && r.text.includes('scan --staged');
      if (!isOurs) {
        return false;
      }
    }
    writeFileAtomically(cmdPath, NATIVE_HOOK_CMD, 0o644);
    return true;
  }

  /** @returns whether our companion was removed (or, on a dry run, would be) */
  private removeNativeCmdCompanion(hooksDir: string, dryRun = false): boolean {
    const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
    const r = readHookFile(cmdPath, cmdPath);
    if (r.kind !== 'file') return false;
    const content = r.text;
    if (!content.includes('vault-guard') || !content.includes('scan --staged')) {
      return false;
    }
    if (!dryRun) fs.unlinkSync(cmdPath);
    return true;
  }

  private installNative(cwd: string, force = false): InstallHookResult {
    const { hooksDir, viaHooksPath } = this.getEffectiveHooksDir(cwd);

    // core.hooksPath points at husky 9's generated, gitignored directory
    // (typically .husky/_, but see resolveHuskyDir for the nested case).
    // Writing there is pointless -- husky's prepare script rewrites it on
    // every `pnpm install` -- so install into the same tracked hook file
    // the husky manager uses, and say so. Never write under the generated
    // directory in this branch.
    if (this.isHuskyGeneratedHooksDir(hooksDir)) {
      const huskyDir = this.resolveHuskyDir(hooksDir);
      const result = this.installHusky(cwd, huskyDir, force);
      if (!result.success) {
        return result;
      }
      const relHookPath = this.relFromCwd(cwd, result.hookPath ?? path.join(huskyDir, 'pre-commit'));
      return {
        ...result,
        message: `Hooks are managed by husky; installing into ${relHookPath}. ${result.message}`,
      };
    }

    const hookPath = path.join(hooksDir, 'pre-commit');
    const cmdPath = path.join(hooksDir, 'pre-commit.cmd');

    // Both files are checked before either is written: a link at either path
    // fails the step and changes nothing (design 2026-10-12, section 13).
    try {
      const hookRead = readHookFile(hookPath, this.relFromCwd(cwd, hookPath));
      const cmdRead = readHookFile(cmdPath, this.relFromCwd(cwd, cmdPath));
      if (hookRead.kind === 'refused') return { success: false, message: hookRead.message };
      if (cmdRead.kind === 'refused') return { success: false, message: cmdRead.message };

      if (!fs.existsSync(hooksDir)) {
        fs.mkdirSync(hooksDir, { recursive: true });
      }

      let merged = false;
      let wiredMention = false;
      let rewroteEdited = false;
      if (hookRead.kind === 'file') {
        const existing = hookRead.text;
        const ownership = classifyPreCommitHook(existing);
        // Git skips a hook without its execute bit, so a non-executable hook is
        // never reported as installed (issue 232). A script vault-guard wrote
        // whole is made executable again; a hook with somebody else's lines in
        // it is refused before anything is written, because the bit would also
        // start running those lines, which may have been switched off on purpose.
        // An edited vault-guard script keeps its own refusal below (and --force
        // rewrites it from the template, executable).
        const notExecutable = lacksExecuteBit(hookRead.mode);
        if (notExecutable && ownership !== 'owned' && ownership !== 'empty' && !isEditedWrittenScript(existing)) {
          return { success: false, message: notExecutableRefusal(this.relFromCwd(cwd, hookPath)) };
        }
        if (ownership === 'owned' || ownership === 'merged') {
          let madeExecutable = '';
          if (notExecutable) {
            fs.chmodSync(hookPath, hookRead.mode | 0o111);
            madeExecutable = `; made ${this.relFromCwd(cwd, hookPath)} executable, since git does not run a hook without the execute bit`;
          }
          // Refresh the Windows companion if missing or stale (never clobber foreign).
          const cmdOk = this.writeNativeCmdCompanion(hooksDir);
          return {
            success: true,
            message:
              (cmdOk
                ? 'Hook already installed (POSIX + Windows .cmd companion)'
                : fs.existsSync(cmdPath)
                  ? 'Hook already installed (left foreign pre-commit.cmd untouched)'
                  : 'Hook already installed') + madeExecutable,
            hookPath,
          };
        }
        if (ownership !== 'empty' && isEditedWrittenScript(existing)) {
          // A script vault-guard wrote, with lines added after install. Merging
          // would run the scan twice and leave vault-guard's own script behind
          // on uninstall, so refuse; --force rewrites it from the template.
          if (!force) {
            return { success: false, message: editedRefusal(this.relFromCwd(cwd, hookPath)) };
          }
          rewroteEdited = true;
        } else if (ownership !== 'empty') {
          // Somebody else's hook: merge a marked stanza into it, never replace
          // it. A line that mentions the command (wired) gets the stanza too:
          // it may sit in a heredoc, a multi-line string, an `|| true` or dead
          // code, and vault-guard cannot verify from text that it blocks. So
          // does a hook that carries the header line but is not a script
          // vault-guard wrote (claimed), and one whose stanza lost its end
          // marker (damaged).
          wiredMention = ownership === 'wired';
          if (!isShellHook(existing)) {
            return {
              success: false,
              message:
                `${this.relFromCwd(cwd, hookPath)} is not a shell script, so vault-guard cannot merge into it. ` +
                'Add `vault-guard scan --staged` to it by hand, or run it from your hook manager.',
            };
          }
          writeFileAtomically(hookPath, mergeStanza(existing), hookRead.mode);
          merged = true;
        }
      }

      if (!merged) {
        writeFileAtomically(hookPath, NATIVE_HOOK_SCRIPT, 0o755);
      }
      const cmdOk = this.writeNativeCmdCompanion(hooksDir);

      const hint = viaHooksPath
        ? `Installed to hooksPath: ${hooksDir}`
        : cmdOk
          ? 'Installed to .git/hooks/pre-commit (+ pre-commit.cmd)'
          : 'Installed to .git/hooks/pre-commit';

      if (rewroteEdited) {
        return {
          success: true,
          message: `${editedRewritten(this.relFromCwd(cwd, hookPath))} (${hint})`,
          hookPath,
          discardedEdits: true,
        };
      }

      return {
        success: true,
        message: merged
          ? wiredMention
            ? 'The pre-commit hook already mentions vault-guard scan --staged; vault-guard cannot verify that line blocks, so its own stanza was added as well'
            : `Pre-commit hook installed (merged into your existing hook, which is otherwise unchanged; ${hint})`
          : `Pre-commit hook installed (${hint})`,
        hookPath,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to install hook: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  private uninstallNative(cwd: string, dryRun = false): UninstallHookResult {
    const { hooksDir } = this.getEffectiveHooksDir(cwd);

    if (this.isHuskyGeneratedHooksDir(hooksDir)) {
      const huskyDir = this.resolveHuskyDir(hooksDir);
      const result = this.uninstallHusky(cwd, huskyDir, dryRun);
      return {
        ...result,
        message: `Hooks are managed by husky; ${result.message}`,
      };
    }

    const hookPath = path.join(hooksDir, 'pre-commit');
    const hookRead = readHookFile(hookPath, this.relFromCwd(cwd, hookPath));
    if (hookRead.kind === 'refused') return { success: false, message: hookRead.message };

    // The companion is removed only once the hook itself is known to be
    // removable: a refusal below (damaged stanza, a hook with nothing of ours
    // to remove) deletes nothing. On a dry run nothing is removed at all.
    if (hookRead.kind === 'absent') {
      const cmdRemoved = this.removeNativeCmdCompanion(hooksDir, dryRun);
      return {
        success: true,
        message: cmdRemoved
          ? 'Removed Windows pre-commit.cmd companion'
          : 'No hook to remove',
      };
    }

    const content = hookRead.text;
    const ownership = classifyPreCommitHook(content);
    if (ownership === 'empty' || ownership === 'foreign') {
      const cmdRemoved = this.removeNativeCmdCompanion(hooksDir, dryRun);
      return {
        success: true,
        message: cmdRemoved
          ? 'Removed Windows pre-commit.cmd companion'
          : 'No vault-guard hook to remove',
      };
    }

    // An edited vault-guard script is refused, never kept: revert must not go on
    // as if the hook were the user's own.
    if (ownership !== 'merged' && ownership !== 'owned' && isEditedWrittenScript(content)) {
      return { success: false, message: editedUninstallRefusal(this.relFromCwd(cwd, hookPath)) };
    }

    if (ownership === 'wired') {
      return {
        success: false,
        kept: true,
        message:
          'The pre-commit hook mentions vault-guard scan --staged but vault-guard did not write it. ' +
          'Leaving it unchanged; remove that line by hand if you want it gone.',
      };
    }

    if (ownership === 'claimed') {
      return { success: false, message: claimedRefusal(this.relFromCwd(cwd, hookPath)) };
    }

    // A begin marker with no end marker means the stanza was edited or cut;
    // stripping would have to guess where it stops and could take the foreign
    // hook's own lines with it, so refuse and change nothing.
    if (ownership === 'damaged') {
      return {
        success: false,
        message:
          'The vault-guard stanza in the pre-commit hook is damaged (its end marker is missing). ' +
          'Leaving the hook unchanged; remove the stanza by hand.',
      };
    }

    try {
      if (ownership === 'merged') {
        // Remove exactly the stanza we added; the file is somebody else's.
        // Only a block equal to a released stanza is removed: an edit between
        // the markers, or a second stanza, is refused with nothing changed.
        // Unless what is left is still a script vault-guard wrote, with edits:
        // then removing the stanza would leave vault-guard's own scan running.
        const display = this.relFromCwd(cwd, hookPath);
        const strip = stripReleasedStanza(content);
        if (strip.kind === 'edited') return { success: false, message: editedStanzaRefusal(display) };
        if (strip.kind === 'multiple') return { success: false, message: multipleStanzaRefusal(display) };
        const stripped = strip.text;
        if (stripped.trim().length > 0 && isEditedWrittenScript(stripped)) {
          return { success: false, message: remainderRefusal(this.relFromCwd(cwd, hookPath)) };
        }
        // What is left still runs vault-guard on a line of its own (a vault-guard
        // script edited in a way the signature test does not catch, or the
        // user's own line): the stanza comes off, giving back exactly the hook
        // as it was before install, and the hook is reported as kept, the same
        // as a wired hook, never as uninstalled. The .cmd companion stays, as
        // for a wired hook.
        if (stillRunsScan(stripped)) {
          if (!dryRun) writeFileAtomically(hookPath, stripped, hookRead.mode);
          return { success: false, kept: true, message: keptRemainder(display) };
        }
        const cmdRemoved = this.removeNativeCmdCompanion(hooksDir, dryRun);
        if (dryRun) {
          // Nothing is changed.
        } else if (stripped.trim().length === 0) {
          fs.unlinkSync(hookPath);
        } else {
          writeFileAtomically(hookPath, stripped, hookRead.mode);
        }
        return {
          success: true,
          message: cmdRemoved
            ? 'Removed the vault-guard stanza from the pre-commit hook (the rest is unchanged) and the Windows .cmd companion'
            : 'Removed the vault-guard stanza from the pre-commit hook (the rest is unchanged)',
        };
      }
      // owned: the bytes are a whole script vault-guard wrote.
      const cmdRemoved = this.removeNativeCmdCompanion(hooksDir, dryRun);
      if (!dryRun) fs.unlinkSync(hookPath);
      return {
        success: true,
        message: cmdRemoved
          ? 'Pre-commit hook and Windows .cmd companion removed'
          : 'Pre-commit hook removed',
      };
    } catch (error) {
      const hookError = new HookError(`Failed to remove hook: ${error}`, 'uninstall');
      return { success: false, message: hookError.message };
    }
  }

  // -------------------------------------------------------------------------
  // Husky -- .husky/pre-commit
  // -------------------------------------------------------------------------

  /**
   * @param huskyDir Directory holding the tracked hook. Defaults to
   *   \`<cwd>/.husky\`, correct for the explicit \`husky\` manager (it never
   *   consults core.hooksPath). installNative's redirect passes the
   *   ACTUAL directory resolveHuskyDir computed instead, which can be
   *   nested (e.g. \`packages/app/.husky\`) -- see resolveHuskyDir.
   */
  private installHusky(
    cwd: string,
    huskyDir: string = path.join(cwd, '.husky'),
    force = false,
  ): InstallHookResult {
    const hookPath = path.join(huskyDir, 'pre-commit');
    const relHookPath = this.relFromCwd(cwd, hookPath);

    try {
      const hookRead = readHookFile(hookPath, relHookPath);
      if (hookRead.kind === 'refused') return { success: false, message: hookRead.message };

      if (!fs.existsSync(huskyDir)) {
        fs.mkdirSync(huskyDir, { recursive: true });
      }

      if (hookRead.kind === 'file' && hookRead.text.trim().length > 0) {
        const existing = hookRead.text;
        const ownership = classifyPreCommitHook(existing);
        // Adopted only when vault-guard wrote the whole script or a complete
        // stanza; a mention, a header line or a damaged stanza gets the stanza.
        if (ownership === 'owned' || ownership === 'merged') {
          return { success: true, message: 'Husky hook already contains vault-guard', hookPath };
        }
        // A script vault-guard wrote with lines added after install: refused
        // unless --force, which rewrites it from the template (see installNative).
        if (isEditedWrittenScript(existing)) {
          if (!force) return { success: false, message: editedRefusal(relHookPath) };
          writeFileAtomically(hookPath, HUSKY_HOOK_SCRIPT, 0o755);
          return { success: true, message: editedRewritten(relHookPath), hookPath, discardedEdits: true };
        }
        if (!isShellHook(existing)) {
          return {
            success: false,
            message:
              `${relHookPath} is not a shell script, so vault-guard cannot merge into it. ` +
              'Add `vault-guard scan --staged` to it by hand.',
          };
        }
        // The same stanza as the native merge, after the shebang, so a
        // trailing `exit 0` in the hook cannot skip it. Written by temporary
        // file and rename, so a link planted in between is replaced, never
        // written through.
        writeFileAtomically(hookPath, mergeStanza(existing), hookRead.mode);
        return {
          success: true,
          message: `Added the vault-guard stanza to existing ${relHookPath}, after the shebang line; the rest is unchanged`,
          hookPath,
        };
      }

      writeFileAtomically(hookPath, HUSKY_HOOK_SCRIPT, 0o755);
      return {
        success: true,
        message: `Created ${relHookPath} (run \`npx husky init\` first if _/husky.sh is missing)`,
        hookPath,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to install Husky hook: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  /**
   * @param huskyDir See installHusky.
   *
   * Fix for a defect the reviewer found while checking uninstall after
   * the redirect started routing every husky 9 repo through this
   * function (previously only reachable via the explicit `husky`
   * manager): when installHusky wrote the WHOLE file from
   * HUSKY_HOOK_SCRIPT (the fresh-install path -- what both the redirect
   * and a from-scratch \`--manager husky\` install take), there is no
   * "# --- vault-guard ---" appended-block marker to strip, so the old
   * logic here matched nothing, rewrote the file byte-identical, and
   * reported success:true with isInstalled still true. The shapes
   * vault-guard itself produces are told apart by classifyPreCommitHook:
   * a whole script vault-guard wrote is removed entirely; a complete
   * stanza (and the old stanza earlier versions appended at the end, when
   * the file ends with exactly it) is stripped, keeping the pre-existing
   * content; a file that carries the header but is not such a script, or
   * whose stanza lost its end marker, is refused and left untouched;
   * anything else that merely mentions "vault-guard" is left untouched,
   * with an honest message and success only if it does not still run the
   * command.
   */
  private uninstallHusky(
    cwd: string,
    huskyDir: string = path.join(cwd, '.husky'),
    dryRun = false,
  ): UninstallHookResult {
    const hookPath = path.join(huskyDir, 'pre-commit');
    const relHookPath = this.relFromCwd(cwd, hookPath);
    const hookRead = readHookFile(hookPath, relHookPath);
    if (hookRead.kind === 'refused') return { success: false, message: hookRead.message };
    if (hookRead.kind === 'absent') {
      return { success: true, message: `No ${relHookPath} to remove` };
    }

    const content = hookRead.text;
    const ownership = classifyPreCommitHook(content);

    // vault-guard wrote the ENTIRE file (a fresh --manager husky install or
    // the native husky redirect, this version or a released one): remove it.
    if (ownership === 'owned') {
      if (!dryRun) fs.unlinkSync(hookPath);
      return { success: true, message: `Removed ${relHookPath}` };
    }

    // vault-guard added a complete stanza to somebody else's hook, and maybe
    // an earlier version appended its old stanza at the end: strip exactly
    // those, preserving every other byte. The old appended stanza comes off
    // first, by its exact bytes, so its begin marker does not count as a
    // second stanza; the merged block is removed only when it equals a
    // released stanza (see uninstallNative).
    let stripped = content.endsWith(LEGACY_HUSKY_APPEND)
      ? content.slice(0, content.length - LEGACY_HUSKY_APPEND.length)
      : content;
    if (ownership === 'merged') {
      const strip = stripReleasedStanza(stripped);
      if (strip.kind === 'edited') return { success: false, message: editedStanzaRefusal(relHookPath) };
      if (strip.kind === 'multiple') return { success: false, message: multipleStanzaRefusal(relHookPath) };
      stripped = strip.text;
    }
    if (stripped !== content) {
      if (stripped.trim().length === 0) {
        if (!dryRun) fs.unlinkSync(hookPath);
        return { success: true, message: `Removed ${relHookPath}` };
      }
      // What is left is still a script vault-guard wrote, with edits: removing
      // the stanza would leave vault-guard's own scan running.
      if (isEditedWrittenScript(stripped)) {
        return { success: false, message: remainderRefusal(relHookPath) };
      }
      // The rest still runs vault-guard on a line of its own: kept, not
      // uninstalled (see uninstallNative).
      if (stillRunsScan(stripped)) {
        if (!dryRun) writeFileAtomically(hookPath, stripped, hookRead.mode);
        return { success: false, kept: true, message: keptRemainder(relHookPath) };
      }
      if (!dryRun) writeFileAtomically(hookPath, stripped, hookRead.mode);
      return { success: true, message: `Removed vault-guard stanza from ${relHookPath}` };
    }

    // An edited vault-guard script is refused, never kept (see uninstallNative).
    if (isEditedWrittenScript(content)) {
      return { success: false, message: editedUninstallRefusal(relHookPath) };
    }

    if (ownership === 'claimed') {
      return { success: false, message: claimedRefusal(relHookPath) };
    }
    if (ownership === 'damaged') {
      return {
        success: false,
        message:
          `The vault-guard stanza in ${relHookPath} is damaged (its end marker is missing). ` +
          'Leaving the hook unchanged; remove the stanza by hand.',
      };
    }
    if (!content.includes('vault-guard')) {
      return { success: true, message: `No vault-guard stanza in ${relHookPath}` };
    }

    // Mentions "vault-guard" somewhere, but in no shape vault-guard itself
    // writes -- do not guess at what to remove from a file this code did not
    // write; leave it untouched and say so honestly. Report success only if
    // it does not still run the command.
    const stillInstalled = content.includes('vault-guard') && content.includes('scan --staged');
    return {
      success: !stillInstalled,
      ...(stillInstalled ? { kept: true } : {}),
      message: `${relHookPath} mentions vault-guard but does not match the shape this version writes; it may have been written by an older vault-guard, or by hand. Leaving it unchanged. Review and remove the vault-guard reference manually if needed.`,
    };
  }

  // -------------------------------------------------------------------------
  // Lefthook -- lefthook-local.yml (merged with lefthook.yml)
  // -------------------------------------------------------------------------

  private installLefthook(cwd: string): { success: boolean; message: string; hookPath?: string } {
    const localPath = path.join(cwd, 'lefthook-local.yml');
    try {
      const localRead = readHookFile(localPath, 'lefthook-local.yml');
      if (localRead.kind === 'refused') return { success: false, message: localRead.message };
      if (localRead.kind === 'file') {
        const existing = localRead.text;
        if (existing.includes('vault-guard scan --staged')) {
          return { success: true, message: 'lefthook-local.yml already configures vault-guard', hookPath: localPath };
        }
        return {
          success: false,
          message:
            'lefthook-local.yml already exists. Add under pre-commit.commands:\n' +
            '  vault-guard:\n    run: vault-guard scan --staged\n',
        };
      }
      writeFileAtomically(localPath, LEFTHOOK_LOCAL, 0o644);
      return {
        success: true,
        message: 'Wrote lefthook-local.yml (merged by Lefthook with lefthook.yml). Run: lefthook install',
        hookPath: localPath,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to write lefthook-local.yml: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  private uninstallLefthook(cwd: string): { success: boolean; message: string } {
    const localPath = path.join(cwd, 'lefthook-local.yml');
    const localRead = readHookFile(localPath, 'lefthook-local.yml');
    if (localRead.kind === 'refused') return { success: false, message: localRead.message };
    if (localRead.kind === 'absent') {
      return { success: true, message: 'No lefthook-local.yml' };
    }
    const content = localRead.text;
    if (!content.includes('vault-guard')) {
      return { success: true, message: 'lefthook-local.yml does not reference vault-guard' };
    }
    // Only remove the file if it is exactly what we wrote (avoid deleting user merges).
    if (content.replace(/\r\n/g, '\n').trim() !== LEFTHOOK_LOCAL.replace(/\r\n/g, '\n').trim()) {
      return {
        success: true,
        message: 'lefthook-local.yml was edited -- remove the vault-guard stanza manually',
      };
    }
    try {
      fs.unlinkSync(localPath);
      return { success: true, message: 'Removed lefthook-local.yml (vault-guard stub)' };
    } catch (error) {
      const hookError = new HookError(`Failed to remove lefthook-local.yml: ${error}`, 'uninstall');
      return { success: false, message: hookError.message };
    }
  }

  // -------------------------------------------------------------------------
  // pre-commit.com framework
  // -------------------------------------------------------------------------

  private installPreCommitFramework(cwd: string): { success: boolean; message: string; hookPath?: string } {
    const cfg = path.join(cwd, '.pre-commit-config.yaml');
    // Inside a try, like the lefthook and native readers: an unreadable
    // config is a refusal (exit 1), not an uncaught throw (exit 2).
    let cfgRead: ReturnType<typeof readHookFile>;
    try {
      cfgRead = readHookFile(cfg, '.pre-commit-config.yaml');
    } catch (error) {
      const hookError = new HookError(`Failed to read .pre-commit-config.yaml: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
    if (cfgRead.kind === 'refused') return { success: false, message: cfgRead.message };
    if (cfgRead.kind === 'file') {
      const existing = cfgRead.text;
      if (existing.includes('vault-guard') && existing.includes('scan --staged')) {
        return { success: true, message: '.pre-commit-config.yaml already includes vault-guard', hookPath: cfg };
      }
      return {
        success: false,
        message:
          '.pre-commit-config.yaml already exists. Merge manually:\n\n' +
          PRE_COMMIT_CONFIG +
          '\n(under your existing `repos:` list as an additional item, or combine with `repo: local`)',
      };
    }
    try {
      writeFileAtomically(cfg, PRE_COMMIT_CONFIG, 0o644);
      return {
        success: true,
        message: 'Created .pre-commit-config.yaml -- run: pre-commit install',
        hookPath: cfg,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to write .pre-commit-config.yaml: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  private uninstallPreCommitFramework(cwd: string): { success: boolean; message: string } {
    const cfg = path.join(cwd, '.pre-commit-config.yaml');
    const cfgRead = readHookFile(cfg, '.pre-commit-config.yaml');
    if (cfgRead.kind === 'refused') return { success: false, message: cfgRead.message };
    if (cfgRead.kind === 'absent') {
      return { success: true, message: 'No .pre-commit-config.yaml' };
    }
    const content = cfgRead.text;
    if (!content.includes('vault-guard')) {
      return { success: true, message: '.pre-commit-config.yaml does not reference vault-guard' };
    }
    // Only delete if we created the minimal file (only our hook).
    if (content.includes('id: vault-guard') && content.split('\n').length < 25) {
      try {
        fs.unlinkSync(cfg);
        return { success: true, message: 'Removed .pre-commit-config.yaml (vault-guard-only stub)' };
      } catch (error) {
        const hookError = new HookError(`Failed to remove config: ${error}`, 'uninstall');
        return { success: false, message: hookError.message };
      }
    }
    return {
      success: true,
      message: 'Edit .pre-commit-config.yaml manually to remove the vault-guard hook entry',
    };
  }

  private resolveGitDir(cwd: string): string | null {
    try {
      const rel = execSync('git rev-parse --git-dir', {
        cwd,
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
      return path.resolve(cwd, rel);
    } catch {
      return null;
    }
  }

  /**
   * The working-tree root, or null when it cannot be determined. Asked of
   * git rather than assumed to be \`cwd\`, so a relative \`core.hooksPath\`
   * resolves correctly when \`install\`/\`getEffectiveHooksDir\` is called
   * from a subdirectory of the repository.
   */
  private resolveWorktreeRoot(cwd: string): string | null {
    try {
      const rel = execSync('git rev-parse --show-toplevel', {
        cwd,
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
      return path.resolve(cwd, rel);
    } catch {
      return null;
    }
  }
}
