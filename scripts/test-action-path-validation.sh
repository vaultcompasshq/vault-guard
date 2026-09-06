#!/usr/bin/env bash
# Self-test for action.yml path validation.
#
# Regression for macOS BSD regex RE_DUP_MAX=255: a bash `=~` pattern with
# `{1,256}` fails to compile, so every path (including `.`) was rejected.
# Keep charset + length checks portable across Linux and macOS bash.
set -euo pipefail

# Anchored to this script rather than to the caller's cwd. The grep guards
# below check the real action.yml, and a run from anywhere else used to check
# whatever action.yml happened to sit in the current directory, which is a
# guard that passes without having looked at the file it names.
ACTION_YML="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/action.yml"

validate_path() {
  local value="$1"
  if [[ ! "${value}" =~ ^[A-Za-z0-9._/-]+$ ]] || (( ${#value} > 256 )); then
    return 1
  fi
  if [[ "${value}" == *".."* ]]; then
    return 1
  fi
  if [[ "${value}" == /* ]]; then
    return 1
  fi
  return 0
}

assert_ok() {
  local value="$1"
  if ! validate_path "${value}"; then
    printf 'expected OK for %q\n' "${value}" >&2
    exit 1
  fi
}

assert_bad() {
  local value="$1"
  if validate_path "${value}"; then
    printf 'expected reject for %q\n' "${value}" >&2
    exit 1
  fi
}

# The failing consumer default that dogfooded the bug.
assert_ok "."
assert_ok "./src"
assert_ok "vault-guard-results.sarif"
assert_ok "$(printf 'a%.0s' {1..256})"

assert_bad ""
assert_bad ".."
assert_bad "../etc"
assert_bad "/etc/passwd"
assert_bad "has space"
assert_bad "semi;colon"
assert_bad "$(printf 'a%.0s' {1..257})"

# Guard: the old pattern must not be reintroduced. On macOS it fails to
# compile; on Linux it "works" and would hide the regression from ubuntu CI.
if grep -nE '\[A-Za-z0-9\._/-\]\{1,256\}' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml still contains {1,256} path regex (breaks macOS RE_DUP_MAX)\n' >&2
  exit 1
fi


# Guard: npx must not pass a bare `--` before `scan`. That separator is
# forwarded into vault-guard argv; Commander then ignores `--format` and the
# action tees text banners into the SARIF file.
if grep -nE 'npx[^\n]*--[[:space:]]+scan' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml still uses `npx … -- scan` (breaks --format / SARIF upload)\n' >&2
  exit 1
fi

# --- trust-base -------------------------------------------------------------
#
# Same checks as the path ones above, for the same reason: the value reaches a
# command line, and this file is where a regression in it gets noticed on both
# Linux and macOS bash.

validate_trust_base() {
  local value="$1"
  # `off` is refused BY NAME rather than falling through to the ref charset,
  # which it would otherwise pass and be used as a branch called "off". It was
  # accepted before 1.7.0 shipped and was removed because a same-repo
  # pull_request event runs the workflow file from the pull request head, so an
  # off switch here sits on the untrusted side of the boundary it turns off.
  if [[ "${value}" == "off" ]]; then
    return 1
  fi
  if [[ "${value}" == "auto" ]]; then
    return 0
  fi
  if [[ ! "${value}" =~ ^[A-Za-z0-9._/@^~-]+$ ]] || (( ${#value} > 200 )); then
    return 1
  fi
  return 0
}

assert_trust_ok() {
  if ! validate_trust_base "$1"; then
    printf 'expected OK for trust-base %q\n' "$1" >&2
    exit 1
  fi
}

assert_trust_bad() {
  if validate_trust_base "$1"; then
    printf 'expected reject for trust-base %q\n' "$1" >&2
    exit 1
  fi
}

assert_trust_ok "auto"
assert_trust_ok "origin/main"
assert_trust_ok "HEAD~1"
assert_trust_ok "v1.2.3^"

assert_trust_bad ""
assert_trust_bad "off"
assert_trust_bad 'HEAD^{commit}'
assert_trust_bad 'origin/$(id)'
assert_trust_bad 'origin/main; rm -rf /'
assert_trust_bad 'origin/`id`'
assert_trust_bad "$(printf 'a%.0s' {1..201})"

# Guard: `trust-base: off` must be refused by name, with an error that says it
# was removed. Base-ref judging is the floor and not a knob: on a same-repo
# pull_request event the workflow file runs from the pull request head, so any
# off switch here is settable by the pull request it is meant to judge. Without
# this guard `off` reads as an ordinary ref, passes the charset check, and the
# scan fails later with a confusing "does not resolve to a commit".
if ! grep -n 'trust-base: off` was removed' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer refuses `trust-base: off` by name with a removal message\n' >&2
  exit 1
fi

# Guard: and the argv builder must not carry a branch for it either, which is
# where the switch actually lived.
if grep -nE '"\$\{VG_TRUST_BASE\}" != "off"' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml still treats `off` as a trust-base keyword in the argv builder\n' >&2
  exit 1
fi

# Guard: the ref must reach npx as a bash ARRAY element, so a branch name with
# a space stays one argv entry. A string built with `TRUST_ARGS="--trust-base
# ${ref}"` would word-split at the first space.
if ! grep -nE 'TRUST_ARGS=\(' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml no longer builds the trust-base args as an array\n' >&2
  exit 1
fi

# Guard: `set -u` plus bash 3.2 (macOS runners) aborts on a bare empty-array
# expansion, so the `+` form is required rather than stylistic. Checked on the
# npx line itself, not anywhere in the file: an earlier version of this guard
# grepped the whole document and was satisfied by the COMMENT explaining the
# idiom, which is a guard that passes whatever the code says.
npx_line="$(grep 'npx --yes' "${ACTION_YML}" || true)"
if [[ -z "${npx_line}" ]]; then
  printf 'action.yml no longer invokes npx --yes\n' >&2
  exit 1
fi
if [[ "${npx_line}" != *'TRUST_ARGS[@]+'* ]]; then
  printf 'the npx line expands TRUST_ARGS without the ${a[@]+...} guard (breaks bash 3.2 + set -u)\n' >&2
  exit 1
fi

# Guard: the base ref must never be interpolated into a run body as a GitHub
# expression. That substitution happens before the shell parses the script, so
# no amount of quoting downstream helps.
if grep -nE '\$\{\{[^}]*base_ref' "${ACTION_YML}" >/dev/null; then
  printf 'action.yml interpolates base_ref into a run body (command injection)\n' >&2
  exit 1
fi

printf 'action path validation OK (%s bash %s)\n' "$(uname -s)" "${BASH_VERSION}"
