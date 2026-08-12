#!/usr/bin/env bash
# Self-test for action.yml path validation.
#
# Regression for macOS BSD regex RE_DUP_MAX=255: a bash `=~` pattern with
# `{1,256}` fails to compile, so every path (including `.`) was rejected.
# Keep charset + length checks portable across Linux and macOS bash.
set -euo pipefail

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
if grep -nE '\[A-Za-z0-9\._/-\]\{1,256\}' action.yml >/dev/null; then
  printf 'action.yml still contains {1,256} path regex (breaks macOS RE_DUP_MAX)\n' >&2
  exit 1
fi

printf 'action path validation OK (%s bash %s)\n' "$(uname -s)" "${BASH_VERSION}"
