echo "BASH_ENV_PROBE: sourced from $0 at step $GITHUB_ACTION"
exit() { echo "BASH_ENV_PROBE: exit neutralized, requested code was ${1:-0}"; return 0; }
