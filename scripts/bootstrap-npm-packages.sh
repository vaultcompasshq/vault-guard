#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Dependency order: core has no @vaultcompass/* deps, telemetry depends on
# core, and cli and mcp both depend on core and telemetry (not on each
# other). This list must be updated by hand when a package is added -- the
# cross-check below refuses to run if it and the packages/ directory
# disagree, so a new package cannot be silently skipped.
PACKAGES=(
  "packages/core"
  "packages/telemetry"
  "packages/cli"
  "packages/mcp"
)

echo "Bootstrap publish for @vaultcompass/vault-guard-*"
echo "This script is for FIRST publishes of a new subpackage -- a package"
echo "that does not exist on npm yet cannot use OIDC trusted publishing,"
echo "because there is nothing to attach a trusted publisher to until"
echo "something is published. Routine releases of packages that already"
echo "exist stay tag-driven through .github/workflows/release.yml; this"
echo "script will simply skip anything already on the registry (see below)."
echo "Requires: npm login with publish access to @vaultcompass"
echo ""

if ! npm whoami >/dev/null 2>&1; then
  echo "Not logged in. Run: npm login"
  exit 1
fi

# A bootstrap publish must ship exactly what main holds, so refuse to run
# from a dirty tree or any branch other than main.
if [[ -n "$(git -C "$ROOT" status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit or stash before running this."
  exit 1
fi

CURRENT_BRANCH="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)"
if [[ "$CURRENT_BRANCH" != "main" ]]; then
  echo "Not on main (on ${CURRENT_BRANCH}). Check out main before running this."
  exit 1
fi

echo "Logged in as: $(npm whoami)"
cd "$ROOT"

# Cross-check the hardcoded PACKAGES list above against packages/ on disk:
# every directory under packages/ that has a package.json without
# "private": true must appear in PACKAGES, and every entry in PACKAGES must
# be such a directory. This is what catches a new publishable package
# (e.g. a new packages/vault-guard-something) added without updating the
# list above -- packages/vscode-extension (private: true, Marketplace only)
# and packages/cursor-skill (no package.json at all) are expected to be
# absent from PACKAGES and are excluded here on the same basis.
PACKAGES_JSON="$(node -e "
  console.log(JSON.stringify([$(printf '"%s",' "${PACKAGES[@]}")]));
")"

node -e "
  const fs = require('fs');
  const path = require('path');

  const declared = new Set(${PACKAGES_JSON});

  const onDisk = new Set();
  for (const entry of fs.readdirSync('packages', { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const pkgJsonPath = path.join('packages', entry.name, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) continue;
    const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    if (pkgJson.private === true) continue;
    onDisk.add('packages/' + entry.name);
  }

  const missingFromScript = [...onDisk].filter((p) => !declared.has(p)).sort();
  const missingFromDisk = [...declared].filter((p) => !onDisk.has(p)).sort();

  if (missingFromScript.length > 0 || missingFromDisk.length > 0) {
    if (missingFromScript.length > 0) {
      console.error('Publishable under packages/ but missing from this script\'s PACKAGES list: ' + missingFromScript.join(', '));
    }
    if (missingFromDisk.length > 0) {
      console.error('Listed in this script\'s PACKAGES but not a publishable package on disk: ' + missingFromDisk.join(', '));
    }
    console.error('Update the PACKAGES list in scripts/bootstrap-npm-packages.sh (in dependency order) before running this again.');
    process.exit(1);
  }
"

echo "Package list matches packages/ on disk: ${PACKAGES[*]}"

pnpm build

# The RULES.md drift check catches docs/RULES.md going stale against the
# rule source it's generated from -- the same check release.yml runs right
# before a real release.
node scripts/gen-rules-doc.cjs
git diff --exit-code docs/RULES.md

pnpm lint
pnpm check:private-names
pnpm check:pack
pnpm test:coverage

# Cheap and local: scans a handful of generated fixtures against the CLI
# just built above, no network involved. Skipped from this list would be
# the node-version matrix, the Windows test job, and `pnpm audit` -- all
# three are CI-only concerns (multi-runtime coverage, a registry advisory
# lookup) rather than gates release.yml itself runs before publishing.
node bench/run.cjs --assert

# Publish in the dependency order declared in PACKAGES above. Skips any
# package already on the registry at its current version, mirroring the
# publish loop in .github/workflows/release.yml, so re-running this script
# after a partial failure -- or running it when every package listed
# already exists, which is the common case until a new subpackage is
# added -- is safe and only genuinely new packages or versions publish.
#
# pnpm's git checks stay on (no --no-git-checks) since the preflight above
# already enforces a clean tree on main. --publish-branch main is required
# alongside that: pnpm's git checks default to expecting the publish
# branch to be named "master", and this repo has no .npmrc overriding it,
# so a plain "pnpm publish" would fail the branch check here even on a
# clean, up-to-date main. (Conductor's own bootstrap script never needed
# this flag only because conductor's .npmrc sets git-checks=false; that is
# a config dependency worth stating here rather than inheriting invisibly.)
for pkg in "${PACKAGES[@]}"; do
  name="$(node -p "require('./${pkg}/package.json').name")"
  ver="$(node -p "require('./${pkg}/package.json').version")"
  if [[ "$(npm view "${name}@${ver}" version 2>/dev/null || true)" == "${ver}" ]]; then
    echo "Skip ${name}@${ver} (already on registry)"
    continue
  fi
  echo ""
  echo "Publishing ${name}@${ver}..."
  (cd "$ROOT/$pkg" && pnpm publish --access public --tag latest --publish-branch main)
done

cat <<'EOF'

For any package this run actually published for the first time, go to
npmjs.com -> that package -> Settings -> Trusted Publisher and add:
  Publisher: GitHub Actions
  Organization or user: vaultcompasshq
  Repository: vault-guard
  Workflow filename: release.yml
  Environment: (leave blank)

Routine releases of packages that already exist stay tag-driven through
release.yml, which already publishes via OIDC trusted publishing -- this
script has no role in that path. It exists only for the moment a brand
new @vaultcompass/vault-guard-* subpackage is added and needs its first,
logged-in publish before a trusted publisher can be configured for it.
EOF
