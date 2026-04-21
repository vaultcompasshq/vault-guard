# Minimal image for CI or local scans (installs published CLI from npm).
# Build: docker build -t vault-guard:local -f docker/Dockerfile .
# Run:   docker run --rm -v "$PWD":/repo -w /repo vault-guard:local scan .
FROM node:20-bookworm-slim

ARG VG_VERSION=latest
RUN npm install -g "@vaultcompass/vault-guard@${VG_VERSION}" \
  && apt-get update \
  && apt-get install -y --no-install-recommends git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /repo
ENTRYPOINT ["vault-guard"]
CMD ["scan", ".", "--format", "sarif"]
