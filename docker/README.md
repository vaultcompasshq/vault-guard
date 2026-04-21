# Docker image (optional)

Build a local image that installs the **published** npm package:

```bash
docker build -t vault-guard:local -f docker/Dockerfile --build-arg VG_VERSION=latest .
```

From a repository you want to scan:

```bash
docker run --rm -v "$(pwd)":/repo -w /repo vault-guard:local scan .
```

For GitHub Container Registry publishing, add a workflow that builds and pushes
`ghcr.io/vaultcompasshq/vault-guard` on release tags (not included here by default).
