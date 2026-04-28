# Bocce

## Introduction

Bocce is a tool that generates [cloud-init](https://github.com/canonical/cloud-init) user data files for provisioning new environments with standard settings/tools found in typical Boxing Octopus Creative environments

## Why "Bocce"?

Honestly, my IDE autocompleted `boc-do-user-data` to "Bocce", I thought it was funny, and I'm part Italian. So I kept it. It's not that deep.

## Usage

Render the cloud-config template with file-backed SSH key and CA cert, and a locally generated `mkpasswd -m sha-512` compatible password hash:

```bash
./dist/bocce-darwin-arm64 \
  -ssh-key-path ~/.ssh/id_ed25519.pub \
  -ca-cert-path ./aiven_ca.crt \
  -starship-preset nerd-font-symbols \
  -password 'change-me' \
  -output-path .
```

Notes:

- `-password` and `-ca-cert-path` are required.
- `-ssh-key-path` is optional; if omitted, a new no-passphrase ed25519 keypair is generated in `-output-path`.
- `-template` defaults to `templates/user-data.yaml.tmpl`.
- `-output-path` is optional; defaults to the current directory and writes `user-data.yaml`.
- `-outputPath` remains supported as a legacy alias.
- `-salt` is optional; if omitted, a random salt is generated.
- `-rounds` defaults to `5000`, matching `mkpasswd -m sha-512`.
- `-version` prints the binary version and exits.
- Cloud-config schema validation is always performed on both template-rendered content and final output using Canonical's schema from `https://raw.githubusercontent.com/canonical/cloud-init/main/cloudinit/config/schemas/schema-cloud-config-v1.json`.
- For air-gapped or test environments, set `BOCCE_SCHEMA_PATH` to a local schema JSON file.

Show CLI help and version:

```bash
./dist/bocce-darwin-arm64 -h
./dist/bocce-darwin-arm64 -version
```

## Build

```bash
make build-all
```

Artifacts are written to `dist/` for:

- macOS: `arm64`, `amd64`
- Linux: `arm64`, `amd64`
- Windows: `amd64`

Versioning:

- Build version is embedded at build time via linker flags.
- The value is derived from the most recent Git tag (for example `v0.1.1`).
- If no tag is found, version defaults to `dev`.

## Release publishing

- Pushing a tag matching `v*` (for example `v0.1.2`) triggers GitHub Actions release publishing.
- The workflow builds binaries and uploads `dist/*` as GitHub Release assets.
