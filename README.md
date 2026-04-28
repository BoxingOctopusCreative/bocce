# Bocce

## Introduction

Bocce is a tool used internally by Boxing Octopus Creative to generate cloud-init user data files for provisioning new DigitalOcean Droplets.

## Why "Bocce"?

Honestly, my IDE autocompleted `boc-do-user-data` to "Bocce", I thought it was funny, and I'm part Italian. So I kept it. It's not that deep.

## Usage

Render the cloud-config template with file-backed SSH key and CA cert, and a locally generated `mkpasswd -m sha-512` compatible password hash:

```bash
go run . \
  -ssh-key-path ~/.ssh/id_ed25519.pub \
  -ca-cert-path ./aiven_ca.crt \
  -starship-preset nerd-font-symbols \
  -password 'change-me' \
  -outputPath .
```

Notes:

- `-password` and `-ca-cert-path` are required.
- `-ssh-key-path` is optional; if omitted, a new no-passphrase ed25519 keypair is generated in `-outputPath`.
- `-template` defaults to `templates/user-data.yaml.tmpl`.
- `-outputPath` is optional; defaults to the current directory and writes `user-data.yaml`.
- `-salt` is optional; if omitted, a random salt is generated.
- `-rounds` defaults to `5000`, matching `mkpasswd -m sha-512`.
- Cloud-config schema validation is always performed on both template-rendered content and final output using Canonical's schema from `https://raw.githubusercontent.com/canonical/cloud-init/main/cloudinit/config/schemas/schema-cloud-config-v1.json`.
- For air-gapped or test environments, set `BOCCE_SCHEMA_PATH` to a local schema JSON file.

## Build

```bash
make build-all
```

Artifacts are written to `dist/` for:

- macOS: `arm64`, `amd64`
- Linux: `arm64`, `amd64`
