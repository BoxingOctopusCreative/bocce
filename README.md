# Bocchi

## Introduction

Bocchi is a tool used internally by Boxing Octopus Creative to generate cloud-init user data files for provisioning new DigitalOcean Droplets.

## Why "Bocchi"?

Honestly, my IDE autocompleted `boc-do-user-data` to "bocchi", I thought it was funny, and I'm part Italian. So I kept it. It's not that deep.

## Usage

Render the cloud-config template with file-backed SSH key and CA cert, and a locally generated `mkpasswd -m sha-512` compatible password hash:

```bash
go run . \
  -template user-data.yaml.tmpl \
  -ssh-key-path ~/.ssh/id_ed25519.pub \
  -ca-cert-path ./aiven_ca.crt \
  -starship-preset nerd-font-symbols \
  -password 'change-me' \
  -output user-data.yaml
```

Notes:

- `-password`, `-ssh-key-path`, and `-ca-cert-path` are required.
- `-output` is optional; when omitted, rendered YAML is printed to stdout.
- `-salt` is optional; if omitted, a random salt is generated.
- `-rounds` defaults to `5000`, matching `mkpasswd -m sha-512`.

## Build

```bash
make build-all
```

Artifacts are written to `dist/` for:

- macOS: `arm64`, `amd64`
- Linux: `arm64`, `amd64`
