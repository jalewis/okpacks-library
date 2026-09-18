# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting on this repository: **Security → Report a
vulnerability** (Security Advisories). If that is unavailable, contact a maintainer through the
repository's listed contact rather than a public channel. Please include the affected file/pack,
a description, and reproduction steps; we'll acknowledge and coordinate a fix and disclosure.

## What this repository is (and isn't)

okpacks-library ships **pack definitions only** — `schema.yaml`, `CLAUDE.md`, cron/importer
scripts, feed lists, `pack.yaml`, conformance suites, and an **empty** `wiki/` scaffold. It ships
**no secrets and no compiled knowledge content**. In scope for security reports: the importer
scripts, validators, conformance/projectors, and the Docker Compose / `.env.example` deployment
examples. Out of scope: the **generated vault content** a deployment compiles from the feeds you
configure — that is the deploying operator's responsibility (see [`NOTICE`](NOTICE)).

## Do not commit secrets or runtime data

When contributing a pack or a fix, never commit (see also [`CONTRIBUTING.md`](CONTRIBUTING.md)):

- `.env` files or any tokens / API keys / credentials,
- `.hermes-data/` or other deployment runtime state,
- raw ingested data or caches,
- populated/compiled `wiki/` knowledge pages.

`.gitignore` excludes these, but double-check your diff before opening a PR. Generated vault
content may contain third-party, licensed, or sensitivity-marked (TLP) material — do not publish
it here; only the empty scaffold belongs in this repo.

## Deployment hardening

- The MCP query surface (`OKENGINE_MCP_TOKEN`) ships **blank** in `.env.example`. **Generate a
  real secret** (e.g. `openssl rand -hex 32`) before setting `OKENGINE_BIND=0.0.0.0` — never
  expose the MCP with a shared or default token. Keep it bound to loopback (`127.0.0.1`)
  otherwise.
- Importers fetch public datasets from upstream over HTTPS at deploy time; review
  [`NOTICE`](NOTICE) for the sources and their terms.
