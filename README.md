# ReviewedProof proof verifier

Independent MIT-licensed source for ReviewedProof's Python CLI and offline
HTML/JavaScript verifier. Both implementations validate signatures, RFC 3161
timestamps, trust policy, lifecycle events, completion, revocation, supersession,
expiry and optional local artefact matches.

This repository contains verifier source only. It contains no ReviewedProof
application runtime, credentials, private keys, hosted service, telemetry or
network client. The browser verifier runs from `file://` and its CSP blocks
network connections.

## Python CLI

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --frozen
uv run reviewedproof --help
uv run reviewedproof verify RECEIPT.rproof   --trust-store trust-store.json
```

Development or staging evidence requires explicit opt-in:

```bash
uv run reviewedproof verify RECEIPT.rproof   --trust-store trust-store.json   --allow-non-production
```

## Offline browser verifier

Requires Node 24.7.0 and pnpm 10.15.1 through Corepack. Supply a public trust
store explicitly; the build embeds its exact bytes and never generates trust.

```bash
corepack pnpm install --frozen-lockfile
OFFLINE_VERIFIER_TRUST_STORE=/absolute/path/to/trust-store.json   corepack pnpm build
```

Open `apps/offline-verifier/dist/index.html` directly. No server is required.
Build output is exactly `index.html`, `assets/verifier.css` and
`assets/verifier.js`. Release signing and downloadable ZIP assembly happen in
ReviewedProof release infrastructure and are outside this source build.

All resolved dependency versions and hashes are pinned in `uv.lock` and
`pnpm-lock.yaml`. Third-party code and fonts retain their own licences; see
`THIRD-PARTY-NOTICES.txt`.
