# falach-sync

Per-vault synchronization for [Falach](../../README.md) over **S3-compatible
object storage**. The vault is stored as a single opaque, client-encrypted
KDBX object in a bucket you own (AWS S3, MinIO, Cloudflare R2, Backblaze B2,
Wasabi, Garage, SeaweedFS, …); divergence between devices is resolved by an
entry-level three-way merge that never loses data.

This crate owns PRD §6.5 v1.1 (FR-040..048). It sits **above** `falach-core`:
it consumes `Vault` / `Database` but core never depends on it, so the HTTP/TLS
stack stays out of every non-syncing consumer's dependency tree.

## What it does

- **Configure** a per-vault S3 target (`Sync::configure_remote`) — bucket, key,
  endpoint, region, addressing style, and a credential source.
- **Sync** on demand (`Sync::sync_now`) via a four-state truth table over
  *(did the remote change? did the local change?)*:
  - neither → `AlreadyInSync` (a single HEAD)
  - local only → `Pushed` (conditional PUT)
  - remote only → `FastReplaced` (conditional GET, replace local)
  - both → `Merged` (snapshot `.kdbx.bak` → fetch → entry-UUID merge → save →
    conditional PUT, retrying on a concurrent-write `412`)
- **Never lose data**: the loser of a same-entry collision is preserved as a
  KDBX history entry under the same UUID; a pre-merge `.kdbx.bak` is taken
  before any merge work (FR-048).
- **Degrade gracefully**: any network/auth/precondition failure leaves the
  local vault fully usable with a clear `SyncError` (FR-044).

## Configuring a vault

```rust,ignore
use falach_sync::{CredentialSource, S3Config, Sync, SyncOptions};

let s3 = S3Config::new(
    "my-bucket".to_string(),
    "work.kdbx".to_string(),
    "us-east-1".to_string(),
    CredentialSource::EnvVars { prefix: "MY_".to_string() },
);
Sync::configure_remote(&mut registry, "work", s3, &password)?;
// later, after opening the vault:
Sync::sync_now(&mut vault, "work", &mut registry, &password, None, SyncOptions::default())?;
```

The configuration persists to `vaults.toml` under `[vault.sync.s3]` (vaults are
a `[[vault]]` array of tables).
See [`kb/vault-config-schema.md`](../../../notebook/projects/falach/kb/vault-config-schema.md)
for the on-disk schema and the
[operator guide](../../../notebook/projects/falach/kb/s3-sync-operator-guide.md)
for bucket-setup walkthroughs (AWS, MinIO, IAM roles, and the four credential
sources).

### Credential sources (FR-045)

Each vault declares **exactly one** source; there is no implicit shell-env
fallback (that would let a personal vault authenticate with work credentials):

| Source | Use |
| ------ | --- |
| `RstCred1` | Static key + secret, encrypted at rest in `vaults.toml` (Argon2id + ChaCha20-Poly1305). Works everywhere; requires the master password to sync. |
| `AwsProfile` | A *named* profile from `~/.aws/credentials`. Named explicitly per vault — never `AWS_PROFILE` from the shell. |
| `EnvVars` | `<PREFIX>AWS_ACCESS_KEY_ID` / `<PREFIX>AWS_SECRET_ACCESS_KEY`. The prefix must be non-empty. |
| `IamInstanceRole` | EC2/ECS instance metadata (IMDS). For headless servers with an instance profile. |

## Design (the seven ADRs)

Full rationale in the feature [`design.md`](../../../notebook/projects/falach/features/s3-sync/plans/design.md);
the supply-chain analysis is in
[`kb/s3-sync-library.md`](../../../notebook/projects/falach/kb/s3-sync-library.md).

1. **ADR-1 — hand-rolled SigV4 + `ureq`.** ~400 LoC of in-repo SigV4 (validated
   against AWS's published vectors) over `ureq`/`rustls`/`ring`, *not* the AWS
   SDK. The SDK needs Rust 1.91 (workspace is 1.89) and drags ~60 transitive
   crates; CLAUDE.md prefers owning a small, well-specified algorithm.
2. **ADR-2 — RST-CRED-1 is the credential floor.** OS-keychain integration is a
   Phase-1 follow-on; the `CredentialSource` enum is `#[non_exhaustive]` so
   adding it later is non-breaking.
3. **ADR-3 — four-method `SyncTransport` trait.** `head` / `fetch_if_changed` /
   `put_conditional`, content-addressable via an opaque `ObjectVersion`. No
   git-shaped `merge_base` / `read_vault_at`; future transports (NFS, WebDAV)
   map cleanly.
4. **ADR-4 — `Vault::save` stays sync-ignorant.** Frontends call `sync_now`
   explicitly; sync logic never leaks into `vault-core`.
5. **ADR-5 — per-backend `If-Match` probe.** A sentinel-key PUT with a bogus
   `If-Match` classifies the backend as `Supported` (rejects → 412/404) or
   `Degraded` (silently accepts → 2xx); the result is cached in `vaults.toml`.
6. **ADR-6 — registry-side target uniqueness.** Two vaults pointed at the same
   `(endpoint, bucket, key)` is rejected at `configure_remote`
   (`SyncError::DuplicateTarget`).
7. **ADR-7 — `User-Agent: falach-sync/<crate-version>`.**

## Backends

A `MemoryTransport` (behind the `test-helpers` feature) backs the fast,
network-free scenario tests. Live-wire tests run against a pinned MinIO
container (`make minio-up && make test-s3-integration`); MinIO is the *strict*
SigV4 implementation that catches encoding bugs AWS's permissive parser
accepts. Per-backend support is tracked in
[`docs/backend-conformance.md`](docs/backend-conformance.md).

## Testing

- `cargo test -p falach-sync` — unit + `MemoryTransport` scenario (US-040..046)
  + fault-injection (`.kdbx.bak` recovery) + the SigV4 corpus. No network.
- `make test-s3-integration` — `#[ignore]`-gated MinIO live-wire tests
  (requires Docker + `mc`; see [`tools/sync-tests/README.md`](../../tools/sync-tests/README.md)).
- `make interop-sync` — KeePassXC round-trip of a merged vault.

## License

MIT (workspace policy: permissive licenses only; no copyleft, no `webpki-roots`).
