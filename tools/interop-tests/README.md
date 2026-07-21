# KeePassXC Interop Tests

These scripts verify the vault-core KDBX compatibility promise against a real
`keepassxc-cli` binary. KeePassXC is invoked as an external test tool only; it
is not linked into Falach and is not part of the Rust dependency graph.

Supported local version: KeePassXC CLI 2.7.x or newer in the 2.x line. The
current local baseline is 2.7.12.

Run from the repository root:

```sh
make interop
```

`make interop` builds the `falach-test-driver` helper and runs:

- `us_090_rust_to_kpxc.sh`: Falach-created vault opens in KeePassXC.
- `us_091_kpxc_to_rust.sh`: KeePassXC-created vault opens in Falach.
- `us_092_round_trip.sh`: alternating Falach/KeePassXC edits remain readable.

Each script uses `mktemp -d` and removes its working directory with an EXIT
trap. If a script fails, rerun it directly with `sh -x` to inspect the command
sequence:

```sh
FALACH_TEST_DRIVER=target/debug/falach-test-driver sh -x tools/interop-tests/us_090_rust_to_kpxc.sh
```
