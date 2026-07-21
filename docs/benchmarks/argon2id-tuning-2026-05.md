# Argon2id Tuning - 2026-05

Benchmark command:

```sh
make bench
```

Benchmark target: `Vault::open` on a KDBX4 vault containing 500 entries, using
`KdfParams::default()` (`memory_kib = 65_536`, `iterations = 3`,
`parallelism = 2`).

Local result on 2026-05-20:

| Host | Median | Max | Samples |
| ---- | ------ | --- | ------- |
| Linux x86_64 local workstation | 102.22 ms | 106.90 ms | 98.98, 100.61, 100.67, 100.80, 101.78, 102.22, 103.12, 103.29, 104.75, 106.90 |

Decision: keep the existing defaults. They are comfortably below the NFR-001
target of <500 ms for vault open with <=500 entries on this hardware.

Gap: M1 hardware was not available in this session. The benchmark is wired into
CI informationally through `make bench`; strict CI gating is intentionally
deferred because hosted runner hardware varies too much for a stable latency
threshold.
