use std::time::{Duration, Instant};

use falach_core::{fields, KdfParams, MasterPassword, NoRecoveryConfirmed, Vault};

fn main() {
    let dir = tempfile::TempDir::new().expect("create benchmark tempdir");
    let path = dir.path().join("bench-500.kdbx");
    let master = MasterPassword::new("benchmark-password".to_string());

    {
        let mut vault = Vault::create(
            &path,
            &master,
            None,
            KdfParams::default(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create benchmark vault");

        for i in 0..500 {
            vault.database_mut().root_mut().add_entry().edit(|entry| {
                entry.set_unprotected(fields::TITLE, format!("Entry {i:03}"));
                entry.set_unprotected(fields::USERNAME, format!("user-{i}@example.com"));
                entry.set_protected(fields::PASSWORD, format!("password-{i}"));
            });
        }
        vault.save().expect("save benchmark vault");
    }

    let mut samples = Vec::new();
    for _ in 0..10 {
        let started = Instant::now();
        let vault = Vault::open(&path, &master, None).expect("open benchmark vault");
        std::hint::black_box(vault.database().root().entry_by_name("Entry 250"));
        drop(vault);
        samples.push(started.elapsed());
    }

    samples.sort();
    let median = samples[samples.len() / 2];
    let max = samples.last().copied().unwrap_or(Duration::ZERO);

    println!(
        "vault_open_500_entries_default_kdf_median_ms={:.2}",
        ms(median)
    );
    println!("vault_open_500_entries_default_kdf_max_ms={:.2}", ms(max));
    println!("samples_ms={}", sample_list(&samples));
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn sample_list(samples: &[Duration]) -> String {
    samples
        .iter()
        .map(|sample| format!("{:.2}", ms(*sample)))
        .collect::<Vec<_>>()
        .join(",")
}
