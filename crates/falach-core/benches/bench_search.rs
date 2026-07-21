use std::time::{Duration, Instant};

use falach_core::{fields, fuzzy_match, Database, SearchOptions, Vault};

const SAMPLE_COUNT: usize = 30;

fn main() {
    let mut db = Database::new();
    populate_with_n_entries(&mut db, 5_000);
    let fixture = SearchBenchFixture::new(db);

    let substring_samples = sample_search(&fixture.vault, || SearchOptions::new("5"));
    print_summary("bench_search_5k", &substring_samples);

    let wildcard_samples = sample_search(&fixture.vault, || {
        SearchOptions::new("Entry-5*").wildcard(true)
    });
    print_summary("bench_search_5k_wildcard", &wildcard_samples);

    // Fuzzy is the most expensive mode (per-field O(n·m) DP + traceback). The
    // gate (tools/bench/bench_search_gate.sh) applies the dual OQ-2 threshold
    // to this line: WARN above 10ms, FAIL above the 50ms NFR-002 budget.
    let fuzzy_samples = sample_search(&fixture.vault, || SearchOptions::fuzzy("entry"));
    print_summary("bench_search_5k_fuzzy", &fuzzy_samples);

    // The 10ms soft threshold measures only the matcher over 5,000 candidate
    // strings. Vault traversal, field extraction, ranking, and result assembly
    // remain covered by the separate end-to-end fuzzy hard gate above.
    let matcher_candidates: Vec<String> = (1..=5_000)
        .map(|index| format!("Entry-{index} user{index} https://entry-{index}.example generated"))
        .collect();
    let matcher_samples = sample_matcher(&matcher_candidates, "entry");
    print_summary("bench_fuzzy_matcher_5k", &matcher_samples);
}

fn sample_matcher(candidates: &[String], query: &str) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(SAMPLE_COUNT);
    for _ in 0..SAMPLE_COUNT {
        let started = Instant::now();
        for candidate in candidates {
            std::hint::black_box(fuzzy_match(query, candidate));
        }
        samples.push(started.elapsed());
    }
    samples.sort();
    samples
}

fn sample_search<F>(vault: &Vault, mut options: F) -> Vec<Duration>
where
    F: FnMut() -> SearchOptions,
{
    let mut samples = Vec::with_capacity(SAMPLE_COUNT);
    for _ in 0..SAMPLE_COUNT {
        let started = Instant::now();
        let results = vault.search(options()).expect("search should succeed");
        std::hint::black_box(results);
        samples.push(started.elapsed());
    }
    samples.sort();
    samples
}

fn print_summary(name: &str, samples: &[Duration]) {
    let median = samples[samples.len() / 2];
    let max = samples.last().copied().unwrap_or(Duration::ZERO);

    println!("{name}_median_ms={:.2}", ms(median));
    println!("{name}_max_ms={:.2}", ms(max));
    println!("{name}_samples_ms={}", sample_list(samples));
}

fn populate_with_n_entries(db: &mut Database, n: usize) {
    for index in 1..=n {
        db.root_mut().add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, format!("Entry-{index}"));
            entry.set_unprotected(fields::USERNAME, format!("user{index}"));
            entry.set_protected(fields::PASSWORD, format!("password-{index}"));
            entry.set_unprotected(fields::URL, format!("https://entry-{index}.example"));
            entry.set_unprotected(fields::NOTES, format!("Generated entry {index}"));
            entry.tags.push("generated".to_string());
        });
    }
}

struct SearchBenchFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

impl SearchBenchFixture {
    fn new(database: Database) -> Self {
        let dir = tempfile::TempDir::new().expect("create benchmark tempdir");
        let path = dir.path().join("bench-search.kdbx");
        let master = falach_core::MasterPassword::new("benchmark-password".to_string());
        let mut vault = Vault::create(
            &path,
            &master,
            None,
            falach_core::KdfParams::default(),
            falach_core::NoRecoveryConfirmed::yes(),
        )
        .expect("create benchmark vault");
        *vault.database_mut() = database;
        Self { _dir: dir, vault }
    }
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
