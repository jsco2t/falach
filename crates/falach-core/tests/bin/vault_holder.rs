use std::path::PathBuf;

use falach_core::{fields, MasterPassword, Vault};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let mode = args
        .next()
        .expect("mode arg")
        .into_string()
        .expect("mode utf8");
    let path = PathBuf::from(args.next().expect("vault path arg"));
    let password = args
        .next()
        .expect("password arg")
        .into_string()
        .expect("password utf8");
    let held_signal = PathBuf::from(args.next().expect("held signal arg"));
    let release_signal = PathBuf::from(args.next().expect("release signal arg"));

    let mut vault =
        Vault::open(&path, &MasterPassword::new(password), None).expect("open vault and lock it");

    if mode == "write-hold" {
        let title = args
            .next()
            .expect("entry title arg")
            .into_string()
            .expect("entry title utf8");
        vault.database_mut().root_mut().add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, &title);
        });
        vault.save().expect("save held write");
    } else if mode != "hold" {
        panic!("unknown mode: {mode}");
    }

    std::fs::write(&held_signal, b"held").expect("write held signal");

    while !release_signal.exists() {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    std::hint::black_box(vault.path());
}
