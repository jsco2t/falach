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

    match mode.as_str() {
        "save" => {
            let password = args
                .next()
                .expect("password arg")
                .into_string()
                .expect("password utf8");
            let title = args
                .next()
                .expect("entry title arg")
                .into_string()
                .expect("entry title utf8");

            let mut vault = Vault::open(&path, &MasterPassword::new(password), None)
                .expect("open vault for save");
            vault.database_mut().root_mut().add_entry().edit(|entry| {
                entry.set_unprotected(fields::TITLE, &title);
            });
            vault.save().expect("save vault");
        }
        "change-password" => {
            let old = args
                .next()
                .expect("old password arg")
                .into_string()
                .expect("old password utf8");
            let new = args
                .next()
                .expect("new password arg")
                .into_string()
                .expect("new password utf8");

            let old = MasterPassword::new(old);
            let new = MasterPassword::new(new);
            let mut vault = Vault::open(&path, &old, None).expect("open vault for password change");
            vault
                .change_master_password(&old, &new)
                .expect("change master password");
        }
        other => panic!("unknown mode: {other}"),
    }
}
