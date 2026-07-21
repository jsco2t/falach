mod common;

use falach_core::{EntryBuilder, NoRecoveryConfirmed, Totp, Vault, VaultError, VaultReadOnly};

use common::{fast_kdf, master, TestEnv};

const RFC_URI_SHA1: &str =
    "otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=8&period=30";

#[test]
fn totp_entry_round_trips_through_save_and_reopen() {
    let env = TestEnv::new();
    let path = env.tempdir().join("totp.kdbx");
    let password = master("totp password");

    let uuid = {
        let mut vault = Vault::create(
            &path,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create vault");
        let root = vault.root_group_uuid();
        let uuid = vault
            .add_entry(
                root,
                EntryBuilder::totp("Example", RFC_URI_SHA1)
                    .expect("RFC 6238 URI parses")
                    .build(),
            )
            .expect("add TOTP entry");
        vault.save().expect("save vault");
        uuid
    };

    let vault = Vault::open(&path, &password, None).expect("reopen vault");
    let view = vault.get_entry(uuid).expect("entry exists after reopen");
    assert_eq!(view.title(), "Example");
    assert_eq!(
        view.custom_field("otp"),
        Some(RFC_URI_SHA1),
        "otp custom field round-trips"
    );

    // Verify codes match RFC 6238 at the canonical timestamps regardless of
    // current system time — Totp::code_at is deterministic.
    let totp = Totp::from_otpauth_uri(view.custom_field("otp").expect("otp field"))
        .expect("stored URI parses");
    assert_eq!(totp.code_at(59), "94287082");
    assert_eq!(totp.code_at(1_111_111_109), "07081804");
    assert_eq!(totp.code_at(1_234_567_890), "89005924");
}

#[test]
fn totp_method_matches_totp_code_at_for_current_time() {
    let env = TestEnv::new();
    let path = env.tempdir().join("totp-current.kdbx");
    let password = master("totp password");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    let root = vault.root_group_uuid();
    let uuid = vault
        .add_entry(
            root,
            EntryBuilder::totp("Example", RFC_URI_SHA1)
                .expect("RFC URI parses")
                .build(),
        )
        .expect("add TOTP entry");

    // Capture `now` ourselves and compare against the deterministic
    // `Totp::code_at(now)` (and the adjacent second to cover the boundary
    // race). Asserting only on string shape would let a regression that
    // always returns "00000000" pass.
    let totp = Totp::from_otpauth_uri(RFC_URI_SHA1).expect("RFC URI parses");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock at-or-after epoch")
        .as_secs();

    let (code, remaining) = vault.totp(uuid).expect("totp current code");

    let expected_now = totp.code_at(now);
    let expected_next = totp.code_at(now + 1);
    assert!(
        code == expected_now || code == expected_next,
        "Vault::totp produced {code}; expected {expected_now} or {expected_next}"
    );
    assert!(
        (1..=30).contains(&remaining),
        "remaining within period: {remaining}"
    );
}

#[test]
fn totp_method_on_non_totp_entry_yields_entry_has_no_totp() {
    let env = TestEnv::new();
    let path = env.tempdir().join("totp-missing.kdbx");
    let password = master("totp password");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    let root = vault.root_group_uuid();
    let uuid = vault
        .add_entry(
            root,
            EntryBuilder::credential("Plain")
                .username("alice")
                .password("secret")
                .build(),
        )
        .expect("add credential entry");

    let err = vault
        .totp(uuid)
        .expect_err("non-TOTP entry has no otp field");
    assert!(matches!(err, VaultError::EntryHasNoTotp { uuid: e } if e == uuid));
}

#[test]
fn totp_method_on_unknown_uuid_yields_entry_not_found() {
    let env = TestEnv::new();
    let path = env.tempdir().join("totp-unknown.kdbx");
    let password = master("totp password");
    let vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");

    let bogus = uuid::Uuid::new_v4();
    let err = vault.totp(bogus).expect_err("missing uuid should fail");
    assert!(matches!(err, VaultError::EntryNotFound { uuid: u } if u == bogus));
}

#[test]
fn vault_read_only_totp_matches_expected_code_for_current_window() {
    let env = TestEnv::new();
    let path = env.tempdir().join("totp-readonly.kdbx");
    let password = master("totp password");
    let uuid = {
        let mut vault = Vault::create(
            &path,
            &password,
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create vault");
        let root = vault.root_group_uuid();
        let uuid = vault
            .add_entry(
                root,
                EntryBuilder::totp("Example", RFC_URI_SHA1)
                    .expect("RFC URI parses")
                    .build(),
            )
            .expect("add TOTP entry");
        vault.save().expect("save vault");
        uuid
    };

    // Vault::totp / VaultReadOnly::totp use SystemTime::now() internally,
    // which we cannot pin. Instead, capture `now` ourselves, derive the
    // expected code from the stored URI via `Totp::code_at(now)`, then call
    // the read-only surface and assert the codes match — both for the
    // current window and (if a second boundary slips through between
    // captures) for the immediately neighboring window. This proves the
    // read-only surface delegates to the same code generator rather than
    // diverging silently.
    let read_only = VaultReadOnly::open(&path, &password, None).expect("open read-only");
    let totp = Totp::from_otpauth_uri(RFC_URI_SHA1).expect("RFC URI parses");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock at-or-after epoch")
        .as_secs();

    let (code, _) = read_only.totp(uuid).expect("totp via read-only");

    let expected_now = totp.code_at(now);
    let expected_next = totp.code_at(now + 1);
    assert!(
        code == expected_now || code == expected_next,
        "read-only TOTP {code} matches neither the current ({expected_now}) nor next-second \
         ({expected_next}) window-boundary expectation"
    );
}
