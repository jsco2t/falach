mod common;

use falach_core::{
    EntryBuilder, MatchedField, NoRecoveryConfirmed, SearchOptions, Tag, Vault, VaultReadOnly,
};

use common::{fast_kdf, master, TestEnv};

struct SearchFixture {
    path: std::path::PathBuf,
    password: falach_core::MasterPassword,
    title_uuid: uuid::Uuid,
    notes_uuid: uuid::Uuid,
    username_uuid: uuid::Uuid,
    url_uuid: uuid::Uuid,
    tag_uuid: uuid::Uuid,
    recycled_uuid: uuid::Uuid,
}

#[test]
fn search_matches_fields_ranks_results_and_handles_wildcards() {
    let env = TestEnv::new();
    let fixture = create_search_fixture(&env);

    let vault = Vault::open(&fixture.path, &fixture.password, None).expect("open vault");
    let lower = vault
        .search(SearchOptions::new("example"))
        .expect("substring search");
    let upper = vault
        .search(SearchOptions::new("EXAMPLE"))
        .expect("case-insensitive substring search");

    assert_eq!(lower, upper);
    assert_eq!(lower.len(), 5);
    assert_eq!(lower[0].uuid, fixture.title_uuid);
    assert_eq!(lower[0].score, 8);
    assert!(lower[0].matched_fields.contains(&MatchedField::Title));
    assert!(lower
        .iter()
        .any(|result| result.uuid == fixture.username_uuid
            && result.matched_fields == vec![MatchedField::Username]));
    assert!(lower.iter().any(|result| result.uuid == fixture.url_uuid
        && result.matched_fields == vec![MatchedField::Url]));
    assert!(lower.iter().any(|result| result.uuid == fixture.tag_uuid
        && result.matched_fields == vec![MatchedField::Tags]));
    let notes_result = lower
        .iter()
        .find(|result| result.uuid == fixture.notes_uuid)
        .expect("notes match present");
    assert_eq!(notes_result.score, 1);
    assert_eq!(notes_result.matched_fields, vec![MatchedField::Notes]);
    assert!(!lower
        .iter()
        .any(|result| result.uuid == fixture.recycled_uuid));

    let including_recycled = vault
        .search(SearchOptions::new("example").include_recycled(true))
        .expect("include recycled search");
    assert!(including_recycled
        .iter()
        .any(|result| result.uuid == fixture.recycled_uuid));

    let exact = vault
        .search(SearchOptions::new("Example").wildcard(true))
        .expect("wildcard exact-match search");
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].uuid, fixture.title_uuid);

    let prefix = vault
        .search(SearchOptions::new("Example*").wildcard(true))
        .expect("wildcard prefix search");
    assert!(prefix
        .iter()
        .any(|result| result.uuid == fixture.title_uuid));

    let empty = vault
        .search(SearchOptions::new(""))
        .expect("empty query search");
    assert!(empty.is_empty());

    drop(vault);
    let readonly =
        VaultReadOnly::open(&fixture.path, &fixture.password, None).expect("open read-only vault");
    let readonly_results = readonly
        .search(SearchOptions::new("example"))
        .expect("read-only search");
    assert_eq!(readonly_results, lower);
}

fn create_search_fixture(env: &TestEnv) -> SearchFixture {
    let path = env.tempdir().join("search.kdbx");
    let password = master("search password");
    let mut vault = Vault::create(
        &path,
        &password,
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create vault");
    let root = vault.root_group_uuid();

    let title_uuid = vault
        .add_entry(root, EntryBuilder::credential("Example").build())
        .expect("add title match");
    let notes_uuid = vault
        .add_entry(
            root,
            EntryBuilder::credential("Notes Only")
                .notes("example appears in notes only")
                .build(),
        )
        .expect("add notes match");
    let username_uuid = vault
        .add_entry(
            root,
            EntryBuilder::credential("Username Only")
                .username("example-user")
                .build(),
        )
        .expect("add username match");
    let url_uuid = vault
        .add_entry(
            root,
            EntryBuilder::credential("Url Only")
                .url("https://example.test/login")
                .build(),
        )
        .expect("add url match");
    let tag_uuid = vault
        .add_entry(
            root,
            EntryBuilder::credential("Tag Only")
                .tag(Tag::new("example-tag"))
                .build(),
        )
        .expect("add tag match");
    let recycled_uuid = vault
        .add_entry(root, EntryBuilder::credential("Example Recycled").build())
        .expect("add recycled match");
    vault
        .delete_entry(recycled_uuid)
        .expect("delete to recycle bin");
    vault.save().expect("save vault");

    SearchFixture {
        path,
        password,
        title_uuid,
        notes_uuid,
        username_uuid,
        url_uuid,
        tag_uuid,
        recycled_uuid,
    }
}
