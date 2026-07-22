use falach_api::dto::{
    AttachmentMeta, CustomFieldDto, CustomFieldInputDto, EntryDetail, EntryDraftDto, EntryEditDto,
    EntryKindDto, EntrySummary, GeneratedSecret, HistorySummary, KeyfileRef, S3ConfigDto,
    SearchModeDto, SearchOptionsDto, SearchScopeDto, TotpCode,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn assert_zeroize_on_drop<T: Zeroize + ZeroizeOnDrop>() {}

const MARKER: &str = "dto-marker-p@ss-S3CR3T";

fn assert_debug_values_are_redacted(values: impl IntoIterator<Item = String>) {
    for rendered in values {
        assert!(
            !rendered.contains(MARKER),
            "secret marker leaked from boundary Debug output: {rendered}"
        );
    }
}

#[test]
fn every_secret_bearing_boundary_type_zeroizes_on_drop() {
    assert_zeroize_on_drop::<EntryDraftDto>();
    assert_zeroize_on_drop::<EntryEditDto>();
    assert_zeroize_on_drop::<CustomFieldInputDto>();
    assert_zeroize_on_drop::<TotpCode>();
    assert_zeroize_on_drop::<GeneratedSecret>();
    assert_zeroize_on_drop::<S3ConfigDto>();
    assert_zeroize_on_drop::<KeyfileRef>();
}

#[test]
fn inbound_secret_types_redact_debug_output() {
    assert_debug_values_are_redacted([
        format!(
            "{:?}",
            EntryDraftDto {
                kind: EntryKindDto::Credential,
                title: MARKER.to_string(),
                username: Some(MARKER.to_string()),
                password: Some(MARKER.to_string()),
                url: Some(MARKER.to_string()),
                notes: Some(MARKER.to_string()),
                tags: vec![MARKER.to_string()],
                custom_fields: Vec::new(),
                totp_uri: Some(MARKER.to_string()),
            }
        ),
        format!(
            "{:?}",
            TotpCode {
                code: MARKER.to_string(),
                remaining_secs: 10,
                period: 30,
            }
        ),
        format!(
            "{:?}",
            GeneratedSecret {
                value: MARKER.to_string(),
                entropy_bits: 64.0,
            }
        ),
        format!(
            "{:?}",
            S3ConfigDto {
                bucket: "bucket".to_string(),
                key: "key".to_string(),
                region: "region".to_string(),
                endpoint: None,
                path_style: false,
                access_key_id: MARKER.to_string(),
                secret_access_key: MARKER.to_string(),
            }
        ),
        format!("{:?}", KeyfileRef::Bytes(MARKER.as_bytes().to_vec())),
        format!(
            "{:?}",
            EntryEditDto {
                title: Some(MARKER.to_string()),
                username: Some(MARKER.to_string()),
                password: Some(MARKER.to_string()),
                url: Some(MARKER.to_string()),
                notes: Some(MARKER.to_string()),
                tags: Some(vec![MARKER.to_string()]),
                custom_fields: None,
                totp_uri: Some(MARKER.to_string()),
            }
        ),
        format!(
            "{:?}",
            CustomFieldInputDto {
                name: MARKER.to_string(),
                value: MARKER.to_string(),
                protected: true,
            }
        ),
    ]);
}

#[test]
fn entry_and_search_outputs_redact_user_content_in_debug_output() {
    assert_debug_values_are_redacted([
        format!(
            "{:?}",
            EntrySummary {
                uuid: "uuid".to_string(),
                title: MARKER.to_string(),
                username: MARKER.to_string(),
                url: MARKER.to_string(),
                kind: EntryKindDto::Credential,
                has_totp: false,
                has_attachments: false,
                is_expired: false,
                group_uuid: "group".to_string(),
                tags: vec![MARKER.to_string()],
            }
        ),
        format!(
            "{:?}",
            SearchOptionsDto {
                query: MARKER.to_string(),
                mode: SearchModeDto::Substring,
                scope: SearchScopeDto::Tag(MARKER.to_string()),
                include_recycled: false,
            }
        ),
        format!(
            "{:?}",
            EntryDetail {
                uuid: "uuid".to_string(),
                title: MARKER.to_string(),
                username: MARKER.to_string(),
                has_password: true,
                url: MARKER.to_string(),
                notes: MARKER.to_string(),
                kind: EntryKindDto::Credential,
                tags: vec![MARKER.to_string()],
                custom_fields: Vec::new(),
                attachments: vec![AttachmentMeta {
                    name: MARKER.to_string(),
                    size_bytes: 1,
                }],
                creation_time: None,
                last_modification_time: None,
                expiry_time: None,
            }
        ),
        format!(
            "{:?}",
            HistorySummary {
                title: MARKER.to_string(),
                username: MARKER.to_string(),
                last_modification_time: None,
            }
        ),
        format!(
            "{:?}",
            CustomFieldDto {
                name: MARKER.to_string(),
                is_protected: true,
            }
        ),
        format!(
            "{:?}",
            AttachmentMeta {
                name: MARKER.to_string(),
                size_bytes: 1,
            }
        ),
    ]);
}

#[test]
fn explicit_zeroize_clears_entry_input_secrets() {
    let mut draft = EntryDraftDto {
        kind: EntryKindDto::Credential,
        title: "title".to_string(),
        username: Some("username".to_string()),
        password: Some("password".to_string()),
        url: Some("url".to_string()),
        notes: Some("notes".to_string()),
        tags: vec!["tag".to_string()],
        custom_fields: vec![CustomFieldInputDto {
            name: "name".to_string(),
            value: "value".to_string(),
            protected: true,
        }],
        totp_uri: Some("otpauth://secret".to_string()),
    };
    draft.zeroize();
    assert!(draft.title.is_empty());
    assert!(draft.username.as_deref().is_none_or(str::is_empty));
    assert!(draft.password.as_deref().is_none_or(str::is_empty));
    assert!(draft.url.as_deref().is_none_or(str::is_empty));
    assert!(draft.notes.as_deref().is_none_or(str::is_empty));
    assert!(draft.tags.is_empty());
    assert!(draft.custom_fields.is_empty());
    assert!(draft.totp_uri.as_deref().is_none_or(str::is_empty));

    let mut edit = EntryEditDto {
        title: Some("title".to_string()),
        username: Some("username".to_string()),
        password: Some("password".to_string()),
        url: Some("url".to_string()),
        notes: Some("notes".to_string()),
        tags: Some(vec!["tag".to_string()]),
        custom_fields: Some(vec![CustomFieldInputDto {
            name: "name".to_string(),
            value: "value".to_string(),
            protected: true,
        }]),
        totp_uri: Some("otpauth://secret".to_string()),
    };
    edit.zeroize();
    assert!(edit.title.as_deref().is_none_or(str::is_empty));
    assert!(edit.username.as_deref().is_none_or(str::is_empty));
    assert!(edit.password.as_deref().is_none_or(str::is_empty));
    assert!(edit.url.as_deref().is_none_or(str::is_empty));
    assert!(edit.notes.as_deref().is_none_or(str::is_empty));
    assert!(edit.tags.as_ref().is_none_or(Vec::is_empty));
    assert!(edit.custom_fields.as_ref().is_none_or(Vec::is_empty));
    assert!(edit.totp_uri.as_deref().is_none_or(str::is_empty));

    let mut field = CustomFieldInputDto {
        name: "name".to_string(),
        value: "value".to_string(),
        protected: true,
    };
    field.zeroize();
    assert!(field.name.is_empty());
    assert!(field.value.is_empty());
    assert!(!field.protected);
}

#[test]
fn explicit_zeroize_clears_generated_keyfile_totp_and_s3_secrets() {
    let mut generated = GeneratedSecret {
        value: "secret".to_string(),
        entropy_bits: 64.0,
    };
    generated.zeroize();
    assert!(generated.value.is_empty());
    assert!(generated.entropy_bits.abs() < f64::EPSILON);

    let mut keyfile = KeyfileRef::Bytes(vec![1, 2, 3, 4]);
    keyfile.zeroize();
    match keyfile {
        KeyfileRef::Bytes(ref bytes) => assert!(bytes.iter().all(|byte| *byte == 0)),
        KeyfileRef::Path(_) => panic!("expected an in-memory keyfile"),
    }

    let mut totp = TotpCode {
        code: "123456".to_string(),
        remaining_secs: 10,
        period: 30,
    };
    totp.zeroize();
    assert!(totp.code.is_empty());
    assert_eq!(totp.remaining_secs, 0);
    assert_eq!(totp.period, 0);

    let mut s3 = S3ConfigDto {
        bucket: "bucket".to_string(),
        key: "key".to_string(),
        region: "region".to_string(),
        endpoint: Some("endpoint".to_string()),
        path_style: true,
        access_key_id: "access-key".to_string(),
        secret_access_key: "secret-key".to_string(),
    };
    s3.zeroize();
    assert!(s3.bucket.is_empty());
    assert!(s3.key.is_empty());
    assert!(s3.region.is_empty());
    assert!(s3.endpoint.as_deref().is_none_or(str::is_empty));
    assert!(!s3.path_style);
    assert!(s3.access_key_id.is_empty());
    assert!(s3.secret_access_key.is_empty());
}
