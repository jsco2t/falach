//! `falach entry {add, get, edit, rm, list, search}` dispatcher.
//!
//! Each verb prompts for the master password (via
//! `crate::prompt::master_password`), opens the vault (read-write for
//! mutating verbs; read-only for `get` / `list` / `search`), calls the
//! entry-management surface, builds the per-verb view struct and writes
//! it via `crate::format::OutputFormatter`.
//!
//! ## `--copy` clipboard hand-off
//!
//! `entry get --copy` hands the password to `falach-security`'s
//! `falach_security::Clipboard::copy_with_autoclear`. The CLI blocks on
//! `falach_security::AutoClearGuard::wait_for_clear` before exit so
//! the auto-clear timer actually fires on Wayland (design §2.5 + §3.9).
//!
//! ## Group resolution
//!
//! `falach-core::EntryView` does not expose the parent group; we walk
//! `vault.database().iter_all_entries()` to find the entry's `EntryRef`
//! and read `parent().name`. The cost is O(N) per get/list — fine at
//! Phase 0 vault sizes (≤5,000 entries per NFR-002). When tighter,
//! entry-management can add a `group_name()` accessor.

use chrono::Utc;
use falach_core::{
    EntryBuilder, EntryKind, EntryView, Keyfile, MatchedField, RegisteredVault, SearchMode,
    SearchOptions, SearchScope, Vault, VaultError, VaultReadOnly, VaultRegistry,
};
use falach_genpw::{CharSet, PasswordBuilder};

use crate::agent::NoAgentClient;
use crate::cli::{
    Cli, EntryAddArgs, EntryArgs, EntryEditArgs, EntryGetArgs, EntryListArgs, EntryRmArgs,
    EntrySearchArgs, EntryVerb, PasswordClassFlags, SearchModeArg,
};
use crate::commands::{arm_clipboard, resolve_paths, write_success};
use crate::exit::CliExit;
use crate::prompt::{master_password, read_password_no_echo, PromptOpts};
use crate::views::entry::{
    EntryAddView, EntryEditView, EntryGetView, EntryListItem, EntryListView, EntryRmView,
    EntrySearchItem, EntrySearchView, FieldIndices,
};

/// Owned row buffered during `list`/`search` so the resulting view
/// items can borrow `&str` slices into the same memory. Defining it at
/// module scope (rather than inside each function) keeps clippy's
/// "items after statements" lint happy.
struct EntryRow {
    uuid: uuid::Uuid,
    title: String,
    group: String,
    tags: Vec<String>,
    expired: bool,
}

/// Owned search-result row: an [`EntryRow`] plus the fuzzy ranking `score` and
/// matched character positions (`matched_indices`) the JSON view emits.
struct SearchRowOwned {
    row: EntryRow,
    score: u32,
    matched_indices: Vec<FieldIndices>,
}

/// Phase 3 entry point — dispatches to the verb handler.
///
/// # Errors
///
/// Any [`CliExit`] returned by the per-verb handlers.
pub fn run(cli: &Cli, args: &EntryArgs) -> Result<(), CliExit> {
    match &args.verb {
        Some(EntryVerb::Add(a)) => run_add(cli, a),
        Some(EntryVerb::Get(a)) => run_get(cli, a),
        Some(EntryVerb::Edit(a)) => run_edit(cli, a),
        Some(EntryVerb::Rm(a)) => run_rm(cli, a),
        Some(EntryVerb::List(a)) => run_list(cli, a),
        Some(EntryVerb::Search(a)) => run_search(cli, a),
        None => Err(CliExit::UserError(
            "missing subcommand verb (try `falach entry --help`)".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------

fn run_add(cli: &Cli, args: &EntryAddArgs) -> Result<(), CliExit> {
    let record = load_registry_record(cli, &args.vault)?;
    let master = prompt_for_vault(&args.vault)?;
    let keyfile = record.keyfile_path.clone().map(Keyfile::Path);

    // Decide the entry password BEFORE opening the vault so a stdin
    // failure doesn't leave the file locked with no committed change.
    let password_value = resolve_add_password(args)?;

    let mut vault = Vault::open(&record.path, &master, keyfile.as_ref()).map_err(CliExit::from)?;
    let root = vault.root_group_uuid();

    let mut builder = EntryBuilder::credential(&args.title);
    if let Some(u) = args.username.as_deref() {
        builder = builder.username(u);
    }
    if let Some(u) = args.url.as_deref() {
        builder = builder.url(u);
    }
    if let Some(n) = args.notes.as_deref() {
        builder = builder.notes(n);
    }
    for tag in &args.tags {
        let parsed = falach_core::Tag::from(tag.clone()).map_err(CliExit::from)?;
        builder = builder.tag(parsed);
    }
    if let Some(pw) = password_value.as_deref() {
        builder = builder.password(pw);
    }

    let uuid = vault
        .add_entry(root, builder.build())
        .map_err(CliExit::from)?;
    vault.save().map_err(CliExit::from)?;

    let group_name = group_name_for(vault.database(), uuid)
        .unwrap_or_else(|| vault.database().root().name.clone());
    let view = EntryAddView {
        uuid,
        title: &args.title,
        group: &group_name,
        // Only surface the password when the user explicitly opted in
        // AND we actually have one in hand (`--generate` or
        // `--password-stdin`). Disambiguation: a captured user
        // password echoed back is just as sensitive as a generated one;
        // `--show-password` is the user's explicit acknowledgment.
        password: if args.show_password {
            password_value.as_deref()
        } else {
            None
        },
    };
    write_success(cli, &view)
}

fn resolve_add_password(args: &EntryAddArgs) -> Result<Option<String>, CliExit> {
    if args.generate {
        let builder = build_password_builder(args.length, args.class_flags);
        let value = builder
            .generate()
            .map_err(CliExit::from)?
            .as_str()
            .to_string();
        return Ok(Some(value));
    }
    if args.password_stdin {
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        let mut stderr = std::io::stderr().lock();
        let raw = read_password_no_echo("Entry password: ", &mut stdin, &mut stderr)
            .map_err(|e| CliExit::UserError(format!("failed to read password: {e}")))?;
        return Ok(Some(raw));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

fn run_get(cli: &Cli, args: &EntryGetArgs) -> Result<(), CliExit> {
    let record = load_registry_record(cli, &args.vault)?;
    let master = prompt_for_vault(&args.vault)?;
    let keyfile = record.keyfile_path.clone().map(Keyfile::Path);
    let vault =
        VaultReadOnly::open(&record.path, &master, keyfile.as_ref()).map_err(CliExit::from)?;

    let uuid = resolve_entry_uuid(&vault, args)?;
    let entry_ref = vault
        .database()
        .iter_all_entries()
        .find(|e| e.id().uuid() == uuid)
        .ok_or(CliExit::from(VaultError::EntryNotFound { uuid }))?;
    let group_name = entry_ref.parent().name.clone();
    let view_data = EntryView::new(entry_ref);

    let totp_code = if args.show_totp {
        match vault.totp(uuid) {
            Ok((code, _)) => Some(code),
            Err(VaultError::EntryHasNoTotp { .. }) => None,
            Err(other) => return Err(CliExit::from(other)),
        }
    } else {
        None
    };

    let expired = view_data
        .expires()
        .is_some_and(|expiry| expiry <= Utc::now());
    let tags = view_data.tags();
    let tag_strs: Vec<&str> = tags.iter().map(falach_core::Tag::as_str).collect();
    let attachments = view_data.attachments();

    let password_owned = if args.show_password {
        Some(view_data.password().to_owned())
    } else {
        None
    };
    let view = EntryGetView {
        uuid,
        title: view_data.title(),
        username: optional_field(view_data.username()),
        url: optional_field(view_data.url()),
        notes: optional_field(view_data.notes()),
        password: password_owned.as_deref(),
        tags: tag_strs,
        group: &group_name,
        expired,
        has_attachments: !attachments.is_empty(),
        // Reuse the core's single TOTP definition (`fields::OTP`
        // presence) rather than re-typing the interop field name here.
        has_totp: view_data.kind() == EntryKind::Totp,
        totp_code,
    };

    if args.copy {
        // Arm the clipboard BEFORE writing the success view so that an
        // arming failure (e.g., no DISPLAY) produces a single JSON
        // error envelope on stdout instead of "success view + error
        // envelope" — preserving the `--format json` single-document
        // contract. The `wait_for_clear` always runs, even if
        // write_success errors (broken-pipe consumer), so the timer
        // can fire and clear the clipboard.
        let password = view_data.password().to_owned();
        let mut guard = arm_clipboard(password)?;
        let write_result = write_success(cli, &view);
        let wait_result = guard.wait_for_clear().map_err(CliExit::from);
        write_result?;
        return wait_result;
    }
    write_success(cli, &view)
}

fn resolve_entry_uuid(vault: &VaultReadOnly, args: &EntryGetArgs) -> Result<uuid::Uuid, CliExit> {
    if let Some(s) = args.uuid.as_deref() {
        return parse_uuid(s);
    }
    let Some(title) = args.title.as_deref() else {
        return Err(CliExit::UserError(
            "entry get requires --uuid or --title".to_string(),
        ));
    };
    let matches: Vec<uuid::Uuid> = vault
        .database()
        .iter_all_entries()
        .filter(|e| {
            e.get(falach_core::fields::TITLE)
                .is_some_and(|t| t.eq_ignore_ascii_case(title))
        })
        .map(|e| e.id().uuid())
        .collect();
    match matches.len() {
        0 => Err(CliExit::UserError(format!("no entry with title {title:?}"))),
        1 => Ok(matches[0]),
        _ => {
            let listing = matches
                .iter()
                .map(|u| format!("  {u}"))
                .collect::<Vec<_>>()
                .join("\n");
            Err(CliExit::UserError(format!(
                "{n} entries share title {title:?}; pass --uuid to disambiguate:\n{listing}",
                n = matches.len()
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// edit
// ---------------------------------------------------------------------------

fn run_edit(cli: &Cli, args: &EntryEditArgs) -> Result<(), CliExit> {
    let uuid = parse_uuid(&args.uuid)?;
    let record = load_registry_record(cli, &args.vault)?;
    let master = prompt_for_vault(&args.vault)?;
    let keyfile = record.keyfile_path.clone().map(Keyfile::Path);

    // Capture the new password (if requested) BEFORE opening the vault
    // so a stdin failure doesn't hold the write lock open.
    let new_password = if args.password_stdin {
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        let mut stderr = std::io::stderr().lock();
        Some(
            read_password_no_echo("New entry password: ", &mut stdin, &mut stderr)
                .map_err(|e| CliExit::UserError(format!("failed to read password: {e}")))?,
        )
    } else {
        None
    };

    let parsed_add_tags = args
        .add_tags
        .iter()
        .map(|t| falach_core::Tag::from(t.clone()).map_err(CliExit::from))
        .collect::<Result<Vec<_>, _>>()?;
    let parsed_rm_tags = args
        .rm_tags
        .iter()
        .map(|t| falach_core::Tag::from(t.clone()).map_err(CliExit::from))
        .collect::<Result<Vec<_>, _>>()?;

    let mut vault = Vault::open(&record.path, &master, keyfile.as_ref()).map_err(CliExit::from)?;

    let mut modified_fields: Vec<&'static str> = Vec::new();
    vault
        .update_entry(uuid, |entry| {
            if let Some(t) = args.title.as_deref() {
                entry.set_title(t);
                modified_fields.push("title");
            }
            if let Some(u) = args.username.as_deref() {
                entry.set_username(u);
                modified_fields.push("username");
            }
            if let Some(u) = args.url.as_deref() {
                entry.set_url(u);
                modified_fields.push("url");
            }
            if let Some(n) = args.notes.as_deref() {
                entry.set_notes(n);
                modified_fields.push("notes");
            }
            if let Some(p) = new_password.as_deref() {
                entry.set_password(p);
                modified_fields.push("password");
            }
            let mut tags_touched = false;
            for tag in &parsed_add_tags {
                entry.add_tag(tag.clone());
                tags_touched = true;
            }
            for tag in &parsed_rm_tags {
                entry.remove_tag(tag);
                tags_touched = true;
            }
            if tags_touched {
                modified_fields.push("tags");
            }
            Ok(())
        })
        .map_err(CliExit::from)?;
    vault.save().map_err(CliExit::from)?;

    let view = EntryEditView {
        uuid,
        modified_fields,
    };
    write_success(cli, &view)
}

// ---------------------------------------------------------------------------
// rm
// ---------------------------------------------------------------------------

fn run_rm(cli: &Cli, args: &EntryRmArgs) -> Result<(), CliExit> {
    let uuid = parse_uuid(&args.uuid)?;
    let record = load_registry_record(cli, &args.vault)?;
    let master = prompt_for_vault(&args.vault)?;
    let keyfile = record.keyfile_path.clone().map(Keyfile::Path);
    let mut vault = Vault::open(&record.path, &master, keyfile.as_ref()).map_err(CliExit::from)?;

    if args.permanent {
        vault.purge_entry(uuid).map_err(CliExit::from)?;
    } else {
        vault.delete_entry(uuid).map_err(CliExit::from)?;
    }
    vault.save().map_err(CliExit::from)?;

    let view = EntryRmView {
        uuid,
        recycle_bin: !args.permanent,
    };
    write_success(cli, &view)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn run_list(cli: &Cli, args: &EntryListArgs) -> Result<(), CliExit> {
    let record = load_registry_record(cli, &args.vault)?;
    let master = prompt_for_vault(&args.vault)?;
    let keyfile = record.keyfile_path.clone().map(Keyfile::Path);
    let vault =
        VaultReadOnly::open(&record.path, &master, keyfile.as_ref()).map_err(CliExit::from)?;
    let db = vault.database();

    // Collect tag filter parsed once.
    let filter_tags: Vec<falach_core::Tag> = args
        .tags
        .iter()
        .map(|t| falach_core::Tag::from(t.clone()).map_err(CliExit::from))
        .collect::<Result<Vec<_>, _>>()?;

    let now = Utc::now();
    // First pass: collect raw filtered + group-resolved rows. We keep
    // owned `String`s for the group name (the DB borrow lives across
    // the iteration but group lookup requires a fresh `EntryRef` walk).
    let mut rows: Vec<EntryRow> = Vec::new();
    for entry_ref in db.iter_all_entries() {
        // Capture the parent group's name BEFORE moving the EntryRef
        // into the EntryView façade — the view takes ownership.
        let group_name = entry_ref.parent().name.clone();
        let view = EntryView::new(entry_ref);
        let expired = view.expires().is_some_and(|t| t <= now);
        if expired && !args.include_expired {
            continue;
        }
        let entry_tags = view.tags();
        if !filter_tags.is_empty()
            && !filter_tags
                .iter()
                .all(|f| entry_tags.iter().any(|t| t == f))
        {
            continue;
        }
        rows.push(EntryRow {
            uuid: view.uuid(),
            title: view.title().to_owned(),
            group: group_name,
            tags: entry_tags.iter().map(|t| t.as_str().to_owned()).collect(),
            expired,
        });
    }
    // Apply pagination.
    let offset = args.offset.unwrap_or(0);
    let limit = args.limit.unwrap_or(usize::MAX);
    let paged: Vec<&EntryRow> = rows.iter().skip(offset).take(limit).collect();

    let items: Vec<EntryListItem<'_>> = paged
        .iter()
        .map(|r| EntryListItem {
            uuid: r.uuid,
            title: &r.title,
            group: &r.group,
            tags: r.tags.iter().map(String::as_str).collect(),
            expired: r.expired,
        })
        .collect();
    let view = EntryListView { entries: items };
    write_success(cli, &view)
}

// ---------------------------------------------------------------------------
// search
// ---------------------------------------------------------------------------

fn run_search(cli: &Cli, args: &EntrySearchArgs) -> Result<(), CliExit> {
    let record = load_registry_record(cli, &args.vault)?;
    let master = prompt_for_vault(&args.vault)?;
    let keyfile = record.keyfile_path.clone().map(Keyfile::Path);
    let vault =
        VaultReadOnly::open(&record.path, &master, keyfile.as_ref()).map_err(CliExit::from)?;
    let mode = match args.mode {
        SearchModeArg::Substring => SearchMode::Substring,
        SearchModeArg::Wildcard => SearchMode::Wildcard,
        SearchModeArg::Fuzzy => SearchMode::Fuzzy,
    };
    let mut opts = SearchOptions::new(args.query.as_str())
        .with_mode(mode)
        .include_recycled(args.include_recycled);
    if let Some(scope_str) = &args.scope {
        opts = opts.with_scope(parse_scope(&vault, scope_str)?);
    }
    let mut results = vault.search(opts).map_err(CliExit::from)?;
    if let Some(cap) = args.limit {
        results.truncate(cap);
    }

    // Resolve UUIDs back to display rows, carrying score + fuzzy indices.
    let now = Utc::now();
    let mut rows: Vec<SearchRowOwned> = Vec::new();
    let db = vault.database();
    for result in &results {
        let Some(entry_ref) = db.iter_all_entries().find(|e| e.id().uuid() == result.uuid) else {
            continue;
        };
        let group_name = entry_ref.parent().name.clone();
        let view = EntryView::new(entry_ref);
        let matched_indices = result
            .match_indices
            .iter()
            .map(|(field, positions)| FieldIndices {
                field: matched_field_name(*field),
                positions: positions.clone(),
            })
            .collect();
        rows.push(SearchRowOwned {
            row: EntryRow {
                uuid: view.uuid(),
                title: view.title().to_owned(),
                group: group_name,
                tags: view.tags().iter().map(|t| t.as_str().to_owned()).collect(),
                expired: view.expires().is_some_and(|t| t <= now),
            },
            score: result.score,
            matched_indices,
        });
    }
    let matches: Vec<EntrySearchItem<'_>> = rows
        .iter()
        .map(|r| EntrySearchItem {
            uuid: r.row.uuid,
            title: &r.row.title,
            group: &r.row.group,
            tags: r.row.tags.iter().map(String::as_str).collect(),
            expired: r.row.expired,
            score: r.score,
            matched_indices: r.matched_indices.clone(),
        })
        .collect();
    let view = EntrySearchView {
        query: args.query.as_str(),
        matches,
    };
    write_success(cli, &view)
}

/// The stable JSON field name for a matched field.
fn matched_field_name(field: MatchedField) -> &'static str {
    match field {
        MatchedField::Title => "title",
        MatchedField::Username => "username",
        MatchedField::Url => "url",
        MatchedField::Notes => "notes",
        MatchedField::Tags => "tags",
    }
}

/// Parse a `--scope` value into a [`SearchScope`]: `group:<name>` resolves the
/// named group's subtree (error listing candidates on miss/ambiguity);
/// `tag:<tag>` is an exact (case-insensitive) tag filter.
fn parse_scope(vault: &VaultReadOnly, scope: &str) -> Result<SearchScope, CliExit> {
    if let Some(name) = scope.strip_prefix("group:") {
        let db = vault.database();
        let mut matches = db
            .iter_all_groups()
            .filter(|g| g.name.eq_ignore_ascii_case(name))
            .map(|g| g.id().uuid());
        let first = matches.next();
        match (first, matches.next()) {
            (Some(uuid), None) => Ok(SearchScope::GroupSubtree(uuid)),
            (Some(_), Some(_)) => Err(CliExit::UserError(format!(
                "scope group {name:?} is ambiguous — multiple groups share that name"
            ))),
            (None, _) => {
                let candidates: Vec<String> =
                    db.iter_all_groups().map(|g| g.name.clone()).collect();
                Err(CliExit::UserError(format!(
                    "no group named {name:?}; known groups: {}",
                    candidates.join(", ")
                )))
            }
        }
    } else if let Some(tag) = scope.strip_prefix("tag:") {
        Ok(SearchScope::Tag(tag.to_string()))
    } else {
        Err(CliExit::UserError(
            "scope must be group:<name> or tag:<tag>".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `falach-genpw` `PasswordBuilder` from the CLI's
/// `--length` + class flags. Negative flags compose: each `--no-*`
/// strips its class.
fn build_password_builder(length: usize, flags: PasswordClassFlags) -> PasswordBuilder {
    let classes = CharSet {
        lowercase: !flags.no_lowercase,
        uppercase: !flags.no_uppercase,
        digits: !flags.no_digits,
        symbols: !flags.no_symbols,
    };
    PasswordBuilder::new()
        .length(length)
        .classes(classes)
        .exclude_ambiguous(flags.exclude_ambiguous)
}

fn parse_uuid(s: &str) -> Result<uuid::Uuid, CliExit> {
    uuid::Uuid::parse_str(s).map_err(|e| CliExit::UserError(format!("invalid UUID {s:?}: {e}")))
}

fn optional_field(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn group_name_for(db: &falach_core::Database, uuid: uuid::Uuid) -> Option<String> {
    db.iter_all_entries()
        .find(|e| e.id().uuid() == uuid)
        .map(|e| e.parent().name.clone())
}

fn load_registry_record(cli: &Cli, vault_id: &str) -> Result<RegisteredVault, CliExit> {
    let paths = resolve_paths(cli)?;
    let registry = VaultRegistry::load(paths).map_err(CliExit::from)?;
    registry.get(vault_id).cloned().ok_or_else(|| {
        CliExit::from(VaultError::NotRegistered {
            name: vault_id.to_string(),
        })
    })
}

fn prompt_for_vault(vault_id: &str) -> Result<falach_core::MasterPassword, CliExit> {
    let agent = NoAgentClient;
    let opts = PromptOpts {
        vault: vault_id,
        agent: &agent,
        prompt_label: "Master password: ",
    };
    master_password(&opts)
}
