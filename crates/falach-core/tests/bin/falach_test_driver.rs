//! Test driver: a thin one-shot binary that drives `falach-core`
//! primitives from shell-script interop tests. **Not** the user-facing
//! CLI — that lives in `features/cli-skeleton/` and is its own feature.
//!
//! The driver exists to make shell-script round-tripping with
//! `keepassxc-cli` (and `oathtool`) possible. Output for read-side
//! commands is JSON for `jq` parseability. Master passwords are read
//! from stdin only (FR-061).

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read as _};
use std::path::PathBuf;

use falach_core::{
    fields, EntryBuilder, EntryRef, GroupRef, MasterPassword, NoRecoveryConfirmed, SearchOptions,
    Tag, Totp, Vault,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("falach-test-driver: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    match args[0].as_str() {
        // Original vault-level subcommands.
        "create" => create(&args[1..]),
        "dump" => dump(&args[1..]),
        "add-entry" => add_entry(&args[1..]),
        "change-pw" => change_password(&args[1..]),

        // Entry-management subcommands (Phase 5 T5.1).
        "entry" => entry_subcommand(&args[1..]),
        "group" => group_subcommand(&args[1..]),

        other => Err(format!("unknown subcommand: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Original vault-level subcommands (unchanged).
// ---------------------------------------------------------------------------

fn create(args: &[String]) -> Result<(), String> {
    let path = positional_path(args)?;
    require_stdin_password_flag(args)?;
    let password = read_stdin_lines()?.into_iter().next().unwrap_or_default();
    drop(
        Vault::create(
            &path,
            &MasterPassword::new(password),
            None,
            falach_core::KdfParams::default(),
            NoRecoveryConfirmed::yes(),
        )
        .map_err(|err| err.to_string())?,
    );
    Ok(())
}

fn dump(args: &[String]) -> Result<(), String> {
    let path = positional_path(args)?;
    require_stdin_password_flag(args)?;
    let password = read_stdin_lines()?.into_iter().next().unwrap_or_default();
    let vault =
        Vault::open(&path, &MasterPassword::new(password), None).map_err(|err| err.to_string())?;

    let mut entries = Vec::new();
    collect_entries(&vault.database().root(), "", &mut entries);
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    print_entries_json(&entries);
    Ok(())
}

fn add_entry(args: &[String]) -> Result<(), String> {
    let path = positional_path(args)?;
    let title = flag_value(args, "--title")?;
    let username = flag_value(args, "--username")?;
    let entry_password = flag_value(args, "--password")?;
    let master_password = read_stdin_lines()?.into_iter().next().unwrap_or_default();

    let mut vault = Vault::open(&path, &MasterPassword::new(master_password), None)
        .map_err(|err| err.to_string())?;
    vault.database_mut().root_mut().add_entry().edit(|entry| {
        entry.set_unprotected(fields::TITLE, title);
        entry.set_unprotected(fields::USERNAME, username);
        entry.set_protected(fields::PASSWORD, entry_password);
    });
    vault.save().map_err(|err| err.to_string())
}

fn change_password(args: &[String]) -> Result<(), String> {
    let path = positional_path(args)?;
    let mut lines = read_stdin_lines()?;
    if lines.len() < 2 {
        return Err("change-pw expects current and new passwords on stdin".into());
    }
    let current = MasterPassword::new(lines.remove(0));
    let new = MasterPassword::new(lines.remove(0));
    let mut vault = Vault::open(&path, &current, None).map_err(|err| err.to_string())?;
    vault
        .change_master_password(&current, &new)
        .map_err(|err| err.to_string())
}

// ---------------------------------------------------------------------------
// Entry subcommand dispatch.
// ---------------------------------------------------------------------------

fn entry_subcommand(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        print_entry_help();
        return Ok(());
    }

    match args[0].as_str() {
        "add" => entry_add(&args[1..]),
        "add-totp" => entry_add_totp(&args[1..]),
        "add-note" => entry_add_note(&args[1..]),
        "get" => entry_get(&args[1..]),
        "update" => entry_update(&args[1..]),
        "rm" => entry_rm(&args[1..]),
        "list" => entry_list(&args[1..]),
        "search" => entry_search(&args[1..]),
        "totp" => entry_totp(&args[1..]),
        "attach" => entry_attach(&args[1..]),
        "extract" => entry_extract(&args[1..]),
        "expire" => entry_expire(&args[1..]),
        other => Err(format!("unknown entry subcommand: {other}")),
    }
}

fn entry_add(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let title = required_flag(args, "--title")?;
    let group_arg = optional_flag(args, "--group");
    let username = optional_flag(args, "--username");
    let entry_password = optional_flag(args, "--password");
    let url = optional_flag(args, "--url");
    let notes = optional_flag(args, "--notes");
    let tags = repeated_flag(args, "--tag");

    let master = read_stdin_master_password()?;
    let mut vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let group_uuid = resolve_group(&vault, group_arg)?;

    let mut builder = EntryBuilder::credential(title);
    if let Some(value) = username {
        builder = builder.username(value);
    }
    if let Some(value) = entry_password {
        builder = builder.password(value);
    }
    if let Some(value) = url {
        builder = builder.url(value);
    }
    if let Some(value) = notes {
        builder = builder.notes(value);
    }
    for tag in tags {
        builder = builder.tag(Tag::new(tag));
    }

    let uuid = vault
        .add_entry(group_uuid, builder.build())
        .map_err(|err| err.to_string())?;
    vault.save().map_err(|err| err.to_string())?;
    println!("{{\"uuid\":{}}}", json_string(&uuid.to_string()));
    Ok(())
}

fn entry_add_totp(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let title = required_flag(args, "--title")?;
    let otpauth = required_flag(args, "--otpauth")?;
    let group_arg = optional_flag(args, "--group");

    let master = read_stdin_master_password()?;
    let mut vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let group_uuid = resolve_group(&vault, group_arg)?;

    let draft = EntryBuilder::totp(title, otpauth)
        .map_err(|err| err.to_string())?
        .build();
    let uuid = vault
        .add_entry(group_uuid, draft)
        .map_err(|err| err.to_string())?;
    vault.save().map_err(|err| err.to_string())?;
    println!("{{\"uuid\":{}}}", json_string(&uuid.to_string()));
    Ok(())
}

fn entry_add_note(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let title = required_flag(args, "--title")?;
    let body = required_flag(args, "--body")?;
    let group_arg = optional_flag(args, "--group");

    let master = read_stdin_master_password()?;
    let mut vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let group_uuid = resolve_group(&vault, group_arg)?;

    let draft = EntryBuilder::secure_note(title).notes(body).build();
    let uuid = vault
        .add_entry(group_uuid, draft)
        .map_err(|err| err.to_string())?;
    vault.save().map_err(|err| err.to_string())?;
    println!("{{\"uuid\":{}}}", json_string(&uuid.to_string()));
    Ok(())
}

fn entry_get(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let uuid_arg = required_flag(args, "--uuid")?;
    let show_password = flag_present(args, "--show-password");

    let master = read_stdin_master_password()?;
    let vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let uuid = parse_uuid(uuid_arg)?;
    let view = vault.get_entry(uuid).map_err(|err| err.to_string())?;

    let mut out = String::new();
    out.push('{');
    let _ = write!(
        out,
        "\"uuid\":{},\"title\":{},\"username\":{},\"url\":{},\"notes\":{}",
        json_string(&uuid.to_string()),
        json_string(view.title()),
        json_string(view.username()),
        json_string(view.url()),
        json_string(view.notes())
    );
    if show_password {
        let _ = write!(out, ",\"password\":{}", json_string(view.password()));
    }
    let tag_strs: Vec<String> = view.tags().iter().map(|t| t.as_str().to_string()).collect();
    let _ = write!(out, ",\"tags\":[");
    for (i, tag) in tag_strs.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&json_string(tag));
    }
    out.push(']');
    if let Some(otp) = view.custom_field("otp") {
        let _ = write!(out, ",\"otp\":{}", json_string(otp));
    }
    if let Some(expires) = view.expires() {
        let _ = write!(out, ",\"expires\":{}", json_string(&expires.to_rfc3339()));
    }
    out.push_str(",\"history_len\":");
    let _ = write!(out, "{}", view.history().len());
    out.push('}');
    println!("{out}");
    Ok(())
}

fn entry_update(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let uuid_arg = required_flag(args, "--uuid")?;
    let title = optional_flag(args, "--title");
    let username = optional_flag(args, "--username");
    let entry_password = optional_flag(args, "--password");
    let url = optional_flag(args, "--url");
    let notes = optional_flag(args, "--notes");

    let master = read_stdin_master_password()?;
    let mut vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let uuid = parse_uuid(uuid_arg)?;

    vault
        .update_entry(uuid, |entry| {
            if let Some(value) = title {
                entry.set_title(value);
            }
            if let Some(value) = username {
                entry.set_username(value);
            }
            if let Some(value) = entry_password {
                entry.set_password(value);
            }
            if let Some(value) = url {
                entry.set_url(value);
            }
            if let Some(value) = notes {
                entry.set_notes(value);
            }
            Ok(())
        })
        .map_err(|err| err.to_string())?;
    vault.save().map_err(|err| err.to_string())
}

fn entry_rm(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let uuid_arg = required_flag(args, "--uuid")?;
    let purge = flag_present(args, "--purge");

    let master = read_stdin_master_password()?;
    let mut vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let uuid = parse_uuid(uuid_arg)?;

    if purge {
        vault.purge_entry(uuid).map_err(|err| err.to_string())?;
    } else {
        vault.delete_entry(uuid).map_err(|err| err.to_string())?;
    }
    vault.save().map_err(|err| err.to_string())
}

fn entry_list(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let group_arg = optional_flag(args, "--group");

    let master = read_stdin_master_password()?;
    let vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;

    let mut entries = Vec::new();
    match group_arg {
        Some(arg) => {
            let group_uuid = parse_uuid(arg)?;
            let group_view = vault
                .group_view(group_uuid)
                .map_err(|err| err.to_string())?;
            for entry_uuid in group_view.entry_uuids() {
                let view = vault.get_entry(entry_uuid).map_err(|err| err.to_string())?;
                entries.push(JsonEntry {
                    path: view.title().to_string(),
                    title: view.title().to_string(),
                    username: view.username().to_string(),
                    password: String::new(),
                    url: view.url().to_string(),
                    notes: view.notes().to_string(),
                });
            }
        }
        None => {
            collect_entries(&vault.database().root(), "", &mut entries);
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    print_entries_json(&entries);
    Ok(())
}

fn entry_search(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let query = required_flag(args, "--query")?;
    let wildcard = flag_present(args, "--wildcard");

    let master = read_stdin_master_password()?;
    let vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;

    let opts = SearchOptions::new(query).wildcard(wildcard);
    let results = vault.search(opts).map_err(|err| err.to_string())?;

    println!("[");
    for (i, result) in results.iter().enumerate() {
        let suffix = if i + 1 == results.len() { "" } else { "," };
        let mut fields_str = String::new();
        for (j, field) in result.matched_fields.iter().enumerate() {
            if j > 0 {
                fields_str.push(',');
            }
            fields_str.push_str(&json_string(&format!("{field:?}")));
        }
        println!(
            "  {{\"uuid\":{},\"score\":{},\"matched_fields\":[{}]}}{}",
            json_string(&result.uuid.to_string()),
            result.score,
            fields_str,
            suffix
        );
    }
    println!("]");
    Ok(())
}

fn entry_totp(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let uuid_arg = required_flag(args, "--uuid")?;
    let at_arg = optional_flag(args, "--at");

    let master = read_stdin_master_password()?;
    let vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let uuid = parse_uuid(uuid_arg)?;

    let (code, remaining) = match at_arg {
        // The --at variant produces a deterministic code for a pinned Unix
        // timestamp, which the TOTP interop script cross-checks against
        // oathtool. Without it the test would race the 30-second window.
        Some(at) => {
            let when: u64 = at
                .parse()
                .map_err(|_| format!("--at must be a Unix timestamp; got {at}"))?;
            let view = vault.get_entry(uuid).map_err(|err| err.to_string())?;
            let uri = view
                .custom_field("otp")
                .ok_or_else(|| "entry has no otp field".to_string())?;
            let totp = Totp::from_otpauth_uri(uri).map_err(|err| err.to_string())?;
            (totp.code_at(when), totp.remaining_at(when))
        }
        None => vault.totp(uuid).map_err(|err| err.to_string())?,
    };

    println!(
        "{{\"code\":{},\"remaining_seconds\":{}}}",
        json_string(&code),
        remaining
    );
    Ok(())
}

fn entry_attach(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let uuid_arg = required_flag(args, "--uuid")?;
    let name = required_flag(args, "--name")?;
    let file_path = required_flag(args, "--file")?;

    let master = read_stdin_master_password()?;
    let mut vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let uuid = parse_uuid(uuid_arg)?;
    let bytes = fs::read(file_path).map_err(|err| err.to_string())?;
    vault
        .add_attachment(uuid, name, &bytes)
        .map_err(|err| err.to_string())?;
    vault.save().map_err(|err| err.to_string())
}

fn entry_extract(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let uuid_arg = required_flag(args, "--uuid")?;
    let name = required_flag(args, "--name")?;
    let out_path = required_flag(args, "--out")?;

    let master = read_stdin_master_password()?;
    let vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let uuid = parse_uuid(uuid_arg)?;
    let bytes = vault
        .get_attachment(uuid, name)
        .map_err(|err| err.to_string())?;
    fs::write(out_path, bytes.as_slice()).map_err(|err| err.to_string())
}

fn entry_expire(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let uuid_arg = required_flag(args, "--uuid")?;
    let when = required_flag(args, "--when")?;

    let master = read_stdin_master_password()?;
    let mut vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let uuid = parse_uuid(uuid_arg)?;

    let parsed = chrono::DateTime::parse_from_rfc3339(when)
        .map_err(|err| format!("invalid --when (RFC3339 expected): {err}"))?
        .with_timezone(&chrono::Utc);
    vault
        .set_expiration(uuid, parsed)
        .map_err(|err| err.to_string())?;
    vault.save().map_err(|err| err.to_string())
}

// ---------------------------------------------------------------------------
// Group subcommand dispatch.
// ---------------------------------------------------------------------------

fn group_subcommand(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("group requires a subcommand (create | rm)".into());
    }
    match args[0].as_str() {
        "create" => group_create(&args[1..]),
        "rm" => group_rm(&args[1..]),
        other => Err(format!("unknown group subcommand: {other}")),
    }
}

fn group_create(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let name = required_flag(args, "--name")?;
    let parent_arg = optional_flag(args, "--parent");

    let master = read_stdin_master_password()?;
    let mut vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let parent_uuid = resolve_group(&vault, parent_arg)?;

    let uuid = vault
        .create_group(parent_uuid, name)
        .map_err(|err| err.to_string())?;
    vault.save().map_err(|err| err.to_string())?;
    println!("{{\"uuid\":{}}}", json_string(&uuid.to_string()));
    Ok(())
}

fn group_rm(args: &[String]) -> Result<(), String> {
    let vault_path = required_flag(args, "--vault")?;
    let uuid_arg = required_flag(args, "--uuid")?;
    let recurse = flag_present(args, "--recurse");

    let master = read_stdin_master_password()?;
    let mut vault =
        Vault::open(&PathBuf::from(vault_path), &master, None).map_err(|err| err.to_string())?;
    let uuid = parse_uuid(uuid_arg)?;
    let behavior = if recurse {
        falach_core::GroupDeleteBehavior::Recurse
    } else {
        falach_core::GroupDeleteBehavior::Refuse
    };
    vault
        .delete_group(uuid, behavior)
        .map_err(|err| err.to_string())?;
    vault.save().map_err(|err| err.to_string())
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

fn resolve_group(vault: &Vault, group_arg: Option<&str>) -> Result<uuid::Uuid, String> {
    match group_arg {
        Some(arg) => parse_uuid(arg),
        None => Ok(vault.root_group_uuid()),
    }
}

fn parse_uuid(value: &str) -> Result<uuid::Uuid, String> {
    uuid::Uuid::parse_str(value).map_err(|err| format!("invalid UUID '{value}': {err}"))
}

fn read_stdin_master_password() -> Result<MasterPassword, String> {
    let line = read_stdin_lines()?.into_iter().next().unwrap_or_default();
    Ok(MasterPassword::new(line))
}

fn required_flag<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    flag_value(args, flag)
}

fn optional_flag<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find_map(|pair| (pair[0] == flag).then_some(pair[1].as_str()))
}

fn flag_present(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn repeated_flag<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
    args.windows(2)
        .filter_map(|pair| (pair[0] == flag).then_some(pair[1].as_str()))
        .collect()
}

fn collect_entries(group: &GroupRef<'_>, prefix: &str, out: &mut Vec<JsonEntry>) {
    for entry in group.entries() {
        out.push(entry_json(&entry, prefix));
    }

    for child in group.groups() {
        let name = child.name.as_str();
        let next_prefix = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        collect_entries(&child, &next_prefix, out);
    }
}

fn entry_json(entry: &EntryRef<'_>, prefix: &str) -> JsonEntry {
    let title = entry.get(fields::TITLE).unwrap_or_default();
    let path = if prefix.is_empty() {
        title.to_string()
    } else {
        format!("{prefix}/{title}")
    };

    JsonEntry {
        path,
        title: title.to_string(),
        username: entry.get(fields::USERNAME).unwrap_or_default().to_string(),
        password: entry.get(fields::PASSWORD).unwrap_or_default().to_string(),
        url: entry.get(fields::URL).unwrap_or_default().to_string(),
        notes: entry.get(fields::NOTES).unwrap_or_default().to_string(),
    }
}

struct JsonEntry {
    path: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
}

fn print_entries_json(entries: &[JsonEntry]) {
    println!("{{");
    println!("  \"entries\": [");
    for (index, entry) in entries.iter().enumerate() {
        let suffix = if index + 1 == entries.len() { "" } else { "," };
        println!("    {{");
        println!("      \"path\": {},", json_string(&entry.path));
        println!("      \"title\": {},", json_string(&entry.title));
        println!("      \"username\": {},", json_string(&entry.username));
        println!("      \"password\": {},", json_string(&entry.password));
        println!("      \"url\": {},", json_string(&entry.url));
        println!("      \"notes\": {}", json_string(&entry.notes));
        println!("    }}{suffix}");
    }
    println!("  ]");
    println!("}}");
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn positional_path(args: &[String]) -> Result<PathBuf, String> {
    let Some(path) = args.first() else {
        return Err("missing path argument".into());
    };
    if path.starts_with("--") {
        return Err("path argument must appear before flags".into());
    }
    Ok(PathBuf::from(path))
}

fn require_stdin_password_flag(args: &[String]) -> Result<(), String> {
    match flag_value(args, "--password")? {
        "<stdin>" | "stdin" | "-" => Ok(()),
        other => Err(format!("password source must be <stdin>, got {other}")),
    }
}

fn flag_value<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    args.windows(2)
        .find_map(|pair| (pair[0] == flag).then_some(pair[1].as_str()))
        .ok_or_else(|| format!("missing required flag: {flag}"))
}

fn read_stdin_lines() -> Result<Vec<String>, String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| err.to_string())?;
    Ok(input.lines().map(str::to_owned).collect())
}

fn print_help() {
    println!(
        "\
falach-test-driver

Vault-level commands (read master password from stdin):
  falach-test-driver create <path> --password <stdin>
  falach-test-driver dump <path> --password <stdin>
  falach-test-driver add-entry <path> --title <t> --username <u> --password <p>
  falach-test-driver change-pw <path>

Entry-management commands (read master password from stdin via 'echo PW |'):
  falach-test-driver entry add --vault PATH --title T [--group UUID] [--username U] [--password P] [--url U] [--notes N] [--tag T ...]
  falach-test-driver entry add-totp --vault PATH --title T --otpauth URI [--group UUID]
  falach-test-driver entry add-note --vault PATH --title T --body B [--group UUID]
  falach-test-driver entry get --vault PATH --uuid UUID [--show-password]
  falach-test-driver entry update --vault PATH --uuid UUID [--title T] [--username U] [--password P] [--url U] [--notes N]
  falach-test-driver entry rm --vault PATH --uuid UUID [--purge]
  falach-test-driver entry list --vault PATH [--group UUID]
  falach-test-driver entry search --vault PATH --query Q [--wildcard]
  falach-test-driver entry totp --vault PATH --uuid UUID [--at UNIX_SECONDS]
  falach-test-driver entry attach --vault PATH --uuid UUID --name N --file PATH
  falach-test-driver entry extract --vault PATH --uuid UUID --name N --out PATH
  falach-test-driver entry expire --vault PATH --uuid UUID --when RFC3339

Group commands:
  falach-test-driver group create --vault PATH --name N [--parent UUID]
  falach-test-driver group rm --vault PATH --uuid UUID [--recurse]

Outputs are JSON. Master password is always read from stdin (FR-061).
"
    );
}

fn print_entry_help() {
    println!(
        "\
falach-test-driver entry [add|add-totp|add-note|get|update|rm|list|search|totp|attach|extract|expire] ...

Run 'falach-test-driver --help' for the full subcommand reference."
    );
}
