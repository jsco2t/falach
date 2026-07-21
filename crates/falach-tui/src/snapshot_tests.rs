//! Snapshot harness + golden tests for the Secrets-tab tree and detail pane
//! (T3.5). No third-party snapshot crate (design §8 "no `insta` dep"): the
//! [`assert_snapshot`] helper reads `tests/snapshots/{name}.txt`, regenerates it
//! **only** under `FALACH_UPDATE_SNAPSHOTS=1` (set by
//! `make test-update-snapshots`), and on mismatch prints a line diff and fails.
//! A missing golden in a normal run is a hard failure, never a silent
//! auto-create (PMF-4 / T4.4 — no fail-open).
//!
//! Only deterministic surfaces are snapshotted (design R-5): the **tree** (names
//! + ▶/▼ markers + the `(expired)` suffix — no timestamps) and the **pure
//! detail lines** at two scroll offsets (fed fixed plain values via
//! [`DetailData`], so no clock / fixture-timestamp flakiness).

use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use falach_core::{
    EntryBuilder, FalachPaths, KdfParams, MasterPassword, NoRecoveryConfirmed, RegisteredVault,
    Uuid, Vault, VaultRegistry,
};
use falach_security::AutoLockConfig;
use ratatui::backend::TestBackend;
use ratatui::layout::Rect;
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};

use crate::app::App;
use crate::recents::Recents;
use crate::tabs::TabBar;
use crate::theme::Theme;
use crate::widgets::entry_detail::{self, DetailData};
use crate::widgets::entry_tree::{self, TreeState};

/// Render a draw closure into a fixed-size `TestBackend` and return its buffer
/// as trimmed text rows.
fn render_lines<F: FnOnce(&mut Frame)>(width: u16, height: u16, draw: F) -> Vec<String> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
    terminal.draw(draw).expect("draw");
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            let mut row = String::new();
            for x in 0..width {
                if let Some(cell) = buffer.cell((x, y)) {
                    row.push_str(cell.symbol());
                }
            }
            row.trim_end().to_string()
        })
        .collect()
}

fn snapshot_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(format!("{name}.txt"))
}

/// Compare `actual` rows against the golden file `name`. Regenerates **only**
/// under `FALACH_UPDATE_SNAPSHOTS` (set by `make test-update-snapshots`);
/// fails with a line diff on mismatch.
fn assert_snapshot(actual: &[String], name: &str) {
    assert_snapshot_inner(
        actual,
        &snapshot_path(name),
        name,
        std::env::var_os("FALACH_UPDATE_SNAPSHOTS").is_some(),
    );
}

/// Inner worker, with the update flag and path passed explicitly so the
/// missing-golden behavior is testable without depending on the process-wide
/// `FALACH_UPDATE_SNAPSHOTS` env var (which `make test-update-snapshots` sets
/// for the whole run).
///
/// **PMF-4 / T4.4 — no fail-open:** a missing golden in a *normal* run (update
/// off) `panic!`s rather than silently auto-creating and passing. The old
/// auto-create-on-missing path meant a deleted or renamed golden self-healed
/// to green, hiding the very regression a snapshot is meant to catch.
fn assert_snapshot_inner(actual: &[String], path: &Path, name: &str, update: bool) {
    let actual_text = actual.join("\n");

    if update {
        std::fs::create_dir_all(path.parent().expect("snapshot dir")).expect("create snapshot dir");
        std::fs::write(path, format!("{actual_text}\n")).expect("write snapshot");
        return;
    }

    assert!(
        path.exists(),
        "missing snapshot golden `{name}` at {} — run `make test-update-snapshots` to create it",
        path.display()
    );

    let expected = std::fs::read_to_string(path).expect("read snapshot");
    let expected_text = expected.trim_end_matches('\n');
    if expected_text != actual_text {
        eprintln!("--- snapshot mismatch: {name} ---");
        let expected_rows: Vec<&str> = expected_text.lines().collect();
        let max = expected_rows.len().max(actual.len());
        for i in 0..max {
            let e = expected_rows.get(i).copied().unwrap_or("<none>");
            let a = actual.get(i).map_or("<none>", String::as_str);
            if e != a {
                eprintln!("  {i:>2} expected |{e}|");
                eprintln!("     actual   |{a}|");
            }
        }
        panic!("snapshot `{name}` mismatch (run `make test-update-snapshots` to update)");
    }
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        memory_kib: 1_024,
        iterations: 1,
        parallelism: 1,
    }
}

/// A vault with `Personal/{BankCard(expired), GitHub}` and `Work` (empty),
/// returned with `Personal` pre-expanded and `GitHub` selected.
fn tree_fixture() -> (tempfile::TempDir, Vault, TreeState) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("snap.kdbx");
    let mut vault = Vault::create(
        &path,
        &MasterPassword::new("pw".to_string()),
        None,
        fast_kdf(),
        NoRecoveryConfirmed::yes(),
    )
    .expect("create");
    let root = vault.root_group_uuid();
    let personal = vault.create_group(root, "Personal").expect("personal");
    vault.create_group(root, "Work").expect("work");
    vault
        .add_entry(personal, EntryBuilder::credential("GitHub").build())
        .expect("github");
    let bankcard = vault
        .add_entry(personal, EntryBuilder::credential("BankCard").build())
        .expect("bankcard");
    // Expired in the past → `is_expired` is stable regardless of wall clock.
    vault
        .set_expiration(bankcard, Utc.timestamp_opt(1_000_000, 0).unwrap())
        .expect("expire");

    // Select the first node (Personal) and expand it via the same path `l`
    // takes, so the snapshot exercises nesting + the expired suffix.
    let mut state = TreeState::new();
    let rows = entry_tree::build_rows(&vault, &state, &Recents::new());
    state.select_first(&rows);
    state.expand_or_child(&rows);
    (dir, vault, state)
}

#[test]
fn tree_snapshot_renders_hierarchy_markers_and_expired_suffix() {
    let (_dir, vault, state) = tree_fixture();
    let rows = entry_tree::build_rows(&vault, &state, &Recents::new());
    let theme = Theme::auto();
    // Fixed clock so the expired check is deterministic.
    let now = Utc.timestamp_opt(2_000_000_000, 0).unwrap();
    let lines = render_lines(40, 10, |frame| {
        let area = Rect::new(0, 0, 40, 10);
        let items = entry_tree::tree_items(
            &rows,
            &vault,
            now,
            &std::collections::HashSet::new(),
            &theme,
        );
        let selected = state.selected_index(&rows);
        entry_tree::render_tree(items, selected, true, frame, area, &theme);
    });
    assert_snapshot(&lines, "secrets_tree");
}

/// The tree with two entries marked for a bulk operation (T4.5): the marked
/// rows carry the `▸ ` glyph lead (a text carrier, not colour) in place of the
/// blank indent. Mark toggling / range logic is unit-tested in `app`.
#[test]
fn tree_snapshot_with_marks() {
    let (_dir, vault, state) = tree_fixture();
    let rows = entry_tree::build_rows(&vault, &state, &Recents::new());
    let theme = Theme::auto();
    let now = Utc.timestamp_opt(2_000_000_000, 0).unwrap();
    // Mark the two non-expired Personal entries (GitHub, Mail).
    let marks: std::collections::HashSet<Uuid> = rows
        .iter()
        .filter(|r| matches!(r.kind, entry_tree::RowKind::Entry))
        .map(|r| r.uuid)
        .take(2)
        .collect();
    let lines = render_lines(40, 10, |frame| {
        let area = Rect::new(0, 0, 40, 10);
        let items = entry_tree::tree_items(&rows, &vault, now, &marks, &theme);
        let selected = state.selected_index(&rows);
        entry_tree::render_tree(items, selected, true, frame, area, &theme);
    });
    assert_snapshot(&lines, "secrets_tree_marked");
}

/// A detail snapshot fixture with enough lines to exercise scrolling.
fn detail_fixture() -> DetailData {
    DetailData {
        title: "GitHub".to_string(),
        kind: "Credential",
        username: "octocat".to_string(),
        url: "https://github.com".to_string(),
        password: falach_core::Zeroizing::new("hunter2".to_string()),
        notes: "line one\nline two\nline three".to_string(),
        created: Some("2026-01-02 03:04 UTC".to_string()),
        modified: Some("2026-05-06 07:08 UTC".to_string()),
        expired: false,
        totp: None,
        attachments: vec![("recovery.txt".to_string(), 2048)],
        tags: vec!["work".to_string(), "dev".to_string()],
        custom_fields: vec![
            entry_detail::CustomFieldData {
                name: "API Key".to_string(),
                value: falach_core::Zeroizing::new("k1".to_string()),
                protected: false,
            },
            // Protected → renders masked at reveal=false, so no plaintext lands
            // in the golden (T1.5 / PMF-1).
            entry_detail::CustomFieldData {
                name: "Recovery PIN".to_string(),
                value: falach_core::Zeroizing::new("4242".to_string()),
                protected: true,
            },
        ],
        history_count: 2,
    }
}

fn render_detail_at(lines: &[ratatui::text::Line<'static>], scroll: u16) -> Vec<String> {
    let owned: Vec<ratatui::text::Line<'static>> = lines.to_vec();
    render_lines(44, 8, move |frame| {
        let area = Rect::new(0, 0, 44, 8);
        // No wrap here: the snapshot pins the builder's line content + the
        // scroll slice, not ratatui's wrapping (a presentation detail).
        let paragraph = Paragraph::new(owned).scroll((scroll, 0));
        frame.render_widget(paragraph, area);
    })
}

#[test]
fn detail_snapshot_at_top_offset() {
    let data = detail_fixture();
    let lines = entry_detail::detail_lines(&data, false, &Theme::auto());
    let rendered = render_detail_at(&lines, 0);
    assert_snapshot(&rendered, "secrets_detail_top");
}

#[test]
fn detail_snapshot_scrolled() {
    let data = detail_fixture();
    let lines = entry_detail::detail_lines(&data, false, &Theme::auto());
    let rendered = render_detail_at(&lines, 5);
    assert_snapshot(&rendered, "secrets_detail_scrolled");
}

/// PMF-1: scrolled to the custom-fields region (reveal off). Pins that the
/// protected custom value renders masked (`••••••••`) end-to-end through the
/// render pipeline — the plaintext never reaches the golden — while the
/// unprotected field stays visible.
#[test]
fn detail_snapshot_custom_fields_masks_protected() {
    let data = detail_fixture();
    let lines = entry_detail::detail_lines(&data, false, &Theme::auto());
    // scroll=10 fills all 8 viewport rows (no trailing-empty-row mismatch in the
    // harness) while keeping the custom-fields region — incl. the masked
    // protected value — in view.
    let rendered = render_detail_at(&lines, 10);
    assert_snapshot(&rendered, "secrets_detail_custom_fields");
}

// ---- T7.4: tab-bar + Settings snapshots (layout-stable surfaces; R-5) ----

/// The tab strip with two pinned secrets, the first pin active. Pins the
/// fixed-anchor layout, the ` │ ` separators, and the `[active]` bracket
/// affordance (the NFR-015 text carrier for the active tab).
#[test]
fn tabbar_snapshot_with_pins() {
    let mut bar = TabBar::new();
    bar.set_pins_for_test(vec![Uuid::new_v4(), Uuid::new_v4()]);
    bar.jump_to(2); // ordinal 2 = the first pinned tab → active bracket on a pin
    let titles = vec!["aws-prod".to_string(), "github".to_string()];
    let theme = Theme::auto(); // text-only snapshot: palette does not affect symbols
    let lines = render_lines(60, 1, |frame| {
        let area = Rect::new(0, 0, 60, 1);
        bar.render(&titles, frame, area, &theme);
    });
    assert_snapshot(&lines, "tabbar");
}

/// An unlocked-but-unconfigured app's Settings tab. Built via `from_registry`
/// (no KDBX open needed — `from_registry` never opens the vault), so it renders
/// deterministically: the editor rows + their default toggle states, and the
/// secret-free "(no sync target configured)" / "Last sync: —" status sub-view.
fn settings_app() -> (tempfile::TempDir, App) {
    let dir = tempfile::tempdir().expect("tempdir");
    // Pin the config dir to a fixed path: the Settings status sub-view renders
    // the config-file path (T3.4), which would otherwise flake on the random
    // tempdir component. Nothing writes to it in a render-only snapshot.
    let paths = FalachPaths::with_state_dir(dir.path().join("state"))
        .with_config_dir(std::path::PathBuf::from("/home/user/.config/falach"));
    let mut registry = VaultRegistry::with_paths(paths.clone());
    registry
        .register(RegisteredVault {
            name: "personal".to_string(),
            path: dir.path().join("personal.kdbx"),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            keyfile_path: None,
            extra: toml::Table::new(),
        })
        .expect("register");
    let mut app =
        App::from_registry(registry, paths, AutoLockConfig::default()).expect("from_registry");
    // The Settings sub-view renders the live theme *name*, so pin a deterministic
    // theme (the truecolor `default`) instead of `Theme::auto()` — otherwise the
    // golden flakes on any host with `NO_COLOR`/`FALACH_TUI_THEME` set.
    app.theme = Theme::from_env_parts(None, false, Some("xterm-256color"), Some("truecolor"));
    (dir, app)
}

/// The quit confirmation dialog (T4.8): exact prompt text with a non-colour
/// carrier (the `y`/`n` wording), rendered via the overlay dispatch path.
#[test]
fn confirm_quit_snapshot() {
    let (_dir, mut app) = settings_app();
    app.overlay = Some(crate::overlay::Overlay::ConfirmQuit);
    // Height 5 == the dialog's exact height, so there is no trailing blank row
    // (which the golden reader would trim, causing a spurious length mismatch).
    let lines = render_lines(50, 5, |frame| crate::overlay::render(&app, frame));
    assert_snapshot(&lines, "confirm_quit");
}

#[test]
fn settings_tab_snapshot() {
    let (_dir, app) = settings_app();
    let lines = render_lines(50, 16, |frame| {
        let area = Rect::new(0, 0, 50, 16);
        crate::screens::settings::render(&app, frame, area);
    });
    assert_snapshot(&lines, "settings_tab");
}

/// The derived hint bar (T2.1) for the Secrets-tree context: navigation +
/// action cells, one command disabled (copy on a group row), the reserved
/// `? more` affordance last. A render-only golden — `build_hint_bar`'s output
/// (order, keys, states, dimming, truncation) is covered by the unit tests in
/// `widgets::hint_bar` / `app`; this pins the rendered span layout. The
/// dimming of the disabled cell is a *style* (`Modifier::DIM`) not visible in a
/// text golden — `disabled_commands_render_dimmed_not_dropped` asserts it — so
/// the value here is that the disabled cell is still *present* (not dropped).
#[test]
fn hint_bar_snapshot() {
    use crate::command::registry::CmdState;
    use crate::widgets::hint_bar::{render_hint_bar, HintCell};

    let cell = |keys: &str, desc: &'static str, state: CmdState| HintCell {
        desc,
        keys: keys.to_string(),
        state,
    };
    let cells = vec![
        cell("j", "down", CmdState::Enabled),
        cell("k", "up", CmdState::Enabled),
        cell("/", "search", CmdState::Enabled),
        cell("a", "add entry", CmdState::Enabled),
        cell("e", "edit entry", CmdState::Enabled),
        cell("c", "copy password", CmdState::Disabled),
        cell("?", "more", CmdState::Enabled),
    ];
    // Palette/theme does not affect the text symbols; `auto()` is fine here.
    // Width 80 fits the whole representative bar (the truncation path is unit-
    // tested in `truncation_keeps_whole_cells_and_more_indicator`).
    let theme = Theme::auto();
    let lines = render_lines(80, 1, |frame| {
        render_hint_bar(frame, Rect::new(0, 0, 80, 1), &cells, &theme);
    });
    assert_snapshot(&lines, "hint_bar_secrets_tree");
}

/// The which-key candidate menu (T2.2) for a pending `g` prefix: the two tab
/// motions it can reach, anchored bottom-right of the body area. Render-only
/// golden — the visibility gate / continuation build are unit-tested in
/// `widgets::which_key`.
#[test]
fn which_key_snapshot() {
    use crate::widgets::which_key::render_which_key;
    let rows = vec![
        ("t".to_string(), "next tab"),
        ("T".to_string(), "previous tab"),
    ];
    let theme = Theme::auto();
    let lines = render_lines(40, 10, |frame| {
        render_which_key(frame, Rect::new(0, 0, 40, 10), &rows, &theme);
    });
    assert_snapshot(&lines, "which_key_g_prefix");
}

/// The command palette (T2.3), unfiltered: group headers + rows (`desc  [keys]`)
/// over the Secrets-tree context. Built via `settings_app` (deterministic theme,
/// no vault — entry-scoped rows list disabled, which the text golden captures as
/// still-present, not dropped). Row-building/filtering are unit-tested in `app`.
#[test]
fn palette_top_snapshot() {
    use crate::command::registry::Contexts;
    use crate::overlay::palette::{self, PaletteState};
    let (_dir, app) = settings_app();
    let state = PaletteState::new(Contexts::SECRETS_TREE);
    let lines = trim_trailing_blank(render_lines(60, 22, |frame| {
        palette::render(&app, &state, frame);
    }));
    assert_snapshot(&lines, "palette_top");
}

/// The palette filtered to `copy` — headers drop, rows rank by match score.
#[test]
fn palette_filtered_snapshot() {
    use crate::command::registry::Contexts;
    use crate::overlay::palette::{self, PaletteState};
    let (_dir, app) = settings_app();
    let mut state = PaletteState::new(Contexts::SECRETS_TREE);
    state.input = tui_input::Input::new("copy".to_string());
    let lines = trim_trailing_blank(render_lines(60, 22, |frame| {
        palette::render(&app, &state, frame);
    }));
    assert_snapshot(&lines, "palette_filtered");
}

/// Narrow search overlay: pins query/scope header, visible-row quick-select
/// labels, metadata columns, match text, and the no-preview responsive layout.
#[test]
fn search_overlay_snapshot() {
    use crate::app::Focus;
    use crate::overlay::search::{self, SavedView, SearchRow, SearchState};
    use falach_core::SearchScope;

    let (_dir, app) = settings_app();
    let mut state = SearchState::new(
        SearchScope::All,
        SavedView {
            selected: None,
            focus: Focus::Tree,
            detail_scroll: 0,
        },
    );
    state.input = tui_input::Input::new("git".to_string());
    state.set_results(vec![
        SearchRow {
            uuid: Uuid::new_v4(),
            title: "GitHub Production".to_string(),
            username: "octocat".to_string(),
            url_host: "github.com".to_string(),
            tags: "work".to_string(),
            title_indices: vec![0, 1, 2],
        },
        SearchRow {
            uuid: Uuid::new_v4(),
            title: "Long prefix around a git match for truncation".to_string(),
            username: "dev".to_string(),
            url_host: String::new(),
            tags: String::new(),
            title_indices: vec![21, 22, 23],
        },
    ]);
    let lines = render_lines(60, 16, |frame| search::render(&app, &state, frame));
    assert_snapshot(&lines, "search_overlay_narrow");
}

/// Drop trailing all-blank rows so a centred modal's bottom margin does not trip
/// the harness (which trims trailing newlines when reading the golden back).
fn trim_trailing_blank(mut lines: Vec<String>) -> Vec<String> {
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

// ---- PMF-4 / T4.4: the harness must not fail open on a missing golden ----

#[test]
fn missing_golden_fails_in_normal_run() {
    // The regression the old fail-open hid: a deleted/renamed golden must
    // FAIL a normal run, not silently self-heal to green. Drives
    // `assert_snapshot_inner` directly with `update = false` so this is
    // independent of the process-wide FALACH_UPDATE_SNAPSHOTS (which
    // `make test-update-snapshots` sets for the whole run).
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("does_not_exist.txt");
    let result = std::panic::catch_unwind(|| {
        assert_snapshot_inner(&["row".to_string()], &missing, "does_not_exist", false);
    });
    assert!(
        result.is_err(),
        "a missing golden in normal (non-update) mode must panic, not pass"
    );
    assert!(
        !missing.exists(),
        "normal mode must not auto-create the missing golden"
    );
}

#[test]
fn update_mode_creates_missing_golden() {
    // The companion path: under update mode the golden IS (re)generated,
    // creating parent dirs as needed — what `make test-update-snapshots` relies on.
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("nested/new_golden.txt");
    assert_snapshot_inner(
        &["hello".to_string(), "world".to_string()],
        &target,
        "new_golden",
        true,
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("golden written"),
        "hello\nworld\n"
    );
}
