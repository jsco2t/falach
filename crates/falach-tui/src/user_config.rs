//! `UserConfig` — the TUI's user-editable preferences in
//! `~/.config/falach/config.toml` (TUI enhancements design §2.2.5; T3.1).
//!
//! The config-vs-state split (2026-07-14 scoping decision) separates two
//! concerns that historically shared `tui.toml`:
//!
//! - **`config.toml`** (this module, `$XDG_CONFIG_HOME/falach/` or
//!   `$HOME/.config/falach/`) holds **user preferences**: default sort, the
//!   two sync-trigger toggles, keymap preset + rebinds, theme selection, search
//!   defaults, the mouse toggle, and the tree-pane ratio. It is hand-edited and
//!   **auto-generated fully commented on first run** (the bottom pattern — the
//!   file *is* the documentation).
//! - **`tui.toml`** ([`crate::config`], the state dir) keeps **machine state**
//!   ONLY: per-vault pins and recents.
//!
//! **No migration (A-5, 2026-07-18):** nothing has been released, so the prefs
//! that used to live in `tui.toml` simply move here. `tui.toml` stops
//! reading/writing them; any stray legacy keys round-trip harmlessly through
//! its lenient `extra` mechanism.
//!
//! **Lenient by design** (mirrors [`crate::config`]): a missing file is
//! generated then treated as defaults; an unparsable file degrades to defaults
//! plus a status-bar warning. Warnings name the file **path and line number
//! only** — never the file's content, which may contain anything (design §2.5).

use std::path::Path;

use falach_core::atomic::write_atomic;
use falach_core::locking::acquire_exclusive;
use falach_core::FalachPaths;
use serde::{Deserialize, Serialize};

use crate::command::keymap::KeymapPatch;
use crate::widgets::entry_tree::SortOrder;

/// Minimum accepted `[layout] tree-ratio` (percent). Below this the tree pane
/// is unusably narrow; out-of-range values clamp here with a warning.
pub(crate) const TREE_RATIO_MIN: u8 = 20;
/// Maximum accepted `[layout] tree-ratio` (percent). Above this the detail pane
/// starves.
pub(crate) const TREE_RATIO_MAX: u8 = 60;

// --- default helpers (shared by `Default` impls and serde field defaults so
// the two can never drift; the `defaults_are_documented` test pins them to the
// generated catalog) ---

fn default_sort() -> SortOrder {
    SortOrder::RecentlyUsed
}
fn default_theme_dark() -> String {
    "default-dark".to_string()
}
fn default_theme_light() -> String {
    "default-light".to_string()
}
fn default_search_scope() -> String {
    "all".to_string()
}
fn default_mouse() -> bool {
    true
}
fn default_tree_ratio() -> u8 {
    35
}

/// Light/dark theme selection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ThemeMode {
    /// Pick `dark`/`light` from a terminal-background heuristic (design §2.2.4).
    #[default]
    Auto,
    /// Always use the configured `dark` theme.
    Dark,
    /// Always use the configured `light` theme.
    Light,
}

/// What the search overlay's primary action (Enter) does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EnterAction {
    /// Copy the selected entry's password + arm auto-clear (the 90% action).
    #[default]
    Copy,
    /// Open the entry (jump tree to it, focus detail).
    Open,
}

/// `[behavior]` — general preferences (moved verbatim from `tui.toml`, plus
/// `confirm-quit`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub(crate) struct BehaviorCfg {
    #[serde(default = "default_sort")]
    pub default_sort: SortOrder,
    #[serde(default)]
    pub sync_on_unlock: bool,
    #[serde(default)]
    pub sync_on_lock_quit: bool,
    #[serde(default)]
    pub confirm_quit: bool,
}

impl Default for BehaviorCfg {
    fn default() -> Self {
        Self {
            default_sort: default_sort(),
            sync_on_unlock: false,
            sync_on_lock_quit: false,
            confirm_quit: false,
        }
    }
}

/// `[theme]` — theme selection (the palettes themselves live in [`crate::theme`]).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub(crate) struct ThemeCfg {
    #[serde(default = "default_theme_dark")]
    pub dark: String,
    #[serde(default = "default_theme_light")]
    pub light: String,
    #[serde(default)]
    pub mode: ThemeMode,
}

impl Default for ThemeCfg {
    fn default() -> Self {
        Self {
            dark: default_theme_dark(),
            light: default_theme_light(),
            mode: ThemeMode::default(),
        }
    }
}

/// `[search]` — search-overlay defaults.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub(crate) struct SearchCfg {
    #[serde(default = "default_search_scope")]
    pub default_scope: String,
    #[serde(default)]
    pub enter_action: EnterAction,
}

impl Default for SearchCfg {
    fn default() -> Self {
        Self {
            default_scope: default_search_scope(),
            enter_action: EnterAction::default(),
        }
    }
}

/// `[layout]` — workspace geometry knobs.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub(crate) struct LayoutCfg {
    /// Tree-pane width as a percent of the workspace. Clamped to
    /// `TREE_RATIO_MIN..=TREE_RATIO_MAX` on load (with a warning).
    #[serde(default = "default_tree_ratio")]
    pub tree_ratio: u8,
}

impl Default for LayoutCfg {
    fn default() -> Self {
        Self {
            tree_ratio: default_tree_ratio(),
        }
    }
}

/// The user-editable TUI preferences (`config.toml`).
///
/// `#[serde(default)]` at the container level makes every section optional, so
/// a partial file (only the keys the user overrode) loads cleanly. `mouse`
/// carries an explicit `#[serde(default = "default_mouse")]` because the serde
/// default for `bool` is `false` — the trap that would silently disable the
/// mouse for everyone (guarded by `mouse_defaults_true`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub(crate) struct UserConfig {
    /// Master mouse toggle (`--no-mouse` overrides to `false`).
    #[serde(default = "default_mouse")]
    pub mouse: bool,
    #[serde(default)]
    pub behavior: BehaviorCfg,
    #[serde(default)]
    pub keymap: KeymapPatch,
    #[serde(default)]
    pub theme: ThemeCfg,
    #[serde(default)]
    pub search: SearchCfg,
    #[serde(default)]
    pub layout: LayoutCfg,
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            mouse: default_mouse(),
            behavior: BehaviorCfg::default(),
            keymap: KeymapPatch::default(),
            theme: ThemeCfg::default(),
            search: SearchCfg::default(),
            layout: LayoutCfg::default(),
        }
    }
}

impl UserConfig {
    /// The persisted default tree sort.
    pub(crate) fn default_sort(&self) -> SortOrder {
        self.behavior.default_sort
    }

    /// Advance the default tree sort to the next order and return it (Settings
    /// editor). The caller persists via [`UserConfig::save`].
    pub(crate) fn cycle_default_sort(&mut self) -> SortOrder {
        self.behavior.default_sort = self.behavior.default_sort.next();
        self.behavior.default_sort
    }

    /// Whether auto-sync-on-unlock is enabled.
    pub(crate) fn sync_on_unlock(&self) -> bool {
        self.behavior.sync_on_unlock
    }

    /// Whether auto-sync-on-lock/quit is enabled.
    pub(crate) fn sync_on_lock_quit(&self) -> bool {
        self.behavior.sync_on_lock_quit
    }

    /// Whether quitting requires an explicit confirmation (T4.8).
    pub(crate) fn confirm_quit(&self) -> bool {
        self.behavior.confirm_quit
    }

    #[cfg(test)]
    pub(crate) fn set_confirm_quit_for_test(&mut self, on: bool) {
        self.behavior.confirm_quit = on;
    }

    /// Set the auto-sync-on-unlock toggle. The caller persists.
    pub(crate) fn set_sync_on_unlock(&mut self, on: bool) {
        self.behavior.sync_on_unlock = on;
    }

    /// Set the auto-sync-on-lock/quit toggle. The caller persists.
    pub(crate) fn set_sync_on_lock_quit(&mut self, on: bool) {
        self.behavior.sync_on_lock_quit = on;
    }

    /// Test seam: set the default sort directly (the load path sets it from
    /// `[behavior] default-sort`).
    #[cfg(test)]
    pub(crate) fn set_default_sort_for_test(&mut self, sort: SortOrder) {
        self.behavior.default_sort = sort;
    }

    /// Load `config.toml` from `paths`. **Never fails.**
    ///
    /// - **Absent file:** the fully-commented default catalog is generated at
    ///   `paths.config_toml()` (best-effort), and defaults are returned.
    /// - **Present file:** parsed leniently — a parse error yields defaults plus
    ///   a warning naming the file path and line number (never content).
    /// - **`tree-ratio` out of range:** clamped, with a warning.
    ///
    /// Returned warnings are surfaced in the status bar's startup notices.
    pub(crate) fn load(paths: &FalachPaths) -> (Self, Vec<String>) {
        let path = paths.config_toml();
        if let Err(e) = paths.ensure_config_dir_exists() {
            return (
                Self::default(),
                vec![format!("Could not create config dir: {e}")],
            );
        }
        load_or_generate(&path)
    }

    /// Load from an explicit path. Missing explicit files are generated at that
    /// exact path so later Settings edits and the displayed path stay coherent.
    pub(crate) fn load_from(path: &Path) -> (Self, Vec<String>) {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return (
                    Self::default(),
                    vec![format!("Could not create {}: {e}", parent.display())],
                );
            }
        }
        load_or_generate(path)
    }

    /// Reload the latest file under its advisory lock, apply one Settings
    /// mutation, and atomically save it. This merge-on-write prevents two TUI
    /// sessions changing unrelated preferences from losing each other's edit.
    pub(crate) fn update_at(
        path: &Path,
        update: impl FnOnce(&mut UserConfig),
    ) -> Result<Self, String> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Could not create {}: {e}", parent.display()))?;
        }
        let _guard = acquire_exclusive(path)
            .map_err(|e| format!("Could not lock {}: {e}", path.display()))?;
        let mut latest = match std::fs::read_to_string(path) {
            Ok(contents) => parse_strict_and_clamp(&contents, path)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(format!("Could not read {}: {e}", path.display())),
        };
        update(&mut latest);
        save_unlocked(&latest, path)?;
        Ok(latest)
    }

    /// Serialize to the effective config path. Callers performing interactive
    /// field edits should prefer [`Self::update_at`] for merge-on-write.
    #[cfg(test)]
    pub(crate) fn save_to(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Could not create {}: {e}", parent.display()))?;
        }
        let _guard = acquire_exclusive(path)
            .map_err(|e| format!("Could not lock {}: {e}", path.display()))?;
        save_unlocked(self, path)
    }

    #[cfg(test)]
    pub(crate) fn save(&self, paths: &FalachPaths) -> Result<(), String> {
        self.save_to(&paths.config_toml())
    }
}

fn load_or_generate(path: &Path) -> (UserConfig, Vec<String>) {
    match std::fs::read_to_string(path) {
        Ok(contents) => return parse_and_clamp(&contents, path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return (
                UserConfig::default(),
                vec![format!(
                    "Could not read {}; using defaults.",
                    path.display()
                )],
            )
        }
    }
    let _guard = match acquire_exclusive(path) {
        Ok(guard) => guard,
        Err(e) => {
            return (
                UserConfig::default(),
                vec![format!("Could not lock {}: {e}", path.display())],
            )
        }
    };
    // Recheck after locking: another first-run process may have generated the
    // file between our initial read and lock acquisition.
    match std::fs::read_to_string(path) {
        Ok(contents) => parse_and_clamp(&contents, path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut warnings = Vec::new();
            if let Err(msg) = write_atomic(path, DEFAULT_CONFIG_CATALOG.as_bytes())
                .map_err(|e| format!("Could not write {}: {e}", path.display()))
            {
                warnings.push(msg);
            }
            (UserConfig::default(), warnings)
        }
        Err(_) => (
            UserConfig::default(),
            vec![format!(
                "Could not read {}; using defaults.",
                path.display()
            )],
        ),
    }
}

fn save_unlocked(config: &UserConfig, path: &Path) -> Result<(), String> {
    let body = toml::to_string(&OnDisk::from(config))
        .map_err(|_| "Could not serialize config.toml".to_string())?;
    write_atomic(path, body.as_bytes())
        .map_err(|e| format!("Could not save {}: {e}", path.display()))
}

fn parse_strict_and_clamp(contents: &str, path: &Path) -> Result<UserConfig, String> {
    let parsed = toml::from_str::<UserConfig>(contents).map_err(|e| {
        let where_ = e
            .span()
            .map(|s| format!(" (line {})", line_of(contents, s.start)))
            .unwrap_or_default();
        format!(
            "Could not parse {}{where_}; refusing to overwrite it.",
            path.display()
        )
    })?;
    let (parsed, warnings) = clamp(parsed);
    if warnings.is_empty() {
        Ok(parsed)
    } else {
        Err(format!(
            "{} contains a value that requires normalization; refusing to overwrite it.",
            path.display()
        ))
    }
}

/// Parse `contents` into a [`UserConfig`], clamping `tree-ratio` and collecting
/// warnings (path/line only; never content).
fn parse_and_clamp(contents: &str, path: &Path) -> (UserConfig, Vec<String>) {
    match toml::from_str::<UserConfig>(contents) {
        Ok(cfg) => clamp(cfg),
        Err(e) => {
            // Never echo `e`'s Display (it quotes the offending TOML); report
            // the path and the 1-based line derived from the error span only.
            let where_ = match e.span() {
                Some(span) => format!(" (line {})", line_of(contents, span.start)),
                None => String::new(),
            };
            (
                UserConfig::default(),
                vec![format!(
                    "Could not parse {}{where_}; using defaults.",
                    path.display()
                )],
            )
        }
    }
}

fn clamp(mut cfg: UserConfig) -> (UserConfig, Vec<String>) {
    let mut warnings = Vec::new();
    if !matches!(cfg.search.default_scope.as_str(), "all" | "group" | "tag") {
        warnings.push(format!(
            "config.toml: unknown search default-scope; using {}",
            default_search_scope()
        ));
        cfg.search.default_scope = default_search_scope();
    }
    let raw = cfg.layout.tree_ratio;
    let clamped = raw.clamp(TREE_RATIO_MIN, TREE_RATIO_MAX);
    if clamped != raw {
        warnings.push(format!("config.toml: tree-ratio {raw} out of range {TREE_RATIO_MIN}..={TREE_RATIO_MAX}; using {clamped}"));
        cfg.layout.tree_ratio = clamped;
    }
    (cfg, warnings)
}

/// The 1-based line containing byte offset `at` in `contents`.
fn line_of(contents: &str, at: usize) -> usize {
    let end = at.min(contents.len());
    contents[..end].bytes().filter(|&b| b == b'\n').count() + 1
}

// ---------------------------------------------------------------------------
// On-disk serialization shape.
//
// `UserConfig` derives only `Deserialize`; a separate `Serialize`-only
// `OnDisk` view (mirroring `crate::config`) keeps the read and write formats
// explicit and lets Settings-tab saves emit stable kebab-case keys.
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
#[serde(rename_all = "kebab-case")]
struct OnDisk {
    mouse: bool,
    behavior: OnDiskBehavior,
    theme: OnDiskTheme,
    search: OnDiskSearch,
    layout: OnDiskLayout,
    /// The user's keymap patch is written back verbatim so a Settings-tab save
    /// never drops hand-configured rebinds/preset. Skipped when empty so a
    /// pristine config stays free of an empty `[keymap]` section. (Emitted last:
    /// TOML requires table-valued keys after the top-level `mouse` scalar, and
    /// `[keymap.bindings]` is itself a nested table.)
    #[serde(skip_serializing_if = "keymap_is_empty")]
    keymap: KeymapPatch,
}

/// Whether a keymap patch carries nothing worth persisting (no preset override,
/// no rebinds) — the `skip_serializing_if` predicate for `OnDisk::keymap`.
fn keymap_is_empty(k: &KeymapPatch) -> bool {
    k.preset.is_none() && k.bindings.is_empty()
}

#[derive(serde::Serialize)]
#[serde(rename_all = "kebab-case")]
struct OnDiskBehavior {
    default_sort: SortOrder,
    sync_on_unlock: bool,
    sync_on_lock_quit: bool,
    confirm_quit: bool,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "kebab-case")]
struct OnDiskTheme {
    dark: String,
    light: String,
    mode: ThemeMode,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "kebab-case")]
struct OnDiskSearch {
    default_scope: String,
    enter_action: EnterAction,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "kebab-case")]
struct OnDiskLayout {
    tree_ratio: u8,
}

impl From<&UserConfig> for OnDisk {
    fn from(c: &UserConfig) -> Self {
        OnDisk {
            mouse: c.mouse,
            behavior: OnDiskBehavior {
                default_sort: c.behavior.default_sort,
                sync_on_unlock: c.behavior.sync_on_unlock,
                sync_on_lock_quit: c.behavior.sync_on_lock_quit,
                confirm_quit: c.behavior.confirm_quit,
            },
            theme: OnDiskTheme {
                dark: c.theme.dark.clone(),
                light: c.theme.light.clone(),
                mode: c.theme.mode,
            },
            search: OnDiskSearch {
                default_scope: c.search.default_scope.clone(),
                enter_action: c.search.enter_action,
            },
            layout: OnDiskLayout {
                tree_ratio: c.layout.tree_ratio,
            },
            keymap: c.keymap.clone(),
        }
    }
}

/// The fully-commented default `config.toml`, written on first run.
///
/// **Format contract** (relied on by `generated_default_file_uncommented_parses_to_defaults`):
/// every *option* line and *section header* is commented as `#key = value` /
/// `#[section]` — a `#` immediately followed by a lowercase letter or `[`.
/// Explanatory prose uses `# ` (hash + space). Uncommenting = stripping one
/// leading `#` from every line whose second char is `[a-z[`; the result must
/// parse to [`UserConfig::default()`]. Every non-`keymap` field therefore
/// appears here set to its default; `keymap` is documented in prose (its
/// binding grammar is too rich for a single default line).
pub(crate) const DEFAULT_CONFIG_CATALOG: &str = r#"# Falach TUI configuration (config.toml)
#
# Auto-generated on first run with every option commented out and set to its
# default. Remove the leading '#' from any line below to override it. Lines
# beginning with '# ' (hash + space) are explanations and are ignored.
#
# This file holds preferences ONLY. Machine state (pinned tabs, recents) lives
# separately in tui.toml under the state directory and is not edited by hand.

# mouse — enable clickable tabs/tree/search/palette rows and wheel scrolling.
# Keyboard access remains available for every mouse action.
#mouse = true

#[behavior]
# default-sort — initial Secrets-tree sort order.
#   "recently-used" | "title" | "last-modified" | "group"
#default-sort = "recently-used"
# sync-on-unlock — automatically sync right after unlocking a vault.
#sync-on-unlock = false
# sync-on-lock-quit — automatically sync when leaving a vault (lock or quit).
#sync-on-lock-quit = false
# confirm-quit — ask for confirmation (y/n) before quitting.
#confirm-quit = false

#[theme]
# dark / light — the built-in or user theme name used for each background.
#   Built-ins: "default-dark", "default-light", "accessible", "slate", "paper".
#   A user theme is the file stem of a ~/.config/falach/themes/<name>.toml.
#dark = "default-dark"
#light = "default-light"
# mode — which of dark/light to use: "auto" | "dark" | "light".
#   "auto" picks from the terminal background (COLORFGBG heuristic), else dark.
#mode = "auto"

#[search]
# Fuzzy-search overlay defaults.
# default-scope — opening scope: "all" | "group" | "tag". Group/tag use the
# current tree selection and fall back to the whole vault when unavailable.
#default-scope = "all"
# enter-action — what Enter does in the search overlay: "copy" | "open".
#   Tab always performs the opposite action, so both remain one key away.
#enter-action = "copy"

#[layout]
# tree-ratio — Secrets-tree pane width as a percent of the workspace.
#   Clamped to 20..=60 on load.
#tree-ratio = 35

# [keymap] — keybinding customization (not shown as a default line because the
# binding grammar is richer than a single value). Select a base preset and then
# override individual command slots. Example:
#
#   [keymap]
#   preset = "vim"           # "vim" (default) or "plain" (arrow-first, no chords)
#
#   [keymap.bindings]
#   copy-password = "y"      # rebind a command to one key
#   search = ["/", "ctrl+f"] # ...or several keys
#   pin-toggle = false       # ...or false to unbind it
#
# Run `falach-tui --dump-keys` to print the effective keymap. Unknown or
# conflicting rebinds are reported at startup and otherwise ignored.
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::keymap::{BindValue, Keymap, Preset};

    fn paths_in(dir: &Path) -> FalachPaths {
        FalachPaths::with_state_dir(dir.join("state")).with_config_dir(dir.join("config"))
    }

    /// Transform the catalog the way a user would to enable every option:
    /// strip one leading `#` from each line whose second char is a lowercase
    /// ASCII letter or `[` (option lines and section headers), leaving prose
    /// (`# ...`) as comments.
    fn uncomment_catalog(catalog: &str) -> String {
        catalog
            .lines()
            .map(|line| {
                let rest = line.strip_prefix('#');
                match rest.and_then(|r| r.chars().next()) {
                    Some(c) if c.is_ascii_lowercase() || c == '[' => rest.unwrap().to_string(),
                    _ => line.to_string(),
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn generated_default_file_uncommented_parses_to_defaults() {
        let enabled = uncomment_catalog(DEFAULT_CONFIG_CATALOG);
        let parsed: UserConfig = toml::from_str(&enabled)
            .unwrap_or_else(|e| panic!("uncommented catalog must parse: {e}\n---\n{enabled}"));
        assert_eq!(
            parsed,
            UserConfig::default(),
            "uncommenting every option must reproduce the defaults"
        );
    }

    #[test]
    fn defaults_are_documented() {
        // Each field's default value must appear as a commented option line so
        // the catalog cannot document a stale default.
        let c = DEFAULT_CONFIG_CATALOG;
        for needle in [
            "#mouse = true",
            "#default-sort = \"recently-used\"",
            "#sync-on-unlock = false",
            "#sync-on-lock-quit = false",
            "#confirm-quit = false",
            "#dark = \"default-dark\"",
            "#light = \"default-light\"",
            "#mode = \"auto\"",
            "#default-scope = \"all\"",
            "#enter-action = \"copy\"",
            "#tree-ratio = 35",
        ] {
            assert!(
                c.contains(needle),
                "catalog missing documented default: {needle}"
            );
        }
        assert!(
            !c.contains("reserved for Phase 4"),
            "live mouse/search settings must not be labeled as reserved"
        );
        assert!(c.contains("enable clickable tabs/tree/search/palette rows"));
    }

    #[test]
    fn invalid_default_scope_falls_back_with_warning() {
        let (cfg, warnings) = clamp(UserConfig {
            search: SearchCfg {
                default_scope: "somewhere".to_string(),
                ..SearchCfg::default()
            },
            ..UserConfig::default()
        });
        assert_eq!(cfg.search.default_scope, "all");
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn first_run_creates_file_second_run_leaves_it() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let path = paths.config_toml();

        assert!(!path.exists(), "precondition: no config file yet");
        let (_cfg, warnings) = UserConfig::load(&paths);
        assert!(
            warnings.is_empty(),
            "first-run generation warns nothing: {warnings:?}"
        );
        assert!(path.exists(), "first run generates the file");
        let first = std::fs::read(&path).unwrap();

        let (_cfg2, warnings2) = UserConfig::load(&paths);
        assert!(warnings2.is_empty());
        let second = std::fs::read(&path).unwrap();
        assert_eq!(first, second, "second run must not rewrite the file");
    }

    #[test]
    fn mouse_defaults_true() {
        // The serde-bool-default trap: an empty file must NOT disable the mouse.
        let (cfg, warnings) = parse_and_clamp("", Path::new("config.toml"));
        assert!(warnings.is_empty());
        assert!(cfg.mouse, "mouse must default to true on an empty file");
    }

    #[test]
    fn partial_edit_changes_exactly_one_option() {
        let (cfg, warnings) = parse_and_clamp(
            "[behavior]\ndefault-sort = \"title\"\n",
            Path::new("config.toml"),
        );
        assert!(warnings.is_empty());
        assert_eq!(
            cfg.behavior.default_sort,
            SortOrder::Title,
            "the edited option"
        );
        // Everything else stays at its default.
        let d = UserConfig::default();
        assert_eq!(cfg.mouse, d.mouse);
        assert_eq!(cfg.behavior.sync_on_unlock, d.behavior.sync_on_unlock);
        assert_eq!(cfg.theme, d.theme);
        assert_eq!(cfg.search, d.search);
        assert_eq!(cfg.layout, d.layout);
    }

    #[test]
    fn tree_ratio_clamped() {
        let (hi, w_hi) = parse_and_clamp("[layout]\ntree-ratio = 90\n", Path::new("config.toml"));
        assert_eq!(hi.layout.tree_ratio, 60, "above range clamps to max");
        assert!(w_hi.iter().any(|w| w.contains("tree-ratio")), "{w_hi:?}");

        let (lo, w_lo) = parse_and_clamp("[layout]\ntree-ratio = 5\n", Path::new("config.toml"));
        assert_eq!(lo.layout.tree_ratio, 20, "below range clamps to min");
        assert!(w_lo.iter().any(|w| w.contains("tree-ratio")), "{w_lo:?}");

        let (ok, w_ok) = parse_and_clamp("[layout]\ntree-ratio = 40\n", Path::new("config.toml"));
        assert_eq!(ok.layout.tree_ratio, 40, "in-range value untouched");
        assert!(w_ok.is_empty(), "in-range value must not warn");
    }

    #[test]
    fn corrupt_file_degrades_with_warning_no_content_echo() {
        const SENTINEL: &str = "SUPERSECRETSENTINEL";
        let src = format!("mouse = {SENTINEL}\nthis is = = not valid [[[\n");
        let (cfg, warnings) = parse_and_clamp(&src, Path::new("/x/config.toml"));
        assert_eq!(cfg, UserConfig::default(), "corrupt file → defaults");
        assert_eq!(warnings.len(), 1, "one parse warning");
        let w = &warnings[0];
        assert!(w.contains("/x/config.toml"), "warning names the path: {w}");
        assert!(w.contains("line"), "warning names a line: {w}");
        assert!(
            !w.contains(SENTINEL),
            "warning must never echo file content: {w}"
        );
    }

    #[test]
    fn keymap_section_flows_to_keymap() {
        // The config→keymap seam (T3.1 meets T1.3): a `[keymap]` section with a
        // preset + a rebind must produce a Keymap reflecting BOTH.
        let (cfg, warnings) = parse_and_clamp(
            "[keymap]\npreset = \"plain\"\n\n[keymap.bindings]\ncopy-password = \"y\"\n",
            Path::new("config.toml"),
        );
        assert!(warnings.is_empty());
        assert_eq!(cfg.keymap.preset, Some(Preset::Plain));
        assert_eq!(
            cfg.keymap.bindings.get("copy-password"),
            Some(&BindValue::One("y".to_string()))
        );
        // And it builds a working keymap with no warnings.
        let (_km, km_warnings) = Keymap::from_patch(&cfg.keymap);
        assert!(km_warnings.is_empty(), "clean rebind: {km_warnings:?}");
    }

    #[test]
    fn save_round_trips_through_load() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let mut cfg = UserConfig::default();
        cfg.set_sync_on_unlock(true);
        cfg.behavior.default_sort = SortOrder::Title;
        cfg.save(&paths).expect("save");

        let (loaded, warnings) = UserConfig::load(&paths);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(loaded.sync_on_unlock());
        assert_eq!(loaded.default_sort(), SortOrder::Title);
    }

    #[test]
    fn save_preserves_keymap_section() {
        // A Settings-tab save must NOT drop a hand-configured `[keymap]` — else a
        // user's preset/rebinds silently vanish on the next launch after they
        // toggle any setting. Regression for the OnDisk-omits-keymap bug.
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let (mut cfg, warnings) = parse_and_clamp(
            "[keymap]\npreset = \"plain\"\n\n[keymap.bindings]\ncopy-password = \"y\"\n",
            &paths.config_toml(),
        );
        assert!(warnings.is_empty());
        assert_eq!(cfg.keymap.preset, Some(Preset::Plain));

        // Simulate a Settings change + save.
        cfg.set_sync_on_unlock(true);
        cfg.save(&paths).expect("save");

        // The written file still carries the keymap section...
        let on_disk = std::fs::read_to_string(paths.config_toml()).unwrap();
        assert!(
            on_disk.contains("preset = \"plain\""),
            "keymap preset persisted: {on_disk}"
        );
        assert!(
            on_disk.contains("copy-password"),
            "keymap rebind persisted: {on_disk}"
        );

        // ...and it reloads intact.
        let (loaded, warnings) = UserConfig::load(&paths);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(loaded.keymap.preset, Some(Preset::Plain));
        assert_eq!(
            loaded.keymap.bindings.get("copy-password"),
            Some(&BindValue::One("y".to_string()))
        );
        assert!(
            loaded.sync_on_unlock(),
            "the toggled setting also persisted"
        );
    }

    #[test]
    fn save_omits_empty_keymap_section() {
        // A pristine config (no keymap customization) must not emit a stray
        // empty `[keymap]` table.
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        UserConfig::default().save(&paths).expect("save");
        let on_disk = std::fs::read_to_string(paths.config_toml()).unwrap();
        assert!(
            !on_disk.contains("[keymap]"),
            "empty keymap must not be written: {on_disk}"
        );
    }

    #[test]
    fn explicit_path_is_generated_and_updated_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom/preferences.toml");
        let (cfg, warnings) = UserConfig::load_from(&path);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(path.exists());
        assert_eq!(cfg, UserConfig::default());

        let updated = UserConfig::update_at(&path, |cfg| cfg.set_sync_on_unlock(true))
            .expect("update explicit path");
        assert!(updated.sync_on_unlock());
        let (reloaded, warnings) = UserConfig::load_from(&path);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(reloaded.sync_on_unlock());
    }

    #[test]
    fn merge_on_write_preserves_disjoint_concurrent_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        UserConfig::load_from(&path);
        let stale = UserConfig::load_from(&path).0;

        UserConfig::update_at(&path, |cfg| cfg.set_sync_on_unlock(true)).expect("first writer");
        let next_sort = stale.default_sort().next();
        let merged = UserConfig::update_at(&path, |cfg| cfg.behavior.default_sort = next_sort)
            .expect("second writer");

        assert!(merged.sync_on_unlock(), "first writer's field survives");
        assert_eq!(merged.default_sort(), next_sort);
    }

    #[test]
    fn contended_config_update_is_non_destructive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        UserConfig::load_from(&path);
        let before = std::fs::read(&path).unwrap();
        let _guard = acquire_exclusive(&path).unwrap();
        let result = UserConfig::update_at(&path, |cfg| cfg.set_sync_on_unlock(true));
        assert!(result.unwrap_err().contains("Could not lock"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn failed_update_does_not_overwrite_or_return_mutated_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[behavior\ninvalid = true\n").unwrap();
        let before = std::fs::read(&path).unwrap();
        let result = UserConfig::update_at(&path, |cfg| cfg.set_sync_on_unlock(true));
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn update_refuses_to_silently_rewrite_an_out_of_range_external_edit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[layout]\ntree-ratio = 99\n").unwrap();
        let before = std::fs::read(&path).unwrap();
        let result = UserConfig::update_at(&path, |cfg| cfg.set_sync_on_unlock(true));
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
