//! `App` — the single source of truth for the running TUI.
//!
//! The [`Phase`] state machine drives the pre-unlock screens (`UnlockList` →
//! `UnlockPrompt` → `LockScreen`) and the unlocked `Workspace` (tab bar + active
//! tab + status bar). Auto-lock (FR-073) is wired in [`App::tick`].
//!
//! **Phase 4 (persistence + pins + recents):** on unlock the workspace is
//! hydrated from `tui.toml` (per-vault pinned tabs + recents), the tree sort
//! defaults to the global preference in `config.toml`, and pin toggles / recents bumps
//! mirror back to `tui.toml`. Overlays (Phase 5) and sync/Settings (Phase 6)
//! land later.
//!
//! Master-password lifetime (ADR-T4): the App holds **no** `MasterPassword`
//! field. The typed password lives only in the `UnlockPrompt`'s
//! [`PasswordInput`] until submit, is moved into `MasterPassword::new` for the
//! `Vault::open` call, and is dropped (zeroized) immediately after.

use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Utc;
use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use falach_core::{
    EntryBuilder, EntryKind, FalachPaths, MasterPassword, MatchedField, SearchOptions,
    SearchResult, SearchScope, Uuid, Vault, VaultError, VaultRegistry,
};
use falach_security::vault_lock::VaultLockConfig;
use falach_security::{AutoLockConfig, AutoLockController, LockState};
use ratatui::layout::Rect;
use ratatui::Frame;

use falach_sync::{S3Config, Sync, SyncConfig, SyncError, SyncOutcome};

use crate::args::Args;
use crate::clipboard::{self, ClipboardSink};
use crate::command::registry::{CmdState, Contexts};
use crate::command::{Command, Keymap, PendingSeq, Preset, Resolution};
use crate::config::{self, TuiConfig};
use crate::error::TuiError;
use crate::jump_history::JumpHistory;
use crate::overlay::bulk::{GroupChoice, GroupPickerState, TagInputState};
use crate::overlay::edit::{Col, EditField, EditState, EditValues};
use crate::overlay::generate::{Class, GenState};
use crate::overlay::history::HistoryState;
use crate::overlay::search::{self, SearchState};
use crate::overlay::sync_config::{SyncConfigState, SyncField};
use crate::overlay::{self, Overlay, TagAction};
use crate::recents::Recents;
use crate::screens;
use crate::sync_runtime::{SyncMsg, SyncResult, SyncRuntime, SyncTrigger};
use crate::tabs::{PinChange, Tab, TabBar, MAX_PINS};
use crate::theme::{self, EnvParts, Theme, UserThemeFile, BUILTIN_NAMES};
use crate::user_config::UserConfig;
use crate::widgets::entry_detail;
use crate::widgets::entry_tree::{self, TreeState};
use crate::widgets::password_input::{InputAction, PasswordInput};
use crate::widgets::status_bar::StatusBar;

/// Which field a copy action targets (T5.5).
#[derive(Debug, Clone, Copy)]
pub(crate) enum CopyField {
    Password,
    Username,
}

/// Feed a terminal event to a single-line [`tui_input::Input`] field.
fn feed_input(input: &mut tui_input::Input, ev: &Event) {
    if let Some(req) = tui_input::backend::crossterm::to_input_request(ev) {
        input.handle(req);
    }
}

/// The 1-9 digit of an `Alt+<digit>` quick-select key, if it is one.
fn digit_value(key: &KeyEvent) -> Option<usize> {
    match key.code {
        KeyCode::Char(c) => c.to_digit(10).map(|d| d as usize),
        _ => None,
    }
}

/// Maximum consecutive failed unlock attempts before bouncing back to the list.
pub(crate) const MAX_UNLOCK_ATTEMPTS: u8 = 3;

/// The registry commands that mutate the KDBX vault and are therefore disabled
/// in a read-only session (T4.7, layer 1). Hand-maintained; the
/// `readonly_mutating_set_is_complete` meta-test pins it against every command
/// that can reach [`App::persist_vault`], and the persist guard (layer 2) is the
/// runtime backstop for anything missed. `Sync` is included because it writes
/// the vault; `PinToggle` is NOT (it writes only `tui.toml` UI state). Entering
/// visual mode is not a mutation — only its bulk operations are blocked.
pub(crate) const RO_MUTATING_COMMANDS: &[Command] = &[
    Command::AddEntry,
    Command::EditEntry,
    Command::DeleteEntry,
    Command::MoveToGroup,
    Command::AddTag,
    Command::RemoveTag,
    Command::Sync,
];

/// A user-facing message for a sync failure (secret-free — `SyncError`'s
/// `Display` carries no endpoint credentials or key material). The
/// `Unresolvable` conflict gets the prominent treatment + a `.kdbx.bak` pointer
/// (ADR-T4a); every other error is a generic "sync failed".
fn sync_error_message(e: &SyncError) -> String {
    match e {
        SyncError::Unresolvable { .. } => {
            format!("Sync conflict needs manual resolution: {e}. Pre-merge state kept as a .kdbx.bak file.")
        }
        _ => format!("Sync failed: {e}"),
    }
}

/// An error from the TUI's persistence boundary. Read-only refusal is kept in
/// the presentation layer rather than inventing a core `VaultError` for a UI
/// session policy.
#[derive(Debug)]
enum PersistError {
    ReadOnly,
    Vault(VaultError),
}

impl fmt::Display for PersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => f.write_str("read-only session — vault not saved"),
            Self::Vault(error) => error.fmt(f),
        }
    }
}

impl From<VaultError> for PersistError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

/// Top-level phase. Pre-unlock screens are full-screen; unlocking enters the
/// (placeholder, this phase) workspace.
pub(crate) enum Phase {
    /// Pick a registered vault.
    UnlockList,
    /// Enter the master password for the chosen vault.
    UnlockPrompt {
        vault_name: String,
        input: PasswordInput,
        attempts: u8,
    },
    /// Post-lock screen; any key returns to the list.
    LockScreen,
    /// Unlocked workspace (placeholder body in Phase 2).
    Workspace,
}

/// Which pane of the Secrets tab has keyboard focus (T3.1). `Tab` toggles it;
/// the focused pane gets a text affordance in its border title (NFR-015).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Focus {
    /// Tree focused: `j`/`k` move selection, `h`/`l` collapse/expand.
    Tree,
    /// Detail focused: `j`/`k` scroll the detail pane.
    Detail,
}

/// The tree's interaction mode (T4.5). `Normal` is single-cursor navigation;
/// `Visual` is multi-select — `j`/`k` extend a range anchored at the row where
/// `v` was pressed, and the marked entries drive the bulk operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeMode {
    Normal,
    /// Range multi-select anchored at the flattened-row index where `v` fired.
    Visual {
        anchor: usize,
    },
}

/// A clickable region of the workspace (T4.6). Every variant maps to an action
/// keys can already perform — mouse is a pure accelerator, never a new
/// capability (US-071). Enforced by `every_mouse_target_maps_to_registry_command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MouseTarget {
    /// A visible Secrets-tree row (0-based from the top of the pane).
    TreeRow(usize),
    /// The detail pane — focus it (keyboard: `Tab`/`l`).
    DetailPane,
    /// An exact tab label (0-based ordinal).
    Tab(usize),
    /// The status line's overflow affordance — open the palette (keyboard: `?`).
    HintMore,
    /// A visible search result's absolute result index.
    SearchRow(usize),
    /// A visible palette command's command-row index (headers excluded).
    PaletteRow(usize),
}

// Several independent UI flags (reveal, pending-g, lock-pending, should-quit)
// legitimately live as separate booleans on this central state struct; grouping
// them into a sub-struct would obscure more than it clarifies.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct App {
    pub(crate) phase: Phase,
    /// `Some` only while unlocked AND not mid-sync. Dropping it zeroizes the
    /// database and releases the on-disk lock. It is `None` while a background
    /// sync owns it (ADR-T4a) — see [`App::is_syncing`].
    pub(crate) vault: Option<Vault>,
    /// `Some` except while a background sync owns it (moved to the worker for
    /// the duration; ADR-T4a). The pre-unlock phases that read it
    /// (`UnlockList`/`LockScreen`) never run mid-sync, so [`App::registry`]'s
    /// `expect` is sound. Handed back in [`App::integrate_sync_result`].
    registry: Option<VaultRegistry>,
    /// Resolved state-directory paths; the anchor for `tui.toml` I/O (T4.1).
    pub(crate) paths: FalachPaths,
    /// Per-vault pins/recents (`tui.toml`; ADR-T3). The on-disk mirror of the
    /// live `tabs.pins()` + `recents` (state only — prefs live in
    /// [`Self::user_config`] now).
    pub(crate) ui_config: TuiConfig,
    /// User preferences (`config.toml`; T3.1): default sort, sync toggles,
    /// keymap, theme, search, mouse, layout. Loaded in [`Self::new`] (honoring
    /// CLI overrides); defaulted in [`Self::from_registry`] so the test seam
    /// touches no config file.
    pub(crate) user_config: UserConfig,
    /// Effective preferences path (default or `--config PATH`). All reads,
    /// Settings writes, generation, and display use this single source.
    user_config_path: PathBuf,
    /// The active vault's recents (MRU) list; hydrated on unlock, mirrored into
    /// `ui_config` on change (ADR-T5).
    pub(crate) recents: Recents,
    /// One-shot startup notices (corrupt/unreadable config → defaults, keymap
    /// conflicts, clamped values), surfaced in the status bar on the first
    /// unlock (U.5 / R-14). Drained by [`Self::reset_secrets_view`].
    startup_notices: Vec<String>,
    pub(crate) controller: AutoLockController,
    pub(crate) keys: Keymap,
    pub(crate) theme: Theme,
    /// CLI `--theme NAME` override, consumed by theme resolution (T3.4). `None`
    /// means "use `config.theme`".
    pub(crate) theme_override: Option<String>,
    /// User theme files discovered under `~/.config/falach/themes/` at startup
    /// (T3.4). Input to theme resolution and the Settings theme cycle.
    user_themes: Vec<UserThemeFile>,
    /// Whether the active appearance is the *light* variant (from env/config;
    /// T3.4). Tells the Settings theme cycle which config slot (`theme.light`
    /// vs `theme.dark`) to edit.
    active_theme_is_light: bool,
    /// Effective mouse enablement (`config.mouse` unless `--no-mouse`). Consumed
    /// by mouse capture in Phase 4 (T4.6).
    #[allow(dead_code)] // wired to mouse capture in T4.6
    pub(crate) mouse_enabled: bool,
    /// Read-only session (`--read-only`): every vault-mutating command is
    /// refused. Enforced in Phase 4 (T4.7).
    #[allow(dead_code)] // enforced in T4.7
    pub(crate) read_only: bool,
    /// The most-recently-chosen vault name; survives lock so the lock screen
    /// can re-highlight it on return.
    pub(crate) selected_vault: Option<String>,
    /// Highlighted row in the `UnlockList`.
    pub(crate) list_index: usize,
    /// The unlock-list message (e.g. failed attempts). The unlocked workspace
    /// uses `status_bar` instead.
    pub(crate) status: Option<String>,
    /// The unlocked workspace's tab bar (Secrets + Settings in Phase 2).
    pub(crate) tabs: TabBar,
    /// The unlocked workspace's bottom status line (transient msg + hints +
    /// countdown).
    pub(crate) status_bar: StatusBar,
    /// Secrets-tab tree state (expansion, selection, sort order).
    pub(crate) tree: TreeState,
    /// Session-only back/forward history over visited entries and groups (T4.4,
    /// D-8). Not persisted; cleared on lock.
    pub(crate) jump_history: JumpHistory,
    /// Tree interaction mode: normal navigation or visual multi-select (T4.5).
    pub(crate) tree_mode: TreeMode,
    /// Entries marked for a bulk operation (UUID-keyed so marks survive a group
    /// collapse; hidden marked entries simply render nothing). Cleared on lock.
    pub(crate) marks: std::collections::HashSet<Uuid>,
    /// Exact clickable rectangles populated by the renderers. Later regions
    /// win, so modal rows naturally shadow the workspace beneath them.
    mouse_regions: std::cell::RefCell<Vec<(Rect, MouseTarget)>>,
    /// Which Secrets-tab pane has focus.
    pub(crate) focus: Focus,
    /// Whether the detail pane reveals the selected entry's password. Reset to
    /// `false` whenever the selected entry changes or the vault locks.
    pub(crate) reveal_password: bool,
    /// Detail-pane scroll offset (rows). Clamped to content height at render.
    pub(crate) detail_scroll: u16,
    /// Chord state for the tab-motion resolver (`g`-prefix + `{count}`). The
    /// resolver in [`Keymap::resolve`] owns the transition logic; `App` only
    /// holds and threads this state.
    pending_seq: PendingSeq,
    /// The modal overlay layered over the active tab (Phase 5). `None` when no
    /// overlay is open. Cleared by [`App::lock_app`] so secret-bearing overlay
    /// buffers (edit password, generate preview) zeroize on lock.
    pub(crate) overlay: Option<Overlay>,
    /// Clipboard sink for copy actions (T5.5). The production sink wraps
    /// `falach_security::Clipboard`; headless launches and tests use a
    /// fallback / recording sink (see [`crate::clipboard`]).
    clipboard: Box<dyn ClipboardSink>,
    /// Background sync runtime (Phase 6 / ADR-T4a). Owns the vault + registry
    /// while a sync is in flight.
    sync: SyncRuntime,
    /// A lock requested while a sync was in flight (idle deadline or manual
    /// `Ctrl+L`). Applied when the worker returns (deferred-lock; ADR-T4a).
    lock_pending: bool,
    /// Highlighted row in the Settings tab editor (T6.3).
    pub(crate) settings_index: usize,
    /// The last sync result/error summary for the Settings sync-status sub-view
    /// (secret-free; T6.2/T6.4).
    sync_status: Option<String>,
    pub(crate) should_quit: bool,
    /// Count of vault saves routed through [`App::persist_vault`] (the single
    /// vault-write choke point). Test-only seam consumed by the bulk-op (T4.5)
    /// and read-only (T4.7) suites to assert "exactly one atomic write per
    /// operation" without inspecting the filesystem.
    #[cfg(test)]
    pub(crate) save_count: u32,
}

/// Number of editable rows in the Settings tab (T6.3; grew with the Theme row
/// in T3.4 and the Auto-lock row in T3.5). Kept in sync with
/// [`settings::ROW_LABELS`] by the test below.
const SETTINGS_ROW_COUNT: usize = 6;

/// Selectable idle auto-lock timeouts, in seconds (1/5/10/15/30 min). The
/// Settings row cycles these (T3.5). "Off" is intentionally absent —
/// [`AutoLockConfig`] has no disabled state (idle timeout must be ≥ 1s), and this
/// cycle must stay ⊆ core's supported values.
const AUTO_LOCK_CYCLE_SECS: [u64; 5] = [60, 300, 600, 900, 1800];

impl App {
    /// Construct from the on-disk registry (production path).
    ///
    /// # Errors
    /// [`TuiError::NoVaultsRegistered`] if the registry has no vaults;
    /// [`TuiError::Core`] if the registry can't be loaded; [`TuiError::Security`]
    /// if the auto-lock controller rejects its config.
    pub(crate) fn new(args: &Args) -> Result<Self, TuiError> {
        let paths = FalachPaths::from_env()?;
        // The registry consumes its `FalachPaths`; clone so the App keeps a
        // copy for `tui.toml` I/O.
        let registry = VaultRegistry::load(paths.clone())?;
        let mut app = Self::from_registry(registry, paths, AutoLockConfig::default())?;
        // Upgrade from the headless-safe fallback to the real system clipboard
        // (falls back again if the platform clipboard can't be opened).
        app.clipboard = clipboard::system_or_unavailable();
        // Load the real user preferences (config.toml) and apply CLI overrides
        // over the defaults `from_registry` installed. Done post-build (like the
        // clipboard upgrade) so the `from_registry` test seam stays file-free.
        app.apply_args(args)?;
        Ok(app)
    }

    /// Load `config.toml` (honoring `--config`), install it as
    /// [`Self::user_config`], rebuild the keymap from its `[keymap]` patch, apply
    /// CLI overrides (theme/mouse/read-only), honor `--vault`, and queue any
    /// warnings for the first unlock. Production `new` path only; `from_registry`
    /// keeps defaults so tests touch no config file.
    ///
    /// # Errors
    /// [`TuiError::UnknownVault`] if `--vault` names a vault not in the registry.
    fn apply_args(&mut self, args: &Args) -> Result<(), TuiError> {
        // 1. User config (CLI --config path override), then keymap from its patch.
        self.user_config_path = args
            .config
            .clone()
            .unwrap_or_else(|| self.paths.config_toml());
        let (user_config, mut notices) = match args.config.as_deref() {
            Some(path) => UserConfig::load_from(path),
            None => UserConfig::load(&self.paths),
        };
        let (keys, keymap_warnings) = Keymap::from_patch(&user_config.keymap);
        notices.extend(keymap_warnings.into_iter().map(|w| w.message));

        // 2. CLI-over-config resolution (theme name, mouse, read-only).
        let effective = args.effective(&user_config);
        self.user_config = user_config;
        self.keys = keys;
        self.theme_override = effective.theme;
        self.mouse_enabled = effective.mouse;
        self.read_only = effective.read_only;
        self.startup_notices.extend(notices);

        // 2b. Resolve the theme (env × config × --theme × discovered user themes).
        let (user_themes, theme_discovery_notices) =
            theme::discover_user_themes(&self.paths.config_dir().join("themes"));
        self.user_themes = user_themes;
        self.startup_notices.extend(
            theme_discovery_notices
                .into_iter()
                .map(|warning| warning.message),
        );
        let flag = self.theme_override.clone();
        let (theme, theme_notices, active_light) = self.resolve_theme_for(flag.as_deref());
        self.theme = theme;
        self.active_theme_is_light = active_light;
        self.startup_notices.extend(theme_notices);

        // 3. `--vault NAME`: validate against the registry, then jump straight to
        //    its unlock prompt. Validated here (pre-terminal) so an unknown name
        //    prints on a normal screen, never inside the alternate screen.
        if let Some(name) = &args.vault {
            if self.registry().get(name).is_none() {
                return Err(TuiError::UnknownVault(name.clone()));
            }
            self.open_unlock_prompt_for(name.clone());
        }

        Ok(())
    }

    /// Resolve the theme from the current process environment × config × `flag`
    /// × discovered user themes (T3.4). Returns the theme plus warning strings.
    fn resolve_theme_for(&self, flag: Option<&str>) -> (Theme, Vec<String>, bool) {
        let rt = std::env::var("FALACH_TUI_THEME").ok();
        let term = std::env::var("TERM").ok();
        let colorterm = std::env::var("COLORTERM").ok();
        let colorfgbg = std::env::var("COLORFGBG").ok();
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let env = EnvParts {
            theme_override: rt.as_deref(),
            no_color,
            term: term.as_deref(),
            colorterm: colorterm.as_deref(),
            colorfgbg: colorfgbg.as_deref(),
        };
        let active_light =
            !env.forces_monochrome() && theme::wants_light(env, self.user_config.theme.mode);
        let (theme, warnings) =
            theme::resolve_theme(env, &self.user_config.theme, flag, &self.user_themes);
        (
            theme,
            warnings.into_iter().map(|w| w.message).collect(),
            active_light,
        )
    }

    /// The selectable theme names (built-ins + discovered user themes), in cycle
    /// order — the Settings theme row iterates these.
    fn theme_names(&self) -> Vec<String> {
        let mut names: Vec<String> = BUILTIN_NAMES.iter().map(|s| (*s).to_string()).collect();
        names.extend(self.user_themes.iter().map(|u| u.name.clone()));
        names
    }

    /// The currently-selected theme name for the active appearance (the value
    /// the Settings row shows / cycles).
    pub(crate) fn current_theme_name(&self) -> &str {
        if self.active_theme_is_light {
            &self.user_config.theme.light
        } else {
            &self.user_config.theme.dark
        }
    }

    /// The active keymap preset label for the read-only Settings display.
    pub(crate) fn keymap_preset_label(&self) -> &'static str {
        match self.user_config.keymap.preset {
            Some(Preset::Plain) => "plain",
            Some(Preset::Vim) | None => "vim",
        }
    }

    /// The config-file path for the read-only Settings display.
    pub(crate) fn config_file_display(&self) -> String {
        self.user_config_path.display().to_string()
    }

    pub(crate) fn tree_ratio(&self) -> u8 {
        self.user_config.layout.tree_ratio
    }

    // --- Auto-lock editing (T3.5) ---

    /// The active vault's configured idle-auto-lock timeout in seconds, read from
    /// its `[vault.lock]` override in `vaults.toml`, else the default. Drives the
    /// Settings row display and the unlock-time controller arming.
    pub(crate) fn current_auto_lock_seconds(&self) -> u64 {
        self.selected_vault
            .as_ref()
            .and_then(|name| self.registry().get(name))
            .and_then(|v| VaultLockConfig::idle_timeout_seconds_from_extra(&v.extra))
            .unwrap_or_else(|| AutoLockConfig::default().idle_timeout.as_secs())
    }

    /// The active vault's *explicit* per-vault auto-lock override, if any.
    /// `None` (the common case) means "keep the frontend default" — matching
    /// `VaultLockConfig`'s documented semantics (a `[vault.lock]` value
    /// overrides the frontend's [`AutoLockConfig`]; its absence falls back to
    /// the frontend default). An invalid stored value is treated as absent so a
    /// hand-edited `vaults.toml` can never make unlock fail.
    fn vault_auto_lock_override(&self) -> Option<AutoLockConfig> {
        let secs = self
            .selected_vault
            .as_ref()
            .and_then(|name| self.registry().get(name))
            .and_then(|v| VaultLockConfig::idle_timeout_seconds_from_extra(&v.extra))?;
        let cfg = AutoLockConfig {
            idle_timeout: Duration::from_secs(secs),
        };
        cfg.validate().ok().map(|()| cfg)
    }

    /// Arm the idle-lock controller for the active vault at `now` (called on
    /// unlock and after an auto-lock change). If the vault carries an explicit
    /// `[vault.lock]` override, the controller is recreated with it (the TUI
    /// attaches no OS event source, so recreating loses nothing); otherwise the
    /// existing controller — carrying the frontend default — is simply re-armed.
    fn arm_auto_lock_for_current_vault(&mut self, now: Instant) {
        match self.vault_auto_lock_override() {
            Some(cfg) => match AutoLockController::new(cfg) {
                Ok(mut controller) => {
                    controller.unlock(now);
                    self.controller = controller;
                }
                Err(_) => self.controller.unlock(now),
            },
            None => self.controller.unlock(now),
        }
    }

    /// Persist a new idle auto-lock timeout for the active vault and re-arm the
    /// live controller immediately (T3.5). Uses the core's locked,
    /// reload-before-write transaction and `falach_security`'s `[vault.lock]`
    /// schema. Best-effort: a write failure warns and leaves live state unchanged.
    fn set_auto_lock(&mut self, seconds: u64) {
        let Some(name) = self.selected_vault.clone() else {
            return;
        };
        let registry = self
            .registry
            .as_mut()
            .expect("registry present outside an in-flight sync");
        if let Err(e) = registry.update_registered_extra(&name, |extra| {
            VaultLockConfig::apply_idle_timeout(extra, Some(seconds));
        }) {
            // Another process may hold the vault; surface, don't retry-loop.
            self.status_bar
                .set_error(format!("Could not save auto-lock: {e}"), Instant::now());
            return;
        }
        // Take effect immediately: re-arm the live controller with the new deadline.
        self.arm_auto_lock_for_current_vault(Instant::now());
        self.status_bar.set(
            format!("Auto-lock: {} min (saved)", seconds / 60),
            Instant::now(),
        );
    }

    /// Advance the auto-lock timeout to the next value in [`AUTO_LOCK_CYCLE_SECS`]
    /// (Settings editor). A stored value outside the cycle starts the cycle from
    /// its first entry.
    fn cycle_auto_lock(&mut self) {
        let current = self.current_auto_lock_seconds();
        let idx = AUTO_LOCK_CYCLE_SECS
            .iter()
            .position(|&s| s == current)
            .map_or(0, |i| (i + 1) % AUTO_LOCK_CYCLE_SECS.len());
        self.set_auto_lock(AUTO_LOCK_CYCLE_SECS[idx]);
    }

    /// Advance the theme to the next selectable name (Settings editor): update
    /// the appropriate config slot (`theme.light`/`theme.dark`), re-resolve the
    /// live [`Theme`] (config-only — the launch `--theme` flag no longer
    /// applies once the user chooses explicitly), and persist.
    fn cycle_theme(&mut self) {
        let names = self.theme_names();
        if names.is_empty() {
            return;
        }
        let idx = names
            .iter()
            .position(|n| n == self.current_theme_name())
            .unwrap_or(0);
        let next = names[(idx + 1) % names.len()].clone();
        let light = self.active_theme_is_light;
        if self.update_user_config(|cfg| {
            if light {
                next.clone_into(&mut cfg.theme.light);
            } else {
                next.clone_into(&mut cfg.theme.dark);
            }
        }) {
            let (theme, notices, active_light) = self.resolve_theme_for(None);
            self.theme = theme;
            self.active_theme_is_light = active_light;
            if notices.is_empty() {
                self.status_bar
                    .set(format!("Theme: {next}"), Instant::now());
            } else {
                self.status_bar
                    .set_error(notices.join("; "), Instant::now());
            }
        }
    }

    /// Construct from a caller-supplied registry + paths + auto-lock config
    /// (test seam; also the body of [`App::new`]). Loads `tui.toml` from `paths`
    /// (absent/corrupt → defaults; never fatal — U.5).
    pub(crate) fn from_registry(
        registry: VaultRegistry,
        paths: FalachPaths,
        lock_config: AutoLockConfig,
    ) -> Result<Self, TuiError> {
        if registry.list().next().is_none() {
            return Err(TuiError::NoVaultsRegistered);
        }
        let (ui_config, config_warning) = TuiConfig::load(&config::config_path(&paths));
        let user_config_path = paths.config_toml();
        Ok(Self {
            phase: Phase::UnlockList,
            vault: None,
            registry: Some(registry),
            paths,
            ui_config,
            // Defaulted here (test seam touches no config file); `App::new`
            // loads the real `config.toml` post-build via `apply_args`.
            user_config: UserConfig::default(),
            user_config_path,
            recents: Recents::new(),
            startup_notices: config_warning.into_iter().collect(),
            controller: AutoLockController::new(lock_config)?,
            keys: Keymap::preset(Preset::Vim),
            theme: Theme::auto(),
            // CLI/config overrides are applied post-build in `apply_args`
            // (production path); the test seam keeps defaults.
            theme_override: None,
            user_themes: Vec::new(),
            active_theme_is_light: false,
            mouse_enabled: true,
            read_only: false,
            selected_vault: None,
            list_index: 0,
            status: None,
            tabs: TabBar::new(),
            status_bar: StatusBar::new(),
            tree: TreeState::new(),
            jump_history: JumpHistory::default(),
            tree_mode: TreeMode::Normal,
            marks: std::collections::HashSet::new(),
            mouse_regions: std::cell::RefCell::new(Vec::new()),
            focus: Focus::Tree,
            reveal_password: false,
            detail_scroll: 0,
            pending_seq: PendingSeq::default(),
            overlay: None,
            // Headless-safe default; `App::new` upgrades to the real clipboard.
            clipboard: Box::new(clipboard::UnavailableClipboard),
            sync: SyncRuntime::new(),
            lock_pending: false,
            settings_index: 0,
            sync_status: None,
            should_quit: false,
            #[cfg(test)]
            save_count: 0,
        })
    }

    /// The vault registry. Present except while a background sync owns it
    /// (ADR-T4a); the pre-unlock phases that call this never run mid-sync.
    pub(crate) fn registry(&self) -> &VaultRegistry {
        self.registry
            .as_ref()
            .expect("registry is present outside an in-flight sync")
    }

    /// Whether a background sync is in flight (vault moved to the worker).
    pub(crate) fn is_syncing(&self) -> bool {
        self.sync.is_syncing()
    }

    /// Test seam: inject a clipboard sink (e.g. a recording mock).
    #[cfg(test)]
    pub(crate) fn set_clipboard(&mut self, sink: Box<dyn ClipboardSink>) {
        self.clipboard = sink;
    }

    /// Test seam: replace the sync runtime with one backed by a fake engine.
    #[cfg(test)]
    pub(crate) fn set_sync_engine(
        &mut self,
        engine: std::sync::Arc<dyn crate::sync_runtime::SyncEngine>,
    ) {
        self.sync = SyncRuntime::with_engine(engine);
    }

    /// Advance the auto-lock clock and integrate any finished/ongoing sync.
    ///
    /// Order matters (ADR-T4a): drain the sync channel **first** so a
    /// progressing sync's `Activity` pings reset the idle deadline *before* the
    /// lock check — otherwise a healthy sync would still trip the deadline.
    /// While a sync owns the vault (`vault == None`), the idle clock still runs
    /// but a fired lock is *deferred* (no `sync_now` cancel hook): the worker
    /// drops+zeroizes the vault on return and the App goes to `LockScreen`.
    pub(crate) fn tick(&mut self, now: Instant) {
        self.status_bar.tick(now);

        for msg in self.sync.drain() {
            self.on_sync_message(msg, now);
        }

        if self.vault.is_some() {
            if self.controller.tick(now) == LockState::Locked {
                self.lock_app();
            }
        } else if self.sync.is_syncing() && self.controller.tick(now) == LockState::Locked {
            self.lock_pending = true;
        }
    }

    /// Handle one message from the sync worker. `Activity` keeps the idle clock
    /// alive; `Done` reintegrates the moved vault + registry and surfaces the
    /// outcome (the logic that matters — directly unit-tested without threading).
    fn on_sync_message(&mut self, msg: SyncMsg, now: Instant) {
        match msg {
            SyncMsg::Activity => self.controller.register_activity(now),
            SyncMsg::Done(result) => self.integrate_sync_result(*result, now),
            SyncMsg::WorkerLost => self.recover_from_lost_worker(),
        }
    }

    /// Recover from a sync worker that vanished mid-sync — it panicked, taking
    /// the moved vault + registry with it (ADR-T4a's "any sync failure →
    /// `LockScreen`", extended to a worker panic). The on-disk vault + registry
    /// are always consistent, so reload the registry from disk (the worker took
    /// the in-memory copy) and drop to `LockScreen`; the next unlock re-opens
    /// cleanly. A failed reload falls back to an empty registry rather than
    /// leaving `registry` `None` (which would panic the post-lock `UnlockList`).
    fn recover_from_lost_worker(&mut self) {
        self.registry = Some(
            VaultRegistry::load(self.paths.clone())
                .unwrap_or_else(|_| VaultRegistry::with_paths(self.paths.clone())),
        );
        self.lock_pending = false;
        let message = "Sync worker failed unexpectedly; vault locked.".to_string();
        self.sync_status = Some(message.clone());
        self.lock_app(); // clears `status`…
        self.status = Some(message); // …so set the user-facing message after.
    }

    /// Reintegrate a finished sync (ADR-T4a). The registry always comes back. On
    /// success the vault is handed back and the outcome surfaced; a deferred lock
    /// (idle/manual) or an on-lock/quit trigger then completes. On **any**
    /// `SyncError` the vault is dropped and the App drops to `LockScreen` (the
    /// on-disk file is always consistent; the next unlock re-opens cleanly).
    fn integrate_sync_result(&mut self, result: SyncResult, now: Instant) {
        let SyncResult {
            vault,
            registry,
            outcome,
            trigger,
        } = result;
        self.registry = Some(registry);
        match outcome {
            Ok(outcome) => {
                self.vault = Some(vault);
                self.surface_outcome(&outcome, now);
                // FastReplaced/Merged may have changed the entry set; the tree
                // rebuilds from the vault each frame, so just re-clamp selection.
                self.reclamp_tree_selection();
                // A remote replacement/merge can remove entries that were
                // marked before sync. Never leave stale batch operands behind.
                self.marks.retain(|uuid| {
                    self.vault
                        .as_ref()
                        .is_some_and(|vault| vault.get_entry(*uuid).is_ok())
                });
                if self.marks.is_empty() {
                    self.tree_mode = TreeMode::Normal;
                }
                if self.lock_pending {
                    self.lock_pending = false;
                    self.lock_app();
                    return;
                }
                match trigger {
                    SyncTrigger::OnLock => self.lock_app(),
                    SyncTrigger::OnQuit => self.should_quit = true,
                    SyncTrigger::Manual | SyncTrigger::OnUnlock => {}
                }
            }
            Err(e) => {
                // Drop the moved-back vault (zeroize) and lock. Any SyncError →
                // LockScreen, even for an on-quit trigger: the local save is
                // already durable, so the user can re-open and retry.
                drop(vault);
                self.lock_pending = false;
                let message = sync_error_message(&e);
                self.sync_status = Some(message.clone());
                self.lock_app();
                // `lock_app` clears `status`; set the user-facing message after.
                self.status = Some(message);
            }
        }
    }

    /// Surface a successful [`SyncOutcome`] per the ADR-T4a matrix (never
    /// swallowed). `AlreadyInSync`/`Pushed` are quiet; `FastReplaced`/`Merged`
    /// are calm (no data lost); the prominent `Unresolvable` case is an error,
    /// handled in [`Self::integrate_sync_result`].
    fn surface_outcome(&mut self, outcome: &SyncOutcome, now: Instant) {
        let message = match outcome {
            SyncOutcome::AlreadyInSync => "Up to date.".to_string(),
            SyncOutcome::Pushed { .. } => "Synced ↑.".to_string(),
            SyncOutcome::FastReplaced => "Updated from remote.".to_string(),
            SyncOutcome::Merged { delta, .. } => format!(
                "Merged: {} added · {} changed · {} removed.",
                delta.added.len(),
                delta.modified.len(),
                delta.removed.len()
            ),
            // `SyncOutcome` is `#[non_exhaustive]`.
            _ => "Synced.".to_string(),
        };
        self.status_bar.set(message.clone(), now);
        self.sync_status = Some(message);
    }

    /// Re-clamp the tree selection after sync may have removed the selected
    /// entry. Selection is UUID-based, so a still-present entry is untouched.
    fn reclamp_tree_selection(&mut self) {
        self.detail_scroll = 0;
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        let rows = entry_tree::build_rows(vault, &self.tree, &self.recents);
        let still_present = self
            .tree
            .selected()
            .is_some_and(|sel| rows.iter().any(|r| r.uuid == sel));
        if !still_present {
            self.tree.select_first(&rows);
        }
    }

    /// The canonical lock sequence (FR-073). Drops the vault (zeroize cascade +
    /// lock release), clears transient state, and returns to the lock screen.
    /// `selected_vault` is preserved so the lock screen can re-highlight it.
    /// Replacing `self.phase` drops any `Zeroizing` buffer held by the current
    /// phase (a partially-typed `UnlockPrompt` password).
    pub(crate) fn lock_app(&mut self) {
        self.vault = None;
        self.status = None;
        // Drop any open overlay so its secret-bearing buffers (edit password,
        // generate preview) zeroize on lock (CLAUDE.md zeroize-on-lock).
        self.overlay = None;
        // Session-only jump history clears on lock like all other view state (D-8).
        self.jump_history.clear();
        // Visual-mode marks are session view state too (T4.5).
        self.tree_mode = TreeMode::Normal;
        self.marks.clear();
        self.phase = Phase::LockScreen;
    }

    /// Dispatch a terminal event. Globals (quit, lock-now) are handled first,
    /// then the active phase. Key handling lives on `&mut self` (rather than in
    /// the screen modules) to avoid aliasing the phase data it mutates.
    pub(crate) fn handle_event(&mut self, ev: &Event) {
        let Event::Key(key) = ev else {
            return;
        };
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Global: quit works everywhere; lock-now only while unlocked. Both may
        // first flush a sync-on-lock/quit (T6.2) — see `request_quit`/`request_lock`.
        if self.keys.matches(Command::Quit, key) {
            self.execute_command(Command::Quit, None);
            return;
        }
        if self.keys.matches(Command::LockNow, key) && matches!(self.phase, Phase::Workspace) {
            self.execute_command(Command::LockNow, None);
            return;
        }

        // An open overlay captures input before anything else (so `?` inside the
        // palette types into its filter rather than re-opening it). Overlays are
        // usually workspace-only, but the palette can also be open pre-unlock.
        if self.overlay.is_some() {
            self.on_overlay_key(ev);
            return;
        }

        // The palette (`?`, and `F1` in the Plain preset) is global: it opens
        // from every phase, including the pre-unlock screens (T2.4). Handled
        // after the overlay check so it never fires while the palette is up.
        //
        // EXCEPTION: the master-password prompt is a text-entry field where `?`
        // is a valid password character — KDBX interop (engineering principle #1)
        // requires a `?`-containing password to be typeable, so at the prompt `?`
        // flows to the input instead. The palette stays reachable pre-unlock from
        // the unlock list and lock screen (one `Esc` away from the prompt).
        if self.keys.matches(Command::Help, key)
            && !matches!(self.phase, Phase::UnlockPrompt { .. })
        {
            self.execute_command(Command::Help, None);
            return;
        }

        // `matches!` releases the phase borrow before the &mut self call.
        if matches!(self.phase, Phase::UnlockList) {
            self.on_unlock_list_key(key);
        } else if matches!(self.phase, Phase::UnlockPrompt { .. }) {
            self.on_unlock_prompt_key(key);
        } else if matches!(self.phase, Phase::LockScreen) {
            self.on_lock_screen_key();
        } else if matches!(self.phase, Phase::Workspace) {
            self.on_workspace_key(key);
        }
    }

    /// Workspace key handling. Phase 2 implements tab navigation only; tree /
    /// detail / overlay keys land in Phase 3+.
    ///
    /// Tab motions (OQ-N1): `Alt+1..9` jumps directly; `gt`/`gT` cycle; a digit
    /// prefix before `gt` (`{count}gt`) jumps to that 1-based ordinal. The
    /// `g`-prefix + count form a tiny input state machine; any other key resets
    /// the pending state.
    fn on_workspace_key(&mut self, key: &KeyEvent) {
        // (`?`/`F1` → palette is handled globally in `handle_event`.)

        // The tab-motion resolver (`Keymap::resolve`) owns the `g`-prefix /
        // `{count}` / `Alt+N` chord machine. A resolved motion switches tabs; a
        // pending prefix waits (which-key renders in T2.2); anything else is not
        // a tab motion and routes to the active tab body.
        match self
            .keys
            .resolve(Contexts::WORKSPACE, key, &mut self.pending_seq)
        {
            Resolution::Command(cmd, count) => self.execute_command(cmd, count),
            Resolution::Pending(_) => {
                // Stamp the empty→pending transition so the which-key menu's
                // render delay (T2.2) measures from when the prefix began. A
                // count-only pending state has an empty prefix and no stamp.
                if !self.pending_seq.prefix.is_empty() && self.pending_seq.since.is_none() {
                    self.pending_seq.since = Some(Instant::now());
                }
            }
            Resolution::None => self.dispatch_active_tab_key(key),
        }
    }

    /// The pending chord state (which-key reads it during render — T2.2).
    pub(crate) fn pending_seq(&self) -> &PendingSeq {
        &self.pending_seq
    }

    // ---- T4.6: mouse as accelerator ----

    /// Handle a mouse event (T4.6). A left click is hit-tested against the
    /// workspace layout; the wheel scrolls the pane under the cursor. Every
    /// action routes through the same paths keys use — mouse is an accelerator,
    /// never a new capability (US-071). No-op when mouse is disabled.
    pub(crate) fn handle_mouse_event(&mut self, ev: MouseEvent) {
        if !self.mouse_enabled {
            return;
        }
        match ev.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(target) = self.mouse_target_at(ev.column, ev.row) {
                    self.apply_mouse_target(target);
                }
            }
            // Wheel scrolls the pane under the cursor by three rows (bottom-style).
            MouseEventKind::ScrollDown => self.mouse_scroll(ev.column, ev.row, Command::Next),
            MouseEventKind::ScrollUp => self.mouse_scroll(ev.column, ev.row, Command::Prev),
            _ => {}
        }
    }

    /// Record an exact region during rendering. Render order defines z-order.
    pub(crate) fn register_mouse_target(&self, area: Rect, target: MouseTarget) {
        if area.width > 0 && area.height > 0 {
            self.mouse_regions.borrow_mut().push((area, target));
        }
    }

    /// Hit-test `(col, row)` against render-populated regions. Last match wins
    /// so overlay rows shadow the workspace. Any overlay also blocks clicks
    /// through its non-interactive background.
    fn mouse_target_at(&self, col: u16, row: u16) -> Option<MouseTarget> {
        if !matches!(self.phase, Phase::Workspace) {
            return None;
        }
        let target = self
            .mouse_regions
            .borrow()
            .iter()
            .rev()
            .find(|(area, _)| {
                col >= area.x
                    && col < area.x.saturating_add(area.width)
                    && row >= area.y
                    && row < area.y.saturating_add(area.height)
            })
            .map(|(_, target)| *target);
        if self.overlay.is_some()
            && !matches!(
                target,
                Some(MouseTarget::SearchRow(_) | MouseTarget::PaletteRow(_))
            )
        {
            None
        } else {
            target
        }
    }

    /// Apply a hit-tested [`MouseTarget`]. Exhaustive over the enum so a new
    /// target cannot ship without a keyboard-reachable mapping (US-071); the
    /// `every_mouse_target_maps_to_registry_command` test pins this.
    fn apply_mouse_target(&mut self, target: MouseTarget) {
        match target {
            MouseTarget::Tab(index) => {
                self.tabs.jump_to(index + 1);
                self.on_tab_switched();
            }
            MouseTarget::HintMore => self.execute_command(Command::Help, None),
            MouseTarget::DetailPane => self.focus = Focus::Detail,
            MouseTarget::TreeRow(i) => self.mouse_select_tree_row(i),
            MouseTarget::SearchRow(i) => {
                if let Some(Overlay::Search(state)) = self.overlay.as_mut() {
                    if i < state.results.len() {
                        state.selected = i;
                    }
                }
            }
            MouseTarget::PaletteRow(i) => {
                if let Some(Overlay::Palette(state)) = self.overlay.as_mut() {
                    state.selected = i;
                }
            }
        }
    }

    /// Select the i-th visible tree row (click-to-select; keyboard equivalent is
    /// `j`/`k`). Best-effort: assumes the tree is not scrolled past the top,
    /// which holds for vaults that fit the pane (the common case).
    fn mouse_select_tree_row(&mut self, i: usize) {
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        let rows = entry_tree::build_rows(vault, &self.tree, &self.recents);
        if let Some(target_row) = rows.get(i) {
            self.tree.select(target_row.uuid);
            self.focus = Focus::Tree;
            self.reveal_password = false;
            self.detail_scroll = 0;
        }
    }

    /// Wheel scroll: three `Next`/`Prev` in the pane under the cursor (tree
    /// selection or detail scroll), through the same nav path keys use.
    fn mouse_scroll(&mut self, col: u16, row: u16, direction: Command) {
        match self.mouse_target_at(col, row) {
            Some(MouseTarget::SearchRow(_)) => {
                if let Some(Overlay::Search(state)) = self.overlay.as_mut() {
                    for _ in 0..3 {
                        match direction {
                            Command::Next => state.select_next(),
                            Command::Prev => state.select_prev(),
                            _ => {}
                        }
                    }
                }
                return;
            }
            Some(MouseTarget::PaletteRow(_)) => {
                let row_count = match self.overlay.as_ref() {
                    Some(Overlay::Palette(state)) => {
                        overlay::palette::build_palette_rows(self, state.underlying, state.filter())
                            .len()
                    }
                    _ => 0,
                };
                if let Some(Overlay::Palette(state)) = self.overlay.as_mut() {
                    for _ in 0..3 {
                        match direction {
                            Command::Next if row_count > 0 => {
                                state.selected = (state.selected + 1).min(row_count - 1);
                            }
                            Command::Prev => state.selected = state.selected.saturating_sub(1),
                            _ => {}
                        }
                    }
                }
                return;
            }
            _ => {}
        }
        // Route to whichever pane the cursor is over so the wheel feels local.
        if let Some(MouseTarget::DetailPane) = self.mouse_target_at(col, row) {
            self.focus = Focus::Detail;
        } else if let Some(MouseTarget::TreeRow(_)) = self.mouse_target_at(col, row) {
            self.focus = Focus::Tree;
        }
        for _ in 0..3 {
            self.exec_context_nav(direction);
        }
    }

    /// Apply a resolved tab-navigation motion. `jump_to` clamps the (1-based)
    /// ordinal, so an out-of-range count is a no-op-ish clamp as before.
    fn apply_tab_motion(&mut self, cmd: Command, count: Option<u16>) {
        match cmd {
            Command::NextTab => self.tabs.next(),
            Command::PrevTab => self.tabs.prev(),
            Command::JumpToTab => self.tabs.jump_to(count.unwrap_or(0) as usize),
            _ => return,
        }
        self.on_tab_switched();
    }

    fn reset_tab_motion(&mut self) {
        self.pending_seq.reset();
    }

    /// Reset the shared detail-view state when the active tab changes so a
    /// revealed/scrolled pin (or Secrets selection) does not bleed into the tab
    /// switched to (design point: `detail_scroll`/`reveal_password` are shared
    /// across tabs).
    fn on_tab_switched(&mut self) {
        self.reveal_password = false;
        self.detail_scroll = 0;
        if let Tab::Pinned(uuid) = self.tabs.active_tab() {
            self.jump_history.push(uuid);
            self.recents.bump(uuid);
            self.persist_ui_state();
        }
    }

    /// Route a non-tab-motion key to the active tab's body. Each handler resolves
    /// command keys and sends them through [`Self::execute_command`], whose sync
    /// guard is shared with palette execution.
    fn dispatch_active_tab_key(&mut self, key: &KeyEvent) {
        match self.tabs.active_tab() {
            Tab::Secrets => self.on_secrets_key(key),
            Tab::Settings => self.on_settings_key(key),
            Tab::Pinned(uuid) => self.on_pinned_key(uuid, key),
        }
    }

    /// Pinned-tab key handling. The pinned body is rendered by
    /// `entry_detail::render_pinned` with the App's shared reveal/scroll
    /// state and advertises "(Space: reveal)" and "(Shift+H to view)"
    /// hints — so reveal, history, and detail scrolling must work here
    /// exactly as they do in the Secrets tab's detail pane.
    fn on_pinned_key(&mut self, _uuid: Uuid, key: &KeyEvent) {
        // Reveal / history route through the shared `execute_command` path (which
        // acts on the pinned entry for a pinned tab); scrolling is pane-local.
        if self.keys.matches(Command::JumpBack, key) {
            self.execute_command(Command::JumpBack, None);
        } else if self.keys.matches(Command::RevealPassword, key) {
            self.execute_command(Command::RevealPassword, None);
        } else if self.keys.matches(Command::History, key) {
            self.execute_command(Command::History, None);
        } else if let Some(cmd) = self.nav_command_for(key) {
            self.execute_command(cmd, None);
        }
    }

    /// Pinned-tab navigation: `Next`/`Prev` scroll the detail pane (the shared
    /// target for keys and, via `exec_context_nav`, the palette).
    fn pinned_command(&mut self, uuid: Uuid, cmd: Command) {
        match cmd {
            Command::Next => {
                self.detail_scroll = self
                    .detail_scroll
                    .saturating_add(1)
                    .min(self.max_scroll_for(uuid));
            }
            Command::Prev => self.detail_scroll = self.detail_scroll.saturating_sub(1),
            _ => {}
        }
    }

    /// Secrets-tab key handling: focus toggle, reveal, sort, and pane-specific
    /// navigation/scrolling.
    fn on_secrets_key(&mut self, key: &KeyEvent) {
        // Visual mode intercepts its own keys (range extend / mark toggle / Esc
        // de-escalation) before normal dispatch; `v`, `m`/`t`/`T`/`d` fall
        // through so re-anchor and the bulk commands still resolve (T4.5).
        if matches!(self.tree_mode, TreeMode::Visual { .. }) && self.handle_visual_key(key) {
            return;
        }
        // Esc-ladder second rung: in normal mode with marks, Esc clears them.
        if matches!(self.tree_mode, TreeMode::Normal)
            && !self.marks.is_empty()
            && matches!(key.code, KeyCode::Esc)
        {
            self.marks.clear();
            return;
        }
        // In the tree, Space is the yazi-style persistent mark toggle in both
        // normal and visual modes. The detail pane and pinned tabs retain the
        // existing password-reveal binding.
        if matches!(self.focus, Focus::Tree) && matches!(key.code, KeyCode::Char(' ')) {
            self.toggle_current_mark();
            return;
        }
        if self.keys.matches(Command::FocusPane, key) {
            self.execute_command(Command::FocusPane, None);
            return;
        }
        // Jump history (T4.4): back works in either pane; forward is tree-focus
        // only because its `Ctrl+I` trigger is indistinguishable from `Tab`
        // (pane toggle) in the detail pane on many terminals.
        if self.keys.matches(Command::JumpBack, key) {
            self.execute_command(Command::JumpBack, None);
            return;
        }
        if matches!(self.focus, Focus::Tree) && self.keys.matches(Command::JumpForward, key) {
            self.execute_command(Command::JumpForward, None);
            return;
        }
        // The Secrets-tab action commands all route through the shared
        // `execute_command` path (the same one the palette uses). Each is a
        // discrete action bound to a single key; resolve the first that matches.
        for cmd in [
            Command::RevealPassword,
            Command::SortCycle,
            Command::PinToggle,
            Command::Search,
            Command::AddEntry,
            Command::EditEntry,
            Command::DeleteEntry,
            Command::History,
            Command::CopyPassword,
            Command::CopyUsername,
            Command::Sync,
            Command::VisualMode,
            Command::MoveToGroup,
            Command::AddTag,
            Command::RemoveTag,
        ] {
            if self.keys.matches(cmd, key) {
                self.execute_command(cmd, None);
                return;
            }
        }
        // Navigation / confirm falls through to the focused pane (also via the
        // shared path so the palette reaches the same handlers).
        if let Some(cmd) = self.nav_command_for(key) {
            self.execute_command(cmd, None);
        }
    }

    /// The selected tree node's UUID if (and only if) it is an entry.
    fn selected_entry_uuid(&self) -> Option<Uuid> {
        let uuid = self.tree.selected()?;
        self.vault
            .as_ref()
            .and_then(|v| v.get_entry(uuid).ok())
            .map(|_| uuid)
    }

    /// Persist the in-memory vault to disk — the single vault-write choke point
    /// (OQ-1). Every mutating command routes its save here so a test seam
    /// (`save_count`) and, later, the read-only guard (T4.7) have exactly one
    /// place to observe/deny writes. No-op when no vault is unlocked (the
    /// callers guarantee one is present; the guard keeps the method total).
    fn persist_vault(&mut self) -> Result<(), PersistError> {
        // Read-only guard (T4.7, layer 2): defense in depth if a dispatch path
        // reaches here without layer 1 having disabled the command. No write
        // occurs and the save counter does not advance.
        if self.read_only {
            self.status_bar
                .set_warning("Read-only session — vault not saved.", Instant::now());
            return Err(PersistError::ReadOnly);
        }
        #[cfg(test)]
        {
            self.save_count += 1;
        }
        match self.vault.as_mut() {
            Some(vault) => vault.save().map_err(PersistError::from),
            None => Ok(()),
        }
    }

    /// The context the dispatcher is in *right now* — phase × active tab × pane
    /// focus × open overlay (design §2.2.1). The single source the hint bar
    /// (T2.1), which-key (T2.2), and palette (T2.3) all derive from. An open
    /// overlay wins (it captures input); otherwise the phase (and, in the
    /// workspace, the active tab / focused pane) decides.
    pub(crate) fn current_context(&self) -> Contexts {
        if let Some(overlay) = self.overlay.as_ref() {
            return match overlay {
                Overlay::Search(_) => Contexts::SEARCH,
                Overlay::Edit(_) => Contexts::EDIT,
                Overlay::History(_) => Contexts::HISTORY,
                Overlay::ConfirmDelete { .. }
                | Overlay::ConfirmBulkDelete { .. }
                | Overlay::ConfirmQuit
                | Overlay::GroupPicker(_)
                | Overlay::TagInput(_) => Contexts::CONFIRM,
                Overlay::SyncUnlock { .. } => Contexts::SYNC_UNLOCK,
                Overlay::SyncConfig(_) => Contexts::SYNC_CONFIG,
                Overlay::Palette(_) => Contexts::PALETTE,
            };
        }
        match self.phase {
            Phase::UnlockList => Contexts::UNLOCK_LIST,
            Phase::UnlockPrompt { .. } => Contexts::UNLOCK_PROMPT,
            Phase::LockScreen => Contexts::LOCK_SCREEN,
            Phase::Workspace => match self.tabs.active_tab() {
                Tab::Secrets => match self.focus {
                    Focus::Tree => Contexts::SECRETS_TREE,
                    Focus::Detail => Contexts::SECRETS_DETAIL,
                },
                Tab::Pinned(_) => Contexts::PINNED_TAB,
                Tab::Settings => Contexts::SETTINGS_TAB,
            },
        }
    }

    /// The live enablement of `id` — whether the command should be offered as
    /// dispatchable (design §2.2.1). Co-located with dispatch state so the same
    /// predicate drives both the projections (hint bar, palette) and dispatch,
    /// making the two structurally unable to disagree (the gitui discipline).
    ///
    /// Each `Disabled` case below is paired 1:1 with a dispatch guard that makes
    /// the command a no-op in that state; the pairing is pinned by
    /// `command_state_disabled_matches_dispatch_guard`. Entry-scoped commands
    /// (copy / edit / delete / pin) need a selected *entry* (a group row is not
    /// actionable); reveal / history also work on a pinned tab (whose entry is
    /// always present); sync needs a configured remote.
    pub(crate) fn command_state(&self, id: Command) -> CmdState {
        if self.sync.is_syncing() && !Self::command_available_during_sync(id) {
            return CmdState::Disabled;
        }
        // Read-only session (T4.7, layer 1): every vault-mutating command is
        // disabled outright — the hint bar dims it and the palette lists-but-
        // refuses it, for free, because both derive from this predicate.
        if self.read_only && RO_MUTATING_COMMANDS.contains(&id) {
            return CmdState::Disabled;
        }
        match id {
            Command::CopyPassword
            | Command::CopyUsername
            | Command::EditEntry
            | Command::PinToggle => Self::enabled_if(self.selected_entry_uuid().is_some()),
            // Delete acts on the marked set when one exists, else the selection.
            Command::DeleteEntry => {
                Self::enabled_if(!self.marks.is_empty() || self.selected_entry_uuid().is_some())
            }
            // Bulk operations require a non-empty mark set ("disabled hints teach"
            // the visual-mode feature — T4.5 / gitui discipline).
            Command::MoveToGroup | Command::AddTag | Command::RemoveTag => {
                Self::enabled_if(!self.marks.is_empty())
            }
            Command::RevealPassword | Command::History => {
                Self::enabled_if(self.context_entry_present())
            }
            Command::Sync => Self::enabled_if(self.sync_configured()),
            _ => CmdState::Enabled,
        }
    }

    /// `Enabled` iff `cond`, else `Disabled`.
    fn enabled_if(cond: bool) -> CmdState {
        if cond {
            CmdState::Enabled
        } else {
            CmdState::Disabled
        }
    }

    /// Commands that do not need access to the vault while the sync worker owns
    /// it. This predicate is shared by palette enablement and execution.
    fn command_available_during_sync(id: Command) -> bool {
        matches!(
            id,
            Command::Quit
                | Command::LockNow
                | Command::Help
                | Command::NextTab
                | Command::PrevTab
                | Command::JumpToTab
        )
    }

    /// Is there an entry the *current context* can act on with reveal / history?
    /// A pinned tab always has one (its pinned UUID); on the Secrets tab it is
    /// the tree selection. Mirrors the dispatch split between `on_pinned_key`
    /// (always acts) and `on_secrets_key` (guards on the selection).
    fn context_entry_present(&self) -> bool {
        matches!(self.tabs.active_tab(), Tab::Pinned(_)) || self.selected_entry_uuid().is_some()
    }

    /// The single execution path for a command (T2.3, design §2.2.3). Key
    /// dispatch resolves a `KeyEvent` to a [`Command`] and calls this; the
    /// palette injects the selected command directly — so keys and the palette
    /// can never diverge. Enablement is the caller's responsibility (dispatch
    /// guards and the palette both consult [`Self::command_state`]); a command
    /// invoked while `Disabled` no-ops through its handler's own guard.
    ///
    /// Navigation / confirm / cancel are context-specific and route through
    /// [`Self::exec_context_nav`] to the active pane; every other command maps
    /// to its handler. `Generate` is EDIT-overlay-only and never reaches here
    /// from a workspace context (the palette lists it disabled there).
    pub(crate) fn execute_command(&mut self, id: Command, count: Option<u16>) {
        // Read-only enforcement at the single dispatch path (T4.7): keyboard,
        // palette, and mouse all funnel here, so blocking the mutating *command*
        // here — not merely its disk write — is what actually prevents the
        // in-memory mutation AND the sync push in a read-only session. (The
        // `command_state` predicate only drives hint-bar/palette dimming; it is
        // NOT consulted by key dispatch, so it cannot be the enforcement point.)
        if self.read_only && RO_MUTATING_COMMANDS.contains(&id) {
            self.status_bar.set_warning(
                "Read-only session — that action is disabled.",
                Instant::now(),
            );
            return;
        }
        // Always available, regardless of an in-flight sync — these self-guard or
        // defer (quit/lock flush-or-defer; the palette is read-only chrome; tab
        // motion is vault-independent).
        match id {
            Command::Quit => return self.request_quit(),
            Command::LockNow => {
                if matches!(self.phase, Phase::Workspace) {
                    self.request_lock();
                }
                return;
            }
            Command::Help => return self.open_palette(),
            Command::NextTab | Command::PrevTab | Command::JumpToTab => {
                return self.apply_tab_motion(id, count);
            }
            _ => {}
        }
        // Every remaining command acts on the vault / active tab body, which is
        // unavailable while a background sync owns the vault (ADR-T4a). Mirror
        // `dispatch_active_tab_key`'s guard so key dispatch and the palette share
        // the same behaviour (the single-execution-path contract).
        if !Self::command_available_during_sync(id) && self.sync.is_syncing() {
            return;
        }
        match id {
            Command::FocusPane => self.toggle_focus(),
            Command::Search => self.open_search(),
            Command::AddEntry => self.open_add(),
            Command::EditEntry => self.open_edit(),
            Command::DeleteEntry => self.open_delete_confirm(),
            Command::CopyPassword => self.do_copy(CopyField::Password),
            Command::CopyUsername => self.do_copy(CopyField::Username),
            Command::RevealPassword => self.exec_reveal(),
            Command::History => self.exec_history(),
            Command::PinToggle => self.toggle_pin_selected(),
            Command::SortCycle => self.cycle_sort(),
            Command::Sync => self.request_sync(),
            Command::Next
            | Command::Prev
            | Command::Parent
            | Command::Child
            | Command::Confirm
            | Command::Cancel => self.exec_context_nav(id),
            Command::JumpBack => self.jump_back(),
            Command::JumpForward => self.jump_forward(),
            Command::VisualMode => self.enter_visual_mode(),
            Command::MoveToGroup => self.open_group_picker(),
            Command::AddTag => self.open_tag_input(TagAction::Add),
            Command::RemoveTag => self.open_tag_input(TagAction::Remove),
            // `Generate` is EDIT-overlay-only (reached through the edit overlay,
            // never a top-level command — the palette lists it disabled
            // elsewhere); the rest are handled in the always-available block
            // above. All are no-ops here.
            // Search-overlay-local commands (T4.2: CycleScope/QuickSelect/
            // OpenEntry) are only meaningful while the search overlay owns input,
            // where `on_search_key` handles them directly — as top-level/palette
            // commands they are no-ops, like the block below.
            Command::CycleScope
            | Command::QuickSelect
            | Command::OpenEntry
            | Command::Generate
            | Command::Quit
            | Command::LockNow
            | Command::Help
            | Command::NextTab
            | Command::PrevTab
            | Command::JumpToTab => {}
        }
    }

    /// Open the command palette (`?`) over the current context (T2.3). Rows are
    /// computed against this underlying context, so out-of-context commands list
    /// disabled (the palette teaches the whole surface).
    pub(crate) fn open_palette(&mut self) {
        let underlying = self.current_context();
        self.reset_tab_motion();
        self.overlay = Some(Overlay::Palette(overlay::PaletteState::new(underlying)));
    }

    /// Toggle Secrets-tab pane focus (tree ↔ detail).
    fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Tree => Focus::Detail,
            Focus::Detail => Focus::Tree,
        };
    }

    /// Cycle the tree sort order and post a status note (selection is UUID-based,
    /// so it survives the re-sort).
    fn cycle_sort(&mut self) {
        self.tree.cycle_sort();
        self.status_bar.set(
            format!("Sort: {}", self.tree.sort().label()),
            Instant::now(),
        );
    }

    /// Reveal / hide the password for the context entry. On a pinned tab the
    /// pinned entry is always revealable; on the Secrets tab a group row has
    /// nothing to reveal (the no-op paired with `command_state == Disabled`).
    fn exec_reveal(&mut self) {
        let revealable = matches!(self.tabs.active_tab(), Tab::Pinned(_))
            || self.selected_entry_uuid().is_some();
        if revealable {
            self.reveal_password = !self.reveal_password;
        }
    }

    /// Open the history overlay for the context entry: the pinned entry on a
    /// pinned tab, else the tree selection (guarded).
    fn exec_history(&mut self) {
        match self.tabs.active_tab() {
            Tab::Pinned(uuid) => self.open_history_for(uuid),
            _ => self.open_history(),
        }
    }

    /// Route a navigation / confirm / cancel command to the active pane's
    /// handler — the shared target for both key dispatch and the palette.
    fn exec_context_nav(&mut self, id: Command) {
        match self.phase {
            Phase::UnlockList => self.unlock_list_nav(id),
            Phase::Workspace => match self.tabs.active_tab() {
                Tab::Secrets => match self.focus {
                    Focus::Tree => self.tree_command(id),
                    Focus::Detail => self.detail_command(id),
                },
                Tab::Pinned(uuid) => self.pinned_command(uuid, id),
                Tab::Settings => self.settings_command(id),
            },
            // Pre-unlock prompt / lock screen have no registry-driven nav.
            Phase::UnlockPrompt { .. } | Phase::LockScreen => {}
        }
    }

    /// Resolve a key to a navigation / confirm / cancel command, if it triggers
    /// one — the reverse lookup key dispatch uses to reach [`Self::exec_context_nav`].
    fn nav_command_for(&self, key: &KeyEvent) -> Option<Command> {
        [
            Command::Next,
            Command::Prev,
            Command::Parent,
            Command::Child,
            Command::Confirm,
            Command::Cancel,
        ]
        .into_iter()
        .find(|&cmd| self.keys.matches(cmd, key))
    }

    /// The group a freshly added entry should land in: the selected group, else
    /// the selected entry's parent group, else the root group.
    fn add_target_group(&self) -> Uuid {
        let Some(vault) = self.vault.as_ref() else {
            return Uuid::nil();
        };
        let root = vault.root_group_uuid();
        let Some(sel) = self.tree.selected() else {
            return root;
        };
        // A selected group is itself the target.
        if vault.group_view(sel).is_ok() {
            return sel;
        }
        // A selected entry → its parent group (nearest preceding shallower row).
        let rows = entry_tree::build_rows(vault, &self.tree, &self.recents);
        if let Some(idx) = rows.iter().position(|r| r.uuid == sel) {
            let depth = rows[idx].depth;
            for i in (0..idx).rev() {
                if rows[i].depth < depth {
                    return rows[i].uuid;
                }
            }
        }
        root
    }

    fn open_search(&mut self) {
        // Capture the exact pre-search view so Esc can restore it verbatim (AC-6).
        let saved = search::SavedView {
            selected: self.tree.selected(),
            focus: self.focus,
            detail_scroll: self.detail_scroll,
        };
        let scope = match self.user_config.search.default_scope.as_str() {
            "group" => self
                .current_tree_group()
                .map_or(SearchScope::All, SearchScope::GroupSubtree),
            "tag" => self
                .selected_entry_uuid()
                .and_then(|uuid| self.vault.as_ref()?.get_entry(uuid).ok())
                .and_then(|entry| entry.tags().first().cloned())
                .map_or(SearchScope::All, |tag| {
                    SearchScope::Tag(tag.as_str().to_string())
                }),
            _ => SearchScope::All,
        };
        let mut state = SearchState::new(scope, saved);
        self.run_search(&mut state);
        self.overlay = Some(Overlay::Search(state));
    }

    /// Restore the pre-search tree selection, pane focus, and detail scroll
    /// (search Esc / cancel — AC-6).
    fn restore_saved_view(&mut self, saved: &search::SavedView) {
        if let Some(uuid) = saved.selected {
            self.tree.select(uuid);
        }
        self.focus = saved.focus;
        self.detail_scroll = saved.detail_scroll;
    }

    /// The next scope in the cycle `[ALL] → [GROUP:current] → [TAG:first] → [ALL]`
    /// (Ctrl+S). The group target is the selected tree node's group; the tag is
    /// the first tag of the highlighted result. Unavailable targets skip ahead.
    fn next_search_scope(&self, state: &SearchState) -> SearchScope {
        match &state.scope {
            SearchScope::All => match self.current_tree_group() {
                Some(group) => SearchScope::GroupSubtree(group),
                None => self.first_tag_scope(state).unwrap_or(SearchScope::All),
            },
            SearchScope::GroupSubtree(_) => self.first_tag_scope(state).unwrap_or(SearchScope::All),
            SearchScope::Tag(_) => SearchScope::All,
        }
    }

    /// The group of the current tree node: a selected group is itself; a selected
    /// entry resolves to its parent group.
    fn current_tree_group(&self) -> Option<Uuid> {
        let vault = self.vault.as_ref()?;
        let sel = self.tree.selected()?;
        if vault.group_view(sel).is_ok() {
            return Some(sel);
        }
        // Selected entry → its parent group via the node path.
        let path = screens::secrets::node_path(vault, vault.root_group_uuid(), sel)?;
        // The element before the entry (last) is its group; None if entry is at root.
        (path.len() >= 2).then(|| path[path.len() - 2])
    }

    fn first_tag_scope(&self, state: &SearchState) -> Option<SearchScope> {
        let uuid = state.selected_uuid()?;
        let vault = self.vault.as_ref()?;
        let entry = vault.get_entry(uuid).ok()?;
        entry
            .tags()
            .first()
            .map(|t| SearchScope::Tag(t.as_str().to_string()))
    }

    /// The primary search action on `uuid`: copy the password (default) or open
    /// the entry, per `config.search.enter-action` (T4.2). Both bump recents.
    fn search_primary_action(&mut self, uuid: Uuid) {
        match self.user_config.search.enter_action {
            crate::user_config::EnterAction::Copy => {
                self.copy_field_of(uuid, CopyField::Password);
            }
            crate::user_config::EnterAction::Open => self.jump_to_entry(uuid),
        }
    }

    /// The non-primary search action. Enter and Tab always provide opposite
    /// copy/open actions so changing `enter-action` swaps them instead of
    /// making both keys open the entry.
    fn search_secondary_action(&mut self, uuid: Uuid) {
        match self.user_config.search.enter_action {
            crate::user_config::EnterAction::Copy => self.jump_to_entry(uuid),
            crate::user_config::EnterAction::Open => {
                self.copy_field_of(uuid, CopyField::Password);
            }
        }
    }

    fn open_add(&mut self) {
        let group = self.add_target_group();
        self.overlay = Some(Overlay::Edit(Box::new(EditState::new_add(group))));
    }

    fn open_edit(&mut self) {
        let Some(uuid) = self.selected_entry_uuid() else {
            self.status_bar
                .set_warning("Select an entry to edit.", Instant::now());
            return;
        };
        let overlay = self
            .vault
            .as_ref()
            .and_then(|v| v.get_entry(uuid).ok())
            .map(|view| Overlay::Edit(Box::new(EditState::from_entry(uuid, &view))));
        if let Some(overlay) = overlay {
            self.overlay = Some(overlay);
        }
    }

    fn open_delete_confirm(&mut self) {
        // A non-empty mark set takes precedence: delete the whole marked set
        // through the pluralized bulk confirmation (T4.5).
        if !self.marks.is_empty() {
            let uuids = self.marked_uuids();
            let titles = uuids.iter().map(|&u| self.entry_title(u)).collect();
            self.overlay = Some(Overlay::ConfirmBulkDelete { uuids, titles });
            return;
        }
        let Some(uuid) = self.selected_entry_uuid() else {
            self.status_bar
                .set_warning("Select an entry to delete.", Instant::now());
            return;
        };
        let title = self.entry_title(uuid);
        self.overlay = Some(Overlay::ConfirmDelete {
            entry_uuid: uuid,
            title,
        });
    }

    fn open_history(&mut self) {
        let Some(uuid) = self.selected_entry_uuid() else {
            self.status_bar
                .set_warning("Select an entry to view its history.", Instant::now());
            return;
        };
        self.open_history_for(uuid);
    }

    /// Open the history overlay for a specific entry (shared by the
    /// Secrets-tab selection and pinned tabs).
    fn open_history_for(&mut self, uuid: Uuid) {
        let overlay = self
            .vault
            .as_ref()
            .and_then(|v| v.get_entry(uuid).ok())
            .map(|view| {
                let title = if view.title().is_empty() {
                    "(untitled)".to_string()
                } else {
                    view.title().to_string()
                };
                Overlay::History(HistoryState::from_views(title, &view.history()))
            });
        if let Some(overlay) = overlay {
            self.overlay = Some(overlay);
        }
    }

    /// Copy the selected entry's password or username to the clipboard with an
    /// armed auto-clear (T5.5). Bumps recents on success (D-6).
    fn do_copy(&mut self, field: CopyField) {
        let Some(uuid) = self.selected_entry_uuid() else {
            self.status_bar
                .set_warning("Select an entry first.", Instant::now());
            return;
        };
        self.copy_field_of(uuid, field);
    }

    /// Copy `field` from a specific entry (shared by the Secrets tab and the
    /// search overlay's Enter-copies action, T4.2). Copy is a *read* — allowed
    /// even in a read-only session.
    fn copy_field_of(&mut self, uuid: Uuid, field: CopyField) {
        let (text, label) = {
            let Some(view) = self.vault.as_ref().and_then(|v| v.get_entry(uuid).ok()) else {
                return;
            };
            match field {
                CopyField::Password => (view.password().to_string(), "Password"),
                CopyField::Username => (view.username().to_string(), "Username"),
            }
        };
        if text.is_empty() {
            self.status_bar
                .set_warning(format!("{label} is empty."), Instant::now());
            return;
        }
        match self.clipboard.copy(text, clipboard::CLIPBOARD_TTL) {
            Ok(()) => {
                self.status_bar
                    .set(format!("{label} copied (clears in 30s)."), Instant::now());
                self.recents.bump(uuid);
                self.persist_ui_state();
            }
            Err(e) => self
                .status_bar
                .set_error(format!("Copy failed: {e}"), Instant::now()),
        }
    }

    /// Pin or unpin the currently-selected entry (T4.4). Groups are not
    /// pinnable. Posts a status note (naming the evicted entry on LRU eviction —
    /// D-7) and persists the new pin set to `tui.toml`.
    fn toggle_pin_selected(&mut self) {
        let Some(uuid) = self.tree.selected() else {
            return;
        };
        let is_entry = self
            .vault
            .as_ref()
            .is_some_and(|v| v.get_entry(uuid).is_ok());
        if !is_entry {
            self.status_bar
                .set_warning("Only entries can be pinned.", Instant::now());
            return;
        }
        let note = match self.tabs.toggle_pin(uuid) {
            PinChange::Pinned => "Pinned entry.".to_string(),
            PinChange::Unpinned => "Unpinned entry.".to_string(),
            PinChange::PinnedEvicting(old) => {
                let old_title = self.entry_title(old);
                format!("Pinned entry; unpinned \"{old_title}\" (max {MAX_PINS} pins).")
            }
        };
        self.status_bar.set(note, Instant::now());
        self.persist_ui_state();
    }

    /// The display title of an entry by UUID (for status notes). Falls back when
    /// the entry is missing or untitled. Titles are non-secret (shown in the
    /// tree), so they are safe to surface.
    /// The display name of a group by UUID (search scope indicator, T4.2).
    pub(crate) fn group_name_for(&self, uuid: Uuid) -> String {
        self.vault
            .as_ref()
            .and_then(|v| v.group_view(uuid).ok())
            .map_or_else(|| "(group)".to_string(), |g| g.name().to_string())
    }

    fn entry_title(&self, uuid: Uuid) -> String {
        self.vault
            .as_ref()
            .and_then(|v| v.get_entry(uuid).ok())
            .map_or_else(
                || "(entry)".to_string(),
                |e| {
                    let t = e.title();
                    if t.is_empty() {
                        "(untitled)".to_string()
                    } else {
                        t.to_string()
                    }
                },
            )
    }

    /// Mirror the live pins + recents into `ui_config` and persist `tui.toml`.
    /// Best-effort (U.5): a write failure warns in the status bar and the UI
    /// keeps running on in-memory state. No-op while locked.
    fn persist_ui_state(&mut self) {
        let Some(name) = self.selected_vault.clone() else {
            return;
        };
        if self.vault.is_none() {
            return;
        }
        self.ui_config.set_vault_state(
            &name,
            self.tabs.pins().to_vec(),
            self.recents.as_slice().to_vec(),
        );
        self.save_ui_config();
    }

    /// Persist per-vault state to `tui.toml`. Best-effort (U.5): a write failure
    /// warns in the status bar and the UI keeps running on in-memory state. Used
    /// by [`Self::persist_ui_state`] (pins/recents).
    fn save_ui_config(&mut self) {
        let path = config::config_path(&self.paths);
        if let Err(e) = self.ui_config.save(&self.paths, &path) {
            self.status_bar
                .set_error(format!("Could not save tui.toml: {e}"), Instant::now());
        }
    }

    /// Persist user preferences to `config.toml` (Settings editor). Best-effort
    /// (U.5): a write failure warns in the status bar and the UI keeps running
    /// on in-memory state. Comments are not preserved (design §2.2.5).
    fn update_user_config(&mut self, update: impl FnOnce(&mut UserConfig)) -> bool {
        match UserConfig::update_at(&self.user_config_path, update) {
            Ok(latest) => {
                self.user_config = latest;
                true
            }
            Err(e) => {
                self.status_bar.set_error(e, Instant::now());
                false
            }
        }
    }

    /// The pinned entries' display titles, in pin order, for the tab strip.
    pub(crate) fn pin_titles(&self) -> Vec<String> {
        self.tabs
            .pins()
            .iter()
            .map(|&uuid| self.entry_title(uuid))
            .collect()
    }

    /// Tree-focused navigation. Rebuilds the flattened rows (cheap for ≤500
    /// entries), applies the motion, and resets reveal/scroll when the selected
    /// entry changes. `cmd` is a resolved navigation command (from a key or the
    /// palette); non-navigation commands are ignored here.
    fn tree_command(&mut self, cmd: Command) {
        let rows = match self.vault.as_ref() {
            Some(vault) => entry_tree::build_rows(vault, &self.tree, &self.recents),
            None => return,
        };
        let changed = match cmd {
            Command::Next => self.tree.move_next(&rows),
            Command::Prev => self.tree.move_prev(&rows),
            Command::Parent => self.tree.collapse_or_parent(&rows),
            Command::Child => {
                // Two-axis navigation (T4.4): `l`/→ on a leaf entry steps into
                // the detail pane (spatial continuity, yazi `enter`); on a group
                // it expands / steps to the first child as before.
                if self.tree.selected_is_entry(&rows) {
                    if let Some(uuid) = self.tree.selected() {
                        self.enter_detail(uuid);
                    }
                    false
                } else {
                    self.tree.expand_or_child(&rows)
                }
            }
            Command::Confirm => {
                // Enter: toggle a group's expansion, or step into the detail pane
                // when an entry is selected (which counts as "opening" it → bump
                // recents, D-6 / ADR-T5).
                if self.tree.selected_is_entry(&rows) {
                    if let Some(uuid) = self.tree.selected() {
                        self.enter_detail(uuid);
                    }
                } else {
                    self.tree.toggle_expand(&rows);
                }
                false
            }
            _ => return,
        };
        if changed {
            self.reveal_password = false;
            self.detail_scroll = 0;
        }
    }

    /// Detail-focused scrolling. `Next`/`Prev` scroll one row; `Parent`/`Cancel`
    /// return focus to the tree. `cmd` is a resolved navigation command; the
    /// stored offset is bounded by the content height so an over-scroll can be
    /// walked back with the same number of `Prev`s.
    fn detail_command(&mut self, cmd: Command) {
        match cmd {
            Command::Next => {
                self.detail_scroll = self
                    .detail_scroll
                    .saturating_add(1)
                    .min(self.max_detail_scroll());
            }
            Command::Prev => self.detail_scroll = self.detail_scroll.saturating_sub(1),
            Command::Parent | Command::Cancel => self.focus = Focus::Tree,
            _ => {}
        }
    }

    /// Upper bound for `detail_scroll`: the detail content's line count. The
    /// render adapter clamps further to `lines - viewport`; this only keeps the
    /// stored offset from running away past the content while holding `j`.
    fn max_detail_scroll(&self) -> u16 {
        self.tree
            .selected()
            .map_or(0, |uuid| self.max_scroll_for(uuid))
    }

    /// [`Self::max_detail_scroll`] for an explicit entry (pinned tabs).
    fn max_scroll_for(&self, uuid: Uuid) -> u16 {
        self.vault
            .as_ref()
            .and_then(|vault| entry_detail::detail_data_for(vault, uuid, Utc::now()))
            .map_or(0, |data| {
                let count =
                    entry_detail::detail_lines(&data, self.reveal_password, &self.theme).len();
                u16::try_from(count).unwrap_or(u16::MAX)
            })
    }

    // ---- Phase 5: overlay dispatch ----

    /// Route a key to the open overlay. The overlay is moved out for the
    /// duration so its handler can call `&mut self` methods (vault mutation,
    /// status, persistence) without aliasing `self.overlay`; it is put back
    /// unless the handler asked to close it.
    fn on_overlay_key(&mut self, ev: &Event) {
        let Event::Key(key) = ev else {
            return;
        };
        let Some(mut overlay) = self.overlay.take() else {
            return;
        };
        let keep = match &mut overlay {
            Overlay::Search(state) => self.on_search_key(state, ev, key),
            Overlay::Edit(state) => self.on_edit_key(state, ev, key),
            Overlay::History(state) => Self::on_history_key(state, key),
            Overlay::ConfirmDelete { entry_uuid, .. } => {
                self.on_confirm_delete_key(*entry_uuid, key)
            }
            Overlay::ConfirmBulkDelete { uuids, .. } => self.on_confirm_bulk_delete_key(uuids, key),
            Overlay::ConfirmQuit => self.on_confirm_quit_key(key),
            Overlay::GroupPicker(state) => self.on_group_picker_key(state, key),
            Overlay::TagInput(state) => self.on_tag_input_key(state, ev, key),
            Overlay::SyncUnlock { input, pending } => self.on_sync_unlock_key(input, *pending, key),
            Overlay::SyncConfig(state) => self.on_sync_config_key(state, ev, key),
            Overlay::Palette(state) => self.on_palette_key(state, ev, key),
        };
        if keep {
            self.overlay = Some(overlay);
        }
    }

    /// Search overlay keys (T4.2). Arrows / `Ctrl+N`/`Ctrl+P` move the selection
    /// (so `j`/`k` stay typeable); `Ctrl+S` cycles the scope; `Tab` opens the
    /// entry; `Alt+1..9` quick-selects a visible row; `Enter` runs the primary
    /// action (copy or open, per config); `Esc` restores the pre-search view;
    /// any other key edits the query and re-runs the search.
    fn on_search_key(&mut self, state: &mut SearchState, ev: &Event, key: &KeyEvent) -> bool {
        // Esc restores the exact pre-search view (AC-6) and closes.
        if self.keys.matches(Command::Cancel, key) {
            self.restore_saved_view(&state.saved);
            return false;
        }
        // Ctrl+S cycles the scope; the query is preserved and re-run.
        if self.keys.matches(Command::CycleScope, key) {
            state.scope = self.next_search_scope(state);
            self.run_search(state);
            return true;
        }
        // Tab performs the opposite action from Enter. This preserves both
        // copy and open regardless of the configured primary action.
        if self.keys.matches(Command::OpenEntry, key) {
            if let Some(uuid) = state.selected_uuid() {
                self.search_secondary_action(uuid);
            }
            return false;
        }
        // Alt+1..9 acts on the numbered VISIBLE row with the primary action.
        if self.keys.matches(Command::QuickSelect, key) {
            if let Some(n) = digit_value(key) {
                if let Some(uuid) = state.quick_select_uuid(n) {
                    self.search_primary_action(uuid);
                    return false;
                }
            }
            return true; // out-of-range quick-select is a no-op, overlay stays
        }
        match key.code {
            KeyCode::Enter => {
                if let Some(uuid) = state.selected_uuid() {
                    self.search_primary_action(uuid);
                }
                return false;
            }
            KeyCode::Down => {
                state.select_next();
                return true;
            }
            KeyCode::Up => {
                state.select_prev();
                return true;
            }
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.select_next();
                return true;
            }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.select_prev();
                return true;
            }
            _ => {}
        }
        if let Some(req) = tui_input::backend::crossterm::to_input_request(ev) {
            if state.input.handle(req).is_some() {
                self.run_search(state);
            }
        }
        true
    }

    /// Run the live query and refresh the result rows. Pure read of the vault.
    fn run_search(&self, state: &mut SearchState) {
        let query = state.input.value().to_string();
        let Some(vault) = self.vault.as_ref() else {
            state.set_results(Vec::new());
            return;
        };
        // Fuzzy mode, scoped, recency-boosted. An empty query is browse mode
        // (recents first) so the overlay opens useful before a keystroke.
        let opts = SearchOptions::fuzzy(query)
            .with_scope(state.scope.clone())
            .with_boost(self.recents.as_slice().to_vec());
        let results = vault.search(opts).unwrap_or_default();
        let rows = results
            .iter()
            .map(|r| Self::build_search_row(vault, r))
            .collect();
        state.set_results(rows);
    }

    /// Resolve a core [`SearchResult`] into a display [`search::SearchRow`],
    /// carrying the title's matched-char positions for highlighting.
    fn build_search_row(vault: &Vault, result: &SearchResult) -> search::SearchRow {
        let (title, username, url_host, tags) = vault.get_entry(result.uuid).map_or_else(
            |_| {
                (
                    "(missing)".to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            },
            |e| {
                let tags = e
                    .tags()
                    .iter()
                    .map(|t| t.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                (
                    e.title().to_string(),
                    e.username().to_string(),
                    search::url_host(e.url()),
                    tags,
                )
            },
        );
        let title_indices = result
            .match_indices
            .iter()
            .find(|(field, _)| *field == MatchedField::Title)
            .map(|(_, idx)| idx.clone())
            .unwrap_or_default();
        search::SearchRow {
            uuid: result.uuid,
            title,
            username,
            url_host,
            tags,
            title_indices,
        }
    }

    /// Jump the Secrets tree to `uuid`, focus the detail pane, and bump recents
    /// (D-6). The detail pane resolves the selection by UUID even inside a
    /// collapsed group, so the entry is shown immediately.
    fn jump_to_entry(&mut self, uuid: Uuid) {
        self.expand_ancestors(uuid);
        self.jump_history.push(uuid);
        self.tabs.jump_to(1); // ensure the Secrets tab is active (ordinal 1)
        self.tree.select(uuid);
        self.focus = Focus::Detail;
        self.reveal_password = false;
        self.detail_scroll = 0;
        self.recents.bump(uuid);
        self.persist_ui_state();
    }

    /// Step into the detail pane for `uuid` (via `l`/→ on a leaf or `Enter`):
    /// records the visit in the jump history, focuses detail, and bumps recents
    /// (D-6 / ADR-T5).
    fn enter_detail(&mut self, uuid: Uuid) {
        self.jump_history.push(uuid);
        self.focus = Focus::Detail;
        self.recents.bump(uuid);
        self.persist_ui_state();
    }

    /// `Ctrl+O` — walk to the previously-visited node. Posts a status note when
    /// there is no earlier node.
    fn jump_back(&mut self) {
        let Some(current) = self.current_jump_uuid() else {
            return;
        };
        match self.jump_history.back(current) {
            Some(target) => self.jump_to_history(target),
            None => self.status = Some("no earlier entry".to_string()),
        }
    }

    /// `Ctrl+I` — walk forward after a `Ctrl+O`. Posts a status note when there
    /// is nothing ahead.
    fn jump_forward(&mut self) {
        let Some(current) = self.current_jump_uuid() else {
            return;
        };
        match self.jump_history.forward(current) {
            Some(target) => self.jump_to_history(target),
            None => self.status = Some("no later entry".to_string()),
        }
    }

    /// Select `uuid` (an entry or group) from the jump history: expand its
    /// ancestor groups so the row is visible, switch to the Secrets tab, and
    /// focus the detail pane for an entry (tree for a group). Does NOT push onto
    /// the history (a back/forward walk is not a new visit).
    fn jump_to_history(&mut self, uuid: Uuid) {
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        let is_group = vault.group_view(uuid).is_ok();
        if let Some(path) = screens::secrets::node_path(vault, vault.root_group_uuid(), uuid) {
            // Expand every ancestor group (all but the target itself).
            for ancestor in &path[..path.len().saturating_sub(1)] {
                self.tree.expand(*ancestor);
            }
        }
        self.tabs.jump_to(1);
        self.tree.select(uuid);
        self.reveal_password = false;
        self.detail_scroll = 0;
        if is_group {
            self.focus = Focus::Tree;
        } else {
            self.focus = Focus::Detail;
            self.recents.bump(uuid);
            self.persist_ui_state();
        }
    }

    fn current_jump_uuid(&self) -> Option<Uuid> {
        match self.tabs.active_tab() {
            Tab::Pinned(uuid) => Some(uuid),
            Tab::Secrets | Tab::Settings => self.tree.selected(),
        }
    }

    /// Expand every group above `uuid` so tree selection and keyboard
    /// navigation agree after search/history jumps into collapsed subtrees.
    fn expand_ancestors(&mut self, uuid: Uuid) {
        let path = self
            .vault
            .as_ref()
            .and_then(|vault| screens::secrets::node_path(vault, vault.root_group_uuid(), uuid));
        if let Some(path) = path {
            for ancestor in &path[..path.len().saturating_sub(1)] {
                self.tree.expand(*ancestor);
            }
        }
    }

    // ---- T4.5: visual mode + bulk operations ----

    /// The marked entries as an ordered UUID vector (sorted for deterministic
    /// bulk-op iteration and test assertions).
    fn marked_uuids(&self) -> Vec<Uuid> {
        let mut v: Vec<Uuid> = self.marks.iter().copied().collect();
        v.sort_unstable();
        v
    }

    /// A persistent selection indicator for the breadcrumb line: `VISUAL` while
    /// in visual mode, plus `N selected` while any marks exist. `None` when
    /// neither applies (design §2.2.8; text + Modifier, never colour alone).
    pub(crate) fn selection_indicator(&self) -> Option<String> {
        let visual = matches!(self.tree_mode, TreeMode::Visual { .. });
        let n = self.marks.len();
        match (visual, n) {
            (false, 0) => None,
            (true, 0) => Some("VISUAL".to_string()),
            (true, _) => Some(format!("VISUAL · {n} selected")),
            (false, _) => Some(format!("{n} selected")),
        }
    }

    /// Enter (or re-anchor) visual multi-select at the current row and mark it.
    fn enter_visual_mode(&mut self) {
        let rows = match self.vault.as_ref() {
            Some(v) => entry_tree::build_rows(v, &self.tree, &self.recents),
            None => return,
        };
        let anchor = self.tree.selected_index(&rows).unwrap_or(0);
        self.tree_mode = TreeMode::Visual { anchor };
        self.recompute_visual_marks();
    }

    /// Recompute the marked set as the entries spanned by anchor..cursor (groups
    /// in the span are skipped, not marked). No-op outside visual mode.
    fn recompute_visual_marks(&mut self) {
        let TreeMode::Visual { anchor } = self.tree_mode else {
            return;
        };
        let rows = match self.vault.as_ref() {
            Some(v) => entry_tree::build_rows(v, &self.tree, &self.recents),
            None => return,
        };
        let cursor = self.tree.selected_index(&rows).unwrap_or(anchor);
        let (lo, hi) = (anchor.min(cursor), anchor.max(cursor));
        self.marks = rows
            .get(lo..=hi)
            .unwrap_or(&[])
            .iter()
            .filter(|r| matches!(r.kind, entry_tree::RowKind::Entry))
            .map(|r| r.uuid)
            .collect();
    }

    fn toggle_current_mark(&mut self) {
        if let Some(uuid) = self.selected_entry_uuid() {
            if !self.marks.remove(&uuid) {
                self.marks.insert(uuid);
            }
        }
    }

    /// Handle a key while the tree is in visual mode. Returns `true` when the
    /// key was consumed here (range extension, individual mark toggle, or the
    /// Esc de-escalation); `false` lets it fall through to normal dispatch (so
    /// the bulk commands `m`/`t`/`T`/`d` and `v` re-anchor still work).
    fn handle_visual_key(&mut self, key: &KeyEvent) -> bool {
        // Range extension: move the cursor, then re-mark the span.
        if self.keys.matches(Command::Next, key) {
            self.tree_command(Command::Next);
            self.recompute_visual_marks();
            return true;
        }
        if self.keys.matches(Command::Prev, key) {
            self.tree_command(Command::Prev);
            self.recompute_visual_marks();
            return true;
        }
        // Space toggles the current row's mark individually (yazi hover-vs-select).
        if matches!(key.code, KeyCode::Char(' ')) {
            self.toggle_current_mark();
            return true;
        }
        // Esc de-escalates visual → normal, keeping the marks (the ladder's first
        // rung; a second Esc in normal mode clears them — see `on_secrets_key`).
        if matches!(key.code, KeyCode::Esc) {
            self.tree_mode = TreeMode::Normal;
            return true;
        }
        false
    }

    /// Build the flat, indent-labelled destination-group list for the picker,
    /// excluding the Recycle Bin (never a move target).
    fn collect_group_choices(&self) -> Vec<GroupChoice> {
        let mut out = Vec::new();
        if let Some(vault) = self.vault.as_ref() {
            let recycle = vault.database().recycle_bin().map(|g| g.id().uuid());
            Self::walk_group_choices(vault, vault.root_group_uuid(), 0, recycle, &mut out);
        }
        out
    }

    fn walk_group_choices(
        vault: &Vault,
        group: Uuid,
        depth: usize,
        recycle: Option<Uuid>,
        out: &mut Vec<GroupChoice>,
    ) {
        if Some(group) == recycle {
            return;
        }
        let Ok(view) = vault.group_view(group) else {
            return;
        };
        let indent = "  ".repeat(depth);
        out.push(GroupChoice {
            uuid: group,
            label: format!("{indent}{}", view.name()),
        });
        let mut children: Vec<Uuid> = view.child_group_uuids();
        children.sort_by_key(|uuid| {
            vault
                .group_view(*uuid)
                .map_or_else(|_| String::new(), |g| g.name().to_lowercase())
        });
        for child in children {
            Self::walk_group_choices(vault, child, depth + 1, recycle, out);
        }
    }

    /// Open the destination-group picker for the marked entries (T4.5).
    fn open_group_picker(&mut self) {
        if self.read_only {
            return;
        }
        let count = self.marks.len();
        if count == 0 {
            return;
        }
        let groups = self.collect_group_choices();
        self.overlay = Some(Overlay::GroupPicker(GroupPickerState::new(groups, count)));
    }

    /// Open the tag input for the marked entries (T4.5).
    fn open_tag_input(&mut self, action: TagAction) {
        if self.read_only {
            return;
        }
        let count = self.marks.len();
        if count == 0 {
            return;
        }
        self.overlay = Some(Overlay::TagInput(TagInputState::new(action, count)));
    }

    fn on_group_picker_key(&mut self, state: &mut GroupPickerState, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => false,
            KeyCode::Down | KeyCode::Char('j') => {
                state.select_next();
                true
            }
            KeyCode::Up | KeyCode::Char('k') => {
                state.select_prev();
                true
            }
            KeyCode::Enter => {
                if let Some(target) = state.selected_uuid() {
                    self.apply_move_to_group(target);
                }
                false
            }
            _ => true,
        }
    }

    fn on_tag_input_key(&mut self, state: &mut TagInputState, ev: &Event, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => false,
            KeyCode::Enter => {
                let tag = state.input.value().trim().to_string();
                if !tag.is_empty() {
                    self.apply_tag(state.action, &tag);
                }
                false
            }
            _ => {
                feed_input(&mut state.input, ev);
                true
            }
        }
    }

    /// Move every marked entry to `target`, in a single atomic write (OQ-1).
    fn apply_move_to_group(&mut self, target: Uuid) {
        let uuids = self.marked_uuids();
        let result: Result<(), VaultError> = (|| {
            let Some(vault) = self.vault.as_mut() else {
                return Ok(());
            };
            // Validate the entire batch before the first mutation. A remote
            // sync may have invalidated one marked UUID; without this pass an
            // earlier entry could move before a later stale mark failed.
            vault.group_view(target)?;
            for &uuid in &uuids {
                vault.get_entry(uuid)?;
            }
            uuids
                .iter()
                .try_for_each(|&uuid| vault.move_entry(uuid, target))
        })();
        self.finish_bulk_op(result, uuids.len(), "moved");
    }

    /// Add or remove `tag` on every marked entry, in a single atomic write.
    fn apply_tag(&mut self, action: TagAction, tag: &str) {
        let uuids = self.marked_uuids();
        let result: Result<(), VaultError> = (|| {
            // User input must use the fallible constructor; `Tag::new` is for
            // trusted literals and deliberately panics on a semicolon.
            let parsed = falach_core::Tag::from(tag.to_string())?;
            let Some(vault) = self.vault.as_mut() else {
                return Ok(());
            };
            for &uuid in &uuids {
                vault.get_entry(uuid)?;
            }
            // `update_entry` appends one KDBX history snapshot per affected
            // entry, matching the single-entry edit contract.
            uuids.iter().try_for_each(|&uuid| {
                vault.update_entry(uuid, |view| {
                    match action {
                        TagAction::Add => view.add_tag(parsed.clone()),
                        TagAction::Remove => view.remove_tag(&parsed),
                    }
                    Ok(())
                })
            })
        })();
        let verb = match action {
            TagAction::Add => "tagged",
            TagAction::Remove => "untagged",
        };
        self.finish_bulk_op(result, uuids.len(), verb);
    }

    /// Persist a completed bulk mutation once, clear the marks + visual mode, and
    /// post a status note. On failure nothing is cleared and the error is shown.
    fn finish_bulk_op(&mut self, result: Result<(), VaultError>, count: usize, verb: &str) {
        let outcome = result
            .map_err(PersistError::from)
            .and_then(|()| self.persist_vault());
        if let Err(e) = outcome {
            self.status_bar
                .set_error(format!("Bulk {verb} failed: {e}"), Instant::now());
            return;
        }
        self.marks.clear();
        self.tree_mode = TreeMode::Normal;
        self.persist_ui_state();
        self.status_bar.set(
            format!(
                "{verb} {count} entr{}",
                if count == 1 { "y" } else { "ies" }
            ),
            Instant::now(),
        );
    }

    /// Confirm-delete keys for the marked set (`y` deletes all, `n`/Esc cancels).
    fn on_confirm_bulk_delete_key(&mut self, uuids: &[Uuid], key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('y' | 'Y') => {
                self.perform_bulk_delete(uuids);
                false
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => false,
            _ => true,
        }
    }

    /// Delete every marked entry through the same recycle-bin-aware core path as
    /// a single delete, in one atomic write (no-data-loss discipline preserved).
    fn perform_bulk_delete(&mut self, uuids: &[Uuid]) {
        let owned: Vec<Uuid> = uuids.to_vec();
        let result: Result<(), VaultError> = (|| {
            let Some(vault) = self.vault.as_mut() else {
                return Ok(());
            };
            for &uuid in &owned {
                vault.get_entry(uuid)?;
            }
            owned.iter().try_for_each(|&uuid| vault.delete_entry(uuid))
        })();
        let outcome = result
            .map_err(PersistError::from)
            .and_then(|()| self.persist_vault());
        if let Err(e) = outcome {
            self.status_bar
                .set_error(format!("Bulk delete failed: {e}"), Instant::now());
            return;
        }
        for &uuid in &owned {
            self.recents.remove(uuid);
            if self.tabs.is_pinned(uuid) {
                self.tabs.toggle_pin(uuid);
            }
        }
        let count = owned.len();
        self.marks.clear();
        self.tree_mode = TreeMode::Normal;
        // Keep the tree selection valid if it pointed at a deleted entry.
        if self.tree.selected().is_some_and(|s| owned.contains(&s)) {
            let rows = self
                .vault
                .as_ref()
                .map(|v| entry_tree::build_rows(v, &self.tree, &self.recents))
                .unwrap_or_default();
            self.tree.select_first(&rows);
        }
        self.persist_ui_state();
        self.status_bar.set(
            format!(
                "deleted {count} entr{}",
                if count == 1 { "y" } else { "ies" }
            ),
            Instant::now(),
        );
    }

    /// History overlay keys: `↑`/`↓` (or `j`/`k`) browse versions; `Esc` closes.
    /// Stateless w.r.t. `self` — `&mut state` is all it needs.
    fn on_history_key(state: &mut HistoryState, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => false,
            KeyCode::Down | KeyCode::Char('j') => {
                state.select_next();
                true
            }
            KeyCode::Up | KeyCode::Char('k') => {
                state.select_prev();
                true
            }
            _ => true,
        }
    }

    /// Palette-overlay keys (T2.3). `Esc` closes with no side effects;
    /// `↑`/`↓` (and `Ctrl+P`/`Ctrl+N`) move the selection; `Enter` runs the
    /// selected **enabled** command via the shared [`Self::execute_command`]
    /// path (closing the palette first, so a command that opens another overlay
    /// leaves exactly one open); `Enter` on a disabled row posts a note and
    /// keeps the palette open. Everything else edits the filter (resetting the
    /// selection). Returns `true` to keep the palette open. The globals
    /// (`Ctrl+Q`/`Ctrl+L`) are dispatched ahead of the overlay layer, so they
    /// still fire.
    fn on_palette_key(
        &mut self,
        state: &mut overlay::PaletteState,
        ev: &Event,
        key: &KeyEvent,
    ) -> bool {
        let rows = overlay::palette::build_palette_rows(self, state.underlying, state.filter());
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => return false,
            KeyCode::Enter => {
                if let Some(row) = rows.get(state.selected) {
                    if row.state == CmdState::Enabled {
                        let id = row.spec.id;
                        // Close first, then execute (so an overlay-opening command
                        // lands a single overlay).
                        self.execute_command(id, None);
                        return false;
                    }
                    self.status_bar
                        .set_warning("Not available here.", Instant::now());
                }
                return true;
            }
            KeyCode::Up => {
                state.selected = state.selected.saturating_sub(1);
                return true;
            }
            KeyCode::Down => {
                if !rows.is_empty() {
                    state.selected = (state.selected + 1).min(rows.len() - 1);
                }
                return true;
            }
            KeyCode::Char('p') if ctrl => {
                state.selected = state.selected.saturating_sub(1);
                return true;
            }
            KeyCode::Char('n') if ctrl => {
                if !rows.is_empty() {
                    state.selected = (state.selected + 1).min(rows.len() - 1);
                }
                return true;
            }
            _ => {}
        }
        // Anything else edits the filter; a changed query resets the selection to
        // the top (the new best match).
        if let Some(req) = tui_input::backend::crossterm::to_input_request(ev) {
            if state.input.handle(req).is_some() {
                state.selected = 0;
            }
        }
        true
    }

    /// Delete-confirmation keys: `y` deletes; `n`/`Esc` cancels.
    fn on_confirm_delete_key(&mut self, uuid: Uuid, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('y' | 'Y') => {
                self.perform_delete(uuid);
                false
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => false,
            _ => true,
        }
    }

    /// Edit overlay keys. The nested generate panel (when open) captures
    /// everything; otherwise: `Esc` cancels, `Ctrl+S` saves, `Ctrl+G` opens
    /// generate, `Tab`/`Shift+Tab` move focus, `Enter` advances (or, in Notes,
    /// inserts a newline; on the add-custom row, appends a field), and any other
    /// key edits the focused field.
    fn on_edit_key(&mut self, state: &mut EditState, ev: &Event, key: &KeyEvent) -> bool {
        if state.generating.is_some() {
            return Self::on_generate_key(state, key);
        }
        if matches!(key.code, KeyCode::Esc) {
            return false;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('s')) {
            // `perform_save` returns true on success → close the overlay.
            return !self.perform_save(state);
        }
        // Generate only fills the password field, which only credentials carry,
        // so gate it to that kind (avoids a dead panel on notes/TOTP edits).
        if ctrl
            && matches!(key.code, KeyCode::Char('g'))
            && matches!(state.kind, EntryKind::Credential)
        {
            state.generating = Some(GenState::new());
            return true;
        }
        match key.code {
            KeyCode::Tab => {
                state.focus_next();
                return true;
            }
            KeyCode::BackTab => {
                state.focus_prev();
                return true;
            }
            KeyCode::Enter => match state.focused() {
                EditField::Notes => {} // fall through: newline into the editor
                EditField::CustomAdd => {
                    state.add_custom_row();
                    return true;
                }
                _ => {
                    state.focus_next();
                    return true;
                }
            },
            _ => {}
        }
        // Field-specific editing.
        match state.focused() {
            EditField::Kind => match key.code {
                KeyCode::Left | KeyCode::Char('h') => state.cycle_kind_back(),
                KeyCode::Right | KeyCode::Char('l' | ' ') => state.cycle_kind(),
                _ => {}
            },
            EditField::Title => feed_input(&mut state.title, ev),
            EditField::Username => feed_input(&mut state.username, ev),
            EditField::Url => feed_input(&mut state.url, ev),
            EditField::TotpUri => {
                // `PasswordInput` (Zeroizing-backed); its `InputAction` is
                // ignored because Enter/Esc/Tab are consumed upstream.
                state.totp_uri.on_key(key);
            }
            EditField::Tags => feed_input(&mut state.tags, ev),
            EditField::Password => {
                if ctrl && matches!(key.code, KeyCode::Char('r')) {
                    state.reveal_password = !state.reveal_password;
                } else {
                    state.password.on_key(key);
                }
            }
            EditField::Notes => {
                state.notes.on_key(key);
            }
            EditField::Custom(i, col) => {
                if ctrl && matches!(key.code, KeyCode::Char('d')) {
                    state.remove_custom_row(i);
                } else if let Some(row) = state.custom.get_mut(i) {
                    match col {
                        Col::Name => feed_input(&mut row.name, ev),
                        // `PasswordInput` (Zeroizing-backed); `InputAction`
                        // ignored — Enter/Esc/Tab are consumed upstream.
                        Col::Value => {
                            row.value.on_key(key);
                        }
                    }
                }
            }
            EditField::CustomAdd => {}
        }
        true
    }

    /// Generate-panel keys (nested in Edit). `Enter` fills the password field
    /// and closes the panel; `Esc` backs out; the rest tune the generator.
    fn on_generate_key(state: &mut EditState, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                state.generating = None;
                return true;
            }
            KeyCode::Enter => {
                if let Some(gen) = state.generating.take() {
                    state.password.set_value(&gen.preview);
                    state.reveal_password = false;
                }
                return true;
            }
            _ => {}
        }
        let Some(gen) = state.generating.as_mut() else {
            return true;
        };
        match key.code {
            KeyCode::Tab => gen.toggle_kind(),
            KeyCode::Char('+' | '=') => gen.grow(),
            KeyCode::Char('-' | '_') => gen.shrink(),
            KeyCode::Char('r') => gen.regenerate(),
            KeyCode::Char('l') => gen.toggle_class(Class::Lower),
            KeyCode::Char('u') => gen.toggle_class(Class::Upper),
            KeyCode::Char('d') => gen.toggle_class(Class::Digits),
            KeyCode::Char('s') => gen.toggle_class(Class::Symbols),
            KeyCode::Char('b') => gen.toggle_ambiguous(),
            _ => {}
        }
        true
    }

    /// Commit the edit form: add or update + save to disk. Returns `true` on
    /// success (the caller closes the overlay); on failure sets the form's
    /// error line and returns `false` (the overlay stays open). The local save
    /// is durable before any UI-state mirroring.
    fn perform_save(&mut self, state: &mut EditState) -> bool {
        let values = match state.snapshot() {
            Ok(values) => values,
            Err(message) => {
                state.error = Some(message);
                return false;
            }
        };
        // Apply the edit to the in-memory vault first (borrows only the vault),
        // then persist through the choke point (borrows all of `self`).
        let mutated: Result<Uuid, VaultError> = {
            let Some(vault) = self.vault.as_mut() else {
                return false;
            };
            match state.target {
                Some(uuid) => Self::apply_update(vault, uuid, &values).map(|()| uuid),
                None => Self::apply_add(vault, state.group, &values),
            }
        };
        let outcome: Result<Uuid, PersistError> = match mutated {
            Ok(uuid) => {
                // The in-memory vault now holds the entry. Record it as the
                // form's target BEFORE attempting the save: if the save fails
                // (disk full, lock contention), the overlay stays open and a
                // retried Ctrl+S must update this entry — re-running the add
                // would create a duplicate under a fresh UUID.
                if state.target.is_none() {
                    state.target = Some(uuid);
                }
                self.persist_vault().map(|()| uuid)
            }
            Err(e) => Err(PersistError::from(e)),
        };
        match outcome {
            Ok(uuid) => {
                if state.is_new {
                    self.tree.expand(state.group);
                }
                self.tree.select(uuid);
                self.recents.bump(uuid);
                self.persist_ui_state();
                let verb = if state.is_new { "added" } else { "updated" };
                self.status_bar
                    .set(format!("Entry {verb}."), Instant::now());
                true
            }
            Err(e) => {
                state.error = Some(e.to_string());
                false
            }
        }
    }

    /// Build an [`EntryBuilder`] from the snapshot and add it (associated fn so
    /// it borrows only the `Vault`, not all of `self`).
    fn apply_add(vault: &mut Vault, group: Uuid, v: &EditValues) -> Result<Uuid, VaultError> {
        let mut builder = match v.kind {
            EntryKind::Credential => EntryBuilder::credential(v.title.clone()),
            EntryKind::SecureNote => EntryBuilder::secure_note(v.title.clone()),
            EntryKind::Totp => EntryBuilder::totp(v.title.clone(), &v.totp_uri)?,
        };
        if matches!(v.kind, EntryKind::Credential | EntryKind::Totp) {
            builder = builder.username(v.username.clone()).url(v.url.clone());
        }
        if matches!(v.kind, EntryKind::Credential) {
            builder = builder.password(v.password.as_str());
        }
        builder = builder.notes(v.notes.clone()).tags(v.tags.clone());
        for (name, value, protected) in &v.custom {
            builder = builder.custom_field(name.clone(), value.as_str().to_string(), *protected);
        }
        vault.add_entry(group, builder.build())
    }

    /// Apply the snapshot to an existing entry via `update_entry` (one history
    /// snapshot). OTP-bearing fields are preserved (never in `v.custom`).
    fn apply_update(vault: &mut Vault, uuid: Uuid, v: &EditValues) -> Result<(), VaultError> {
        vault.update_entry(uuid, |view| {
            view.set_title(v.title.clone());
            match v.kind {
                EntryKind::Credential => {
                    view.set_username(v.username.clone());
                    view.set_password(v.password.as_str());
                    view.set_url(v.url.clone());
                }
                EntryKind::Totp => {
                    view.set_username(v.username.clone());
                    view.set_url(v.url.clone());
                }
                EntryKind::SecureNote => {}
            }
            view.set_notes(v.notes.clone());
            view.set_tags(v.tags.clone());
            for (name, value, protected) in &v.custom {
                view.set_custom_field(name.clone(), value.as_str().to_string(), *protected);
            }
            for name in &v.removed_custom {
                view.remove_custom_field(name);
            }
            Ok(())
        })
    }

    /// Delete the entry, save, then clean up UI state: drop it from recents,
    /// unpin any tab, and fix the tree selection (ADR-T5 delete-removes).
    fn perform_delete(&mut self, uuid: Uuid) {
        // Remove from the in-memory vault first (borrows only the vault), then
        // persist through the choke point (borrows all of `self`).
        let deleted: Result<(), VaultError> = {
            let Some(vault) = self.vault.as_mut() else {
                return;
            };
            vault.delete_entry(uuid)
        };
        let outcome = deleted
            .map_err(PersistError::from)
            .and_then(|()| self.persist_vault());
        if let Err(e) = outcome {
            self.status_bar
                .set_error(format!("Delete failed: {e}"), Instant::now());
            return;
        }
        self.recents.remove(uuid);
        if self.tabs.is_pinned(uuid) {
            self.tabs.toggle_pin(uuid);
        }
        if self.tree.selected() == Some(uuid) {
            let rows = self
                .vault
                .as_ref()
                .map(|v| entry_tree::build_rows(v, &self.tree, &self.recents))
                .unwrap_or_default();
            self.tree.select_first(&rows);
        }
        self.persist_ui_state();
        self.status_bar.set("Entry deleted.", Instant::now());
    }

    /// Hydrate the unlocked workspace from `tui.toml` (T4.4 / ADR-T5): pinned
    /// tabs and the recents list for the just-opened vault. Stale pins (whose
    /// entry was deleted since the last session) are dropped so a pinned tab
    /// never points at a missing entry. Called on each unlock.
    fn hydrate_workspace(&mut self) {
        let (pinned, recents) = match self
            .selected_vault
            .as_deref()
            .and_then(|name| self.ui_config.vault_state(name))
        {
            Some(state) => (
                state.pinned.clone(),
                Recents::from_persisted(&state.recents),
            ),
            None => (Vec::new(), Recents::new()),
        };
        let pinned: Vec<Uuid> = match self.vault.as_ref() {
            Some(vault) => pinned
                .into_iter()
                .filter(|uuid| vault.get_entry(*uuid).is_ok())
                .collect(),
            None => Vec::new(),
        };
        self.tabs = TabBar::with_pins(pinned);
        self.recents = recents;
    }

    /// Reset the Secrets-tab view to a fresh state and select the first visible
    /// node. Called on each unlock so a re-unlock starts clean. The tree sort
    /// defaults to the persisted global preference (T4.3).
    fn reset_secrets_view(&mut self) {
        self.tree = TreeState::with_sort(self.user_config.default_sort());
        self.focus = Focus::Tree;
        self.reveal_password = false;
        self.detail_scroll = 0;
        // Surface one-shot startup notices (config/keymap load warnings) now
        // that the status bar exists (U.5 / R-14). Multiple notices are joined
        // onto the single status line.
        if !self.startup_notices.is_empty() {
            let joined = self.startup_notices.join("; ");
            self.startup_notices.clear();
            self.status_bar.set_warning(joined, Instant::now());
        }
        let rows = match self.vault.as_ref() {
            Some(vault) => entry_tree::build_rows(vault, &self.tree, &self.recents),
            None => return,
        };
        self.tree.select_first(&rows);
    }

    fn on_unlock_list_key(&mut self, key: &KeyEvent) {
        if let Some(cmd) = self.nav_command_for(key) {
            self.execute_command(cmd, None);
        }
    }

    /// Unlock-list navigation / selection — the shared target for keys and the
    /// palette. `Next`/`Prev` move the highlight; `Confirm` opens the prompt for
    /// the highlighted vault.
    fn unlock_list_nav(&mut self, cmd: Command) {
        let count = self.registry().list().count();
        if count == 0 {
            return;
        }
        match cmd {
            Command::Next => self.list_index = (self.list_index + 1).min(count - 1),
            Command::Prev => self.list_index = self.list_index.saturating_sub(1),
            Command::Confirm => {
                // Resolve the name to an owned value first so the registry borrow
                // ends before we mutate `self`.
                let name = self
                    .registry()
                    .list()
                    .nth(self.list_index)
                    .map(|v| v.name.clone());
                if let Some(name) = name {
                    self.open_unlock_prompt_for(name);
                }
            }
            _ => {}
        }
    }

    /// Transition to the unlock prompt for `name` (a registered vault). Shared
    /// by the list's `Confirm` action and the `--vault NAME` fast path (T3.2).
    /// The caller must have validated that `name` is registered.
    fn open_unlock_prompt_for(&mut self, name: String) {
        self.selected_vault = Some(name.clone());
        self.status = None;
        self.phase = Phase::UnlockPrompt {
            vault_name: name,
            input: PasswordInput::new(),
            attempts: 0,
        };
    }

    fn on_unlock_prompt_key(&mut self, key: &KeyEvent) {
        let Phase::UnlockPrompt { input, .. } = &mut self.phase else {
            return;
        };
        match input.on_key(key) {
            InputAction::Continue => {}
            // Replacing the phase drops the `PasswordInput` → zeroize fires.
            InputAction::Cancel => self.phase = Phase::UnlockList,
            InputAction::Submit => self.try_unlock(),
        }
    }

    /// Take the typed password out of the prompt and attempt to open the vault.
    fn try_unlock(&mut self) {
        // Move the prompt's fields out; `self.phase` is left as UnlockList and
        // overwritten below on every path.
        let (vault_name, input, attempts) =
            match std::mem::replace(&mut self.phase, Phase::UnlockList) {
                Phase::UnlockPrompt {
                    vault_name,
                    input,
                    attempts,
                } => (vault_name, input, attempts),
                other => {
                    self.phase = other;
                    return;
                }
            };

        let Some(registered) = self
            .registry
            .as_ref()
            .and_then(|r| r.get(&vault_name))
            .cloned()
        else {
            // Vault vanished from the registry; bounce to the list.
            self.phase = Phase::UnlockList;
            return;
        };

        // The typed buffer (`Zeroizing`) lives until this scope ends; it is used
        // to build the open password and, if auto-sync-on-unlock is enabled, a
        // second `MasterPassword` handed to the worker (dropped when it finishes).
        // TODO(DI-2): pass `registered.keyfile_path` as a `Keyfile` once the
        // keyfile-unlock follow-up lands (impl-plan §5.4 #7). MVP passes None.
        let typed = input.take();
        let password = MasterPassword::new(typed.to_string());
        match Vault::open(&registered.path, &password, None) {
            Ok(vault) => {
                self.vault = Some(vault);
                self.selected_vault = Some(vault_name);
                // Arm the idle-lock controller from THIS vault's configured
                // timeout (T3.5) — so an edited auto-lock survives restart —
                // rather than reusing the placeholder default.
                self.arm_auto_lock_for_current_vault(Instant::now());
                self.hydrate_workspace();
                self.reset_tab_motion();
                self.reset_secrets_view();
                self.phase = Phase::Workspace;
                // Auto-sync on unlock (D-5/ADR-T4): hand the just-collected password
                // to the worker; it drops when the sync finishes. Only when the
                // toggle is on AND a target is configured (TR-9).
                if self.user_config.sync_on_unlock() && self.sync_configured() {
                    let mp = MasterPassword::new(typed.to_string());
                    self.start_sync(SyncTrigger::OnUnlock, mp);
                }
            }
            // Only a genuine authentication failure consumes an attempt and
            // re-prompts — telling the user their password was wrong.
            Err(VaultError::AuthenticationFailed) => {
                let attempts = attempts.saturating_add(1);
                if attempts >= MAX_UNLOCK_ATTEMPTS {
                    self.status = Some(format!(
                        "{MAX_UNLOCK_ATTEMPTS} incorrect attempts; vault remains locked."
                    ));
                    self.phase = Phase::UnlockList;
                } else {
                    self.phase = Phase::UnlockPrompt {
                        vault_name,
                        input: PasswordInput::new(),
                        attempts,
                    };
                }
            }
            // Everything else — lock contention with another process, a
            // missing/corrupt vault file, I/O errors — is NOT a wrong
            // password. Surface the real cause on the vault list instead
            // of miscounting it as an incorrect attempt.
            Err(other) => {
                self.status = Some(format!("Could not open vault: {other}"));
                self.phase = Phase::UnlockList;
            }
        }
    }

    fn on_lock_screen_key(&mut self) {
        // Any key returns to the list with the previously-open vault highlighted.
        if let Some(name) = self.selected_vault.clone() {
            let idx = self.registry().list().position(|v| v.name == name);
            if let Some(idx) = idx {
                self.list_index = idx;
            }
        }
        self.phase = Phase::UnlockList;
    }

    // ---- Phase 6: sync triggers + Settings ----

    /// Whether the selected vault has a sync target configured in `vaults.toml`.
    fn sync_configured(&self) -> bool {
        self.selected_sync_config().is_some()
    }

    /// The selected vault's [`SyncConfig`], if any.
    fn selected_sync_config(&self) -> Option<SyncConfig> {
        let name = self.selected_vault.as_deref()?;
        let entry = self.registry.as_ref()?.get(name)?;
        SyncConfig::from_vault_entry(entry)
    }

    /// A secret-free one-line summary of the configured target (Settings status
    /// sub-view). `None` when no S3 target is configured.
    pub(crate) fn sync_target_summary(&self) -> Option<String> {
        let s3 = self.selected_sync_config()?.s3?;
        let endpoint = s3.endpoint().unwrap_or("AWS default");
        Some(format!(
            "{} / {} (region {}, {})",
            s3.bucket(),
            s3.key(),
            s3.region(),
            endpoint
        ))
    }

    /// The last sync outcome/error summary (secret-free), for the Settings tab.
    pub(crate) fn sync_status_line(&self) -> Option<&str> {
        self.sync_status.as_deref()
    }

    /// Whether leaving the vault (lock/quit) should first flush a sync: the
    /// toggle is on, a target is configured, and a vault is currently open.
    fn should_sync_on_leave(&self) -> bool {
        // A read-only session never syncs on lock/quit (T4.7), so it also never
        // prompts for the master password to do so.
        !self.read_only
            && self.user_config.sync_on_lock_quit()
            && self.vault.is_some()
            && self.sync_configured()
    }

    /// Manual sync (`s`). Re-prompts the master password (the App holds none),
    /// unless already syncing or no target is configured.
    fn request_sync(&mut self) {
        if self.sync.is_syncing() {
            self.status_bar
                .set_info("Sync already in progress.", Instant::now());
            return;
        }
        if !self.sync_configured() {
            self.status_bar.set_warning(
                "No sync target configured (Settings → configure).",
                Instant::now(),
            );
            return;
        }
        self.overlay = Some(Overlay::SyncUnlock {
            input: PasswordInput::new(),
            pending: SyncTrigger::Manual,
        });
    }

    /// `Ctrl+L`. Defers if a sync is in flight; otherwise either flushes first
    /// (sync-on-lock) or locks immediately.
    fn request_lock(&mut self) {
        if self.sync.is_syncing() {
            self.lock_pending = true;
            self.status_bar
                .set_info("Will lock when the sync finishes.", Instant::now());
            return;
        }
        if self.should_sync_on_leave() {
            self.overlay = Some(Overlay::SyncUnlock {
                input: PasswordInput::new(),
                pending: SyncTrigger::OnLock,
            });
            return;
        }
        self.lock_app();
    }

    /// `Ctrl+Q`. While unlocked with sync-on-lock/quit enabled + configured (and
    /// not already syncing), flush first; otherwise quit immediately.
    fn request_quit(&mut self) {
        // Quit confirmation gate (T4.8). When enabled, the first quit opens the
        // confirmation; a second quit while it is open is ignored (never
        // enqueues a duplicate quit/sync). Default off → immediate quit.
        if self.user_config.confirm_quit() {
            if matches!(self.overlay, Some(Overlay::ConfirmQuit)) {
                return;
            }
            self.overlay = Some(Overlay::ConfirmQuit);
            return;
        }
        self.do_quit();
    }

    /// Execute the quit: flush a sync-on-quit first (re-prompting for the master
    /// password) if configured, else set `should_quit`. Shared by the immediate
    /// path and the confirmed path (T4.8) so both preserve `sync-on-lock-quit`.
    fn do_quit(&mut self) {
        if matches!(self.phase, Phase::Workspace)
            && !self.sync.is_syncing()
            && self.should_sync_on_leave()
        {
            self.overlay = Some(Overlay::SyncUnlock {
                input: PasswordInput::new(),
                pending: SyncTrigger::OnQuit,
            });
            return;
        }
        self.should_quit = true;
    }

    /// Quit-confirmation keys (T4.8): `y` proceeds through the quit/sync path
    /// exactly once; `n`/Esc closes with no side effect.
    fn on_confirm_quit_key(&mut self, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('y' | 'Y') => {
                // The confirmation overlay was already `take`n by `on_overlay_key`.
                // `do_quit` either sets `should_quit` (overlay stays cleared) or
                // installs the sync re-prompt overlay; returning `false` keeps
                // whatever it set instead of restoring the confirmation.
                self.do_quit();
                false
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => false,
            _ => true,
        }
    }

    /// Move the vault + registry to the worker and start a background sync.
    fn start_sync(&mut self, trigger: SyncTrigger, master_password: MasterPassword) {
        // Read-only guard at the sync choke point (T4.7): all four triggers
        // (manual, on-unlock, on-lock, on-quit) funnel through here, and sync
        // writes the local vault + pushes to the remote via `engine.sync_now`
        // — bypassing the `persist_vault` guard entirely. A read-only session
        // must never sync. (`master_password` drops here, zeroizing.)
        if self.read_only {
            self.status_bar
                .set_warning("Read-only session — sync disabled.", Instant::now());
            return;
        }
        let Some(name) = self.selected_vault.clone() else {
            return;
        };
        let Some(vault) = self.vault.take() else {
            return;
        };
        let Some(registry) = self.registry.take() else {
            // Should not happen (registry is only None mid-sync, which this
            // gates against); restore the vault and bail.
            self.vault = Some(vault);
            return;
        };
        self.sync
            .start(vault, registry, name, master_password, trigger);
        self.sync_status = Some("Syncing…".to_string());
        self.status_bar.set_info("Syncing…", Instant::now());
    }

    /// `Overlay::SyncUnlock` keys. On submit, take the typed password (read via
    /// `as_str` — the overlay is dropped right after, zeroizing the buffer) and
    /// start the pending sync. On cancel, complete the deferred lock/quit anyway
    /// (the local save is already durable).
    fn on_sync_unlock_key(
        &mut self,
        input: &mut PasswordInput,
        pending: SyncTrigger,
        key: &KeyEvent,
    ) -> bool {
        match input.on_key(key) {
            InputAction::Continue => true,
            InputAction::Cancel => {
                self.cancel_pending_sync(pending);
                false
            }
            InputAction::Submit => {
                let mp = MasterPassword::new(input.as_str().to_string());
                self.start_sync(pending, mp);
                false
            }
        }
    }

    /// A cancelled `SyncUnlock` still completes an on-lock/quit departure.
    fn cancel_pending_sync(&mut self, pending: SyncTrigger) {
        match pending {
            SyncTrigger::OnLock => self.lock_app(),
            SyncTrigger::OnQuit => self.should_quit = true,
            SyncTrigger::Manual | SyncTrigger::OnUnlock => {}
        }
    }

    /// Settings-tab key handling (T6.3): `j`/`k` move the row, `Enter` toggles
    /// or cycles the focused setting (or launches the credential overlay).
    fn on_settings_key(&mut self, key: &KeyEvent) {
        if let Some(cmd) = self.nav_command_for(key) {
            self.execute_command(cmd, None);
        }
    }

    /// Settings-tab navigation / activation — the shared target for keys and the
    /// palette. `Next`/`Prev` move the focused row; `Confirm` activates it.
    fn settings_command(&mut self, cmd: Command) {
        match cmd {
            Command::Next => {
                self.settings_index = (self.settings_index + 1).min(SETTINGS_ROW_COUNT - 1);
            }
            Command::Prev => self.settings_index = self.settings_index.saturating_sub(1),
            Command::Confirm => self.activate_settings_row(),
            _ => {}
        }
    }

    /// Apply the focused Settings row (T6.3). Rows must match
    /// [`settings::ROW_LABELS`].
    fn activate_settings_row(&mut self) {
        match self.settings_index {
            0 => {
                let mut next = self.user_config.default_sort();
                if self.update_user_config(|cfg| next = cfg.cycle_default_sort()) {
                    self.status_bar
                        .set(format!("Default sort: {}", next.label()), Instant::now());
                }
            }
            1 => self.cycle_theme(),
            // Auto-lock writes the vault registry (vaults.toml), so it is a
            // vault-affecting edit — refused in a read-only session (T4.7). Theme
            // and the sync-on-* toggles are config.toml prefs and stay allowed.
            2 if self.read_only => {
                self.status_bar
                    .set_warning("Read-only session — auto-lock unchanged.", Instant::now());
            }
            2 => self.cycle_auto_lock(),
            3 => {
                let on = !self.user_config.sync_on_unlock();
                if self.update_user_config(|cfg| cfg.set_sync_on_unlock(on)) {
                    self.status_bar.set(
                        format!("Auto-sync on unlock: {}", if on { "on" } else { "off" }),
                        Instant::now(),
                    );
                }
            }
            4 => {
                let on = !self.user_config.sync_on_lock_quit();
                if self.update_user_config(|cfg| cfg.set_sync_on_lock_quit(on)) {
                    self.status_bar.set(
                        format!("Auto-sync on lock/quit: {}", if on { "on" } else { "off" }),
                        Instant::now(),
                    );
                }
            }
            5 if self.read_only => {
                self.status_bar
                    .set_warning("Read-only session — sync is disabled.", Instant::now());
            }
            5 => self.open_sync_config(),
            _ => {}
        }
    }

    /// Open the secure S3-credential overlay (T6.4). Reachable only while
    /// unlocked (the credential is encrypted with the master password, and only
    /// an unlocked session is in a position to re-collect it).
    fn open_sync_config(&mut self) {
        if self.vault.is_none() {
            self.status_bar
                .set_warning("Unlock a vault to configure sync.", Instant::now());
            return;
        }
        self.overlay = Some(Overlay::SyncConfig(Box::new(SyncConfigState::new())));
    }

    /// `Overlay::SyncConfig` keys: `Esc` cancels, `Ctrl+S` saves, `Tab`/
    /// `Shift+Tab` move focus, `Space` toggles path-style, everything else edits
    /// the focused field.
    fn on_sync_config_key(
        &mut self,
        state: &mut SyncConfigState,
        ev: &Event,
        key: &KeyEvent,
    ) -> bool {
        if matches!(key.code, KeyCode::Esc) {
            return false; // drop → both `PasswordInput`s zeroize
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('s')) {
            // `perform_configure_sync` returns true on success → close.
            return !self.perform_configure_sync(state);
        }
        match key.code {
            KeyCode::Tab => {
                state.focus_next();
                return true;
            }
            KeyCode::BackTab => {
                state.focus_prev();
                return true;
            }
            _ => {}
        }
        match state.focused() {
            SyncField::Endpoint => feed_input(&mut state.endpoint, ev),
            SyncField::Region => feed_input(&mut state.region, ev),
            SyncField::Bucket => feed_input(&mut state.bucket, ev),
            SyncField::Key => feed_input(&mut state.key, ev),
            SyncField::PathStyle => {
                if matches!(key.code, KeyCode::Char(' ')) {
                    state.path_style = !state.path_style;
                }
            }
            SyncField::AccessKeyId => feed_input(&mut state.access_key_id, ev),
            SyncField::Secret => {
                let _ = state.secret.on_key(key);
            }
            SyncField::Master => {
                let _ = state.master.on_key(key);
            }
        }
        true
    }

    /// Persist the S3 credential via the **two-call flow** (ADR-T2): encrypt the
    /// secret access key in TUI memory (`encrypt_credential`, keyed off the
    /// master password), then write only the ciphertext container to
    /// `vaults.toml` (`configure_remote`). Returns `true` on success (close the
    /// overlay → secrets zeroize); on failure sets `state.error` and returns
    /// `false` (overlay stays open).
    fn perform_configure_sync(&mut self, state: &mut SyncConfigState) -> bool {
        let bucket = state.bucket.value().trim().to_string();
        let key = state.key.value().trim().to_string();
        let region = state.region.value().trim().to_string();
        let access_key_id = state.access_key_id.value().trim().to_string();
        if bucket.is_empty() || key.is_empty() || region.is_empty() || access_key_id.is_empty() {
            state.error =
                Some("Bucket, object key, region, and access key ID are required.".to_string());
            return false;
        }
        if state.secret.len_chars() == 0 {
            state.error = Some("Enter the S3 secret access key.".to_string());
            return false;
        }
        if state.master.len_chars() == 0 {
            state.error = Some("Enter the master password to encrypt the credential.".to_string());
            return false;
        }
        let Some(name) = self.selected_vault.clone() else {
            state.error = Some("No vault selected.".to_string());
            return false;
        };

        // The master password is rebuilt here (the App holds none) and dropped
        // at scope end. `encrypt_credential` runs Argon2id + ChaCha20-Poly1305
        // in memory; only the resulting ciphertext container reaches disk.
        let mp = MasterPassword::new(state.master.as_str().to_string());
        let container = match falach_sync::encrypt_credential(state.secret.as_str(), &mp) {
            Ok(c) => c,
            Err(e) => {
                state.error = Some(format!("Could not encrypt credential: {e}"));
                return false;
            }
        };
        let credentials = falach_sync::CredentialSource::RstCred1 {
            access_key_id,
            secret_access_key_encrypted: container,
        };
        let mut s3 = S3Config::new(bucket, key, region, credentials);
        let endpoint = state.endpoint.value().trim().to_string();
        if !endpoint.is_empty() {
            s3.set_endpoint(Some(endpoint));
        }
        if state.path_style {
            s3.set_path_style(true);
        }

        let Some(registry) = self.registry.as_mut() else {
            state.error = Some("Registry unavailable during sync.".to_string());
            return false;
        };
        // `configure_remote` does NOT encrypt (its `master_password` arg is
        // unused/forward-compat) — it does the duplicate-target check and writes
        // the already-encrypted config to `vaults.toml`.
        match Sync::configure_remote(registry, &name, s3, &mp) {
            Ok(()) => {
                self.status_bar
                    .set("Sync target configured.", Instant::now());
                self.sync_status = Some("Sync target configured.".to_string());
                true
            }
            Err(e) => {
                state.error = Some(format!("Could not configure sync: {e}"));
                false
            }
        }
    }

    /// Render the current phase. The palette overlay (T2.4) can be open in any
    /// phase, so every screen draws the overlay on top; pre-unlock phases only
    /// ever carry the palette (the action overlays open in the workspace).
    pub(crate) fn render(&self, frame: &mut Frame, now: Instant) {
        self.mouse_regions.borrow_mut().clear();
        match &self.phase {
            Phase::UnlockList => screens::unlock_list::render(self, frame),
            Phase::UnlockPrompt { .. } => screens::unlock_prompt::render(self, frame),
            Phase::LockScreen => screens::lock_screen::render(self, frame),
            Phase::Workspace => screens::workspace::render(self, frame, now),
        }
        overlay::render(self, frame);
    }
}

#[cfg(test)]
mod tests {
    //! Unlock/lock state-machine tests (the redesign-aligned T-IT-1/2/3). They
    //! drive `handle_event`/`tick` against a real fast-KDF KDBX fixture and
    //! assert `Phase`/`vault` state. They live in-crate because `App` and its
    //! fields are `pub(crate)` (an integration test could not reach them) — the
    //! same white-box rationale as Phase 1's T-IT-9.

    use std::time::Duration;

    use crossterm::event::{
        Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };
    use falach_core::{
        EntryBuilder, FalachPaths, KdfParams, MasterPassword, NoRecoveryConfirmed, RegisteredVault,
        Vault, VaultRegistry,
    };
    use tempfile::TempDir;

    use super::*;

    const PASSWORD: &str = "test123";

    fn fast_kdf() -> KdfParams {
        KdfParams {
            memory_kib: 1_024,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Build a registry with `names.len()` fast-KDF vaults (all opened by
    /// [`PASSWORD`]) and an `App` over it. The `TempDir` must outlive the App.
    fn fixture_app(names: &[&str], idle: Duration) -> (TempDir, App) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = FalachPaths::with_state_dir(dir.path().join("state"));
        let mut registry = VaultRegistry::with_paths(paths.clone());
        for name in names {
            let path = dir.path().join(format!("{name}.kdbx"));
            drop(
                Vault::create(
                    &path,
                    &MasterPassword::new(PASSWORD.to_string()),
                    None,
                    fast_kdf(),
                    NoRecoveryConfirmed::yes(),
                )
                .expect("create fixture vault"),
            );
            registry
                .register(RegisteredVault {
                    name: (*name).to_string(),
                    path,
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    keyfile_path: None,
                    extra: toml::Table::new(),
                })
                .expect("register");
        }
        registry.save().expect("save fixture registry");
        let app = App::from_registry(registry, paths, AutoLockConfig { idle_timeout: idle })
            .expect("from_registry");
        (dir, app)
    }

    fn single_vault_app() -> (TempDir, App) {
        fixture_app(&["personal"], Duration::from_secs(300))
    }

    fn key(c: char) -> Event {
        Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }
    fn key_code(code: KeyCode) -> Event {
        Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }
    fn key_ctrl(c: char) -> Event {
        Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
    }
    fn key_alt(c: char) -> Event {
        Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT))
    }

    /// Select the first vault and type `password` without submitting.
    fn select_and_type(app: &mut App, password: &str) {
        app.handle_event(&key_code(KeyCode::Enter)); // UnlockList → UnlockPrompt
        assert!(matches!(app.phase, Phase::UnlockPrompt { .. }));
        for c in password.chars() {
            app.handle_event(&key(c));
        }
    }

    fn unlock(app: &mut App, password: &str) {
        select_and_type(app, password);
        app.handle_event(&key_code(KeyCode::Enter)); // submit
    }

    #[test]
    fn from_registry_rejects_empty_registry() {
        let dir = tempfile::tempdir().unwrap();
        let paths = FalachPaths::with_state_dir(dir.path().join("state"));
        let registry = VaultRegistry::with_paths(paths.clone());
        let result = App::from_registry(registry, paths, AutoLockConfig::default());
        assert!(
            matches!(result, Err(TuiError::NoVaultsRegistered)),
            "empty registry must yield NoVaultsRegistered"
        );
    }

    // T-IT-1: correct password opens the vault and enters the workspace.
    #[test]
    fn correct_password_unlocks_into_workspace() {
        let (_dir, mut app) = single_vault_app();
        unlock(&mut app, PASSWORD);
        assert!(matches!(app.phase, Phase::Workspace));
        assert!(app.vault.is_some());
        assert_eq!(app.selected_vault.as_deref(), Some("personal"));
    }

    // T-IT-1: wrong password keeps the prompt and counts the attempt.
    #[test]
    fn wrong_password_increments_attempts_and_stays_locked() {
        let (_dir, mut app) = single_vault_app();
        unlock(&mut app, "wrong-password");
        match &app.phase {
            Phase::UnlockPrompt { attempts, .. } => assert_eq!(*attempts, 1),
            other => panic!("expected UnlockPrompt, got {:?}", PhaseName(other)),
        }
        assert!(app.vault.is_none());
    }

    // Regression: a non-auth `Vault::open` failure (missing file, lock
    // contention, corruption) must NOT be presented as a wrong password or
    // consume an unlock attempt — the real error surfaces on the list.
    #[test]
    fn non_auth_open_error_surfaces_cause_without_counting_attempt() {
        let (dir, mut app) = single_vault_app();
        // Make the open fail for a non-auth reason: the vault file vanishes.
        std::fs::remove_file(dir.path().join("personal.kdbx")).expect("remove vault file");

        unlock(&mut app, PASSWORD);

        assert!(
            matches!(app.phase, Phase::UnlockList),
            "non-auth failure bounces to the list, not the attempts loop"
        );
        let status = app.status.as_deref().unwrap_or_default();
        assert!(
            status.starts_with("Could not open vault:"),
            "status carries the real cause, got {status:?}"
        );
        assert!(
            !status.contains("incorrect"),
            "must not claim the password was wrong: {status:?}"
        );
        assert!(app.vault.is_none());
    }

    // T-IT-1: three wrong attempts bounce back to the list with a status note.
    #[test]
    fn three_wrong_attempts_return_to_list_with_status() {
        let (_dir, mut app) = single_vault_app();
        // First attempt from UnlockList.
        unlock(&mut app, "nope");
        // Attempts 2 and 3 from the re-shown prompt.
        for _ in 0..2 {
            for c in "nope".chars() {
                app.handle_event(&key(c));
            }
            app.handle_event(&key_code(KeyCode::Enter));
        }
        assert!(matches!(app.phase, Phase::UnlockList));
        assert!(app.vault.is_none());
        assert!(app
            .status
            .as_deref()
            .unwrap_or("")
            .contains("incorrect attempts"));
    }

    #[test]
    fn esc_from_prompt_returns_to_list() {
        let (_dir, mut app) = single_vault_app();
        select_and_type(&mut app, "partial");
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(matches!(app.phase, Phase::UnlockList));
        assert!(app.vault.is_none());
    }

    // T-IT-3: manual lock (Ctrl+L) drops the vault and shows the lock screen.
    #[test]
    fn manual_lock_drops_vault() {
        let (_dir, mut app) = single_vault_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_ctrl('l'));
        assert!(matches!(app.phase, Phase::LockScreen));
        assert!(app.vault.is_none());
    }

    // T-IT-3: lock-now is a no-op while still locked (no vault to drop).
    #[test]
    fn lock_now_is_noop_when_locked() {
        let (_dir, mut app) = single_vault_app();
        app.handle_event(&key_ctrl('l'));
        assert!(
            matches!(app.phase, Phase::UnlockList),
            "Ctrl+L on the list does nothing"
        );
    }

    #[test]
    fn lock_screen_any_key_returns_to_list_highlighting_prior_vault() {
        let (_dir, mut app) = fixture_app(&["alpha", "beta"], Duration::from_secs(300));
        // Highlight + unlock the second vault.
        app.handle_event(&key('j')); // list_index → 1 (beta)
        unlock(&mut app, PASSWORD);
        assert_eq!(app.selected_vault.as_deref(), Some("beta"));
        app.handle_event(&key_ctrl('l')); // lock
        app.handle_event(&key(' ')); // any key on the lock screen
        assert!(matches!(app.phase, Phase::UnlockList));
        assert_eq!(app.list_index, 1, "prior vault (beta) re-highlighted");
    }

    // ---- Journey tests: multi-vault lock/unlock chains ----

    /// Journey: unlock vault A → lock → unlock vault B → verify vault UUID
    /// changed and the new vault is active.
    #[test]
    fn switch_vault_after_lock_verifies_uuid_change() {
        let (_dir, mut app) = fixture_app(&["alpha", "beta"], Duration::from_secs(300));
        // Unlock the first vault (alpha).
        unlock(&mut app, PASSWORD);
        assert_eq!(app.selected_vault.as_deref(), Some("alpha"));
        let vault_alpha_uuid = app.vault.as_ref().unwrap().root_group_uuid();
        // Lock.
        app.handle_event(&key_ctrl('l'));
        assert!(matches!(app.phase, Phase::LockScreen));
        // Return to list and select the second vault (beta).
        app.handle_event(&key(' ')); // any key on lock screen → UnlockList
        app.handle_event(&key('j')); // list_index → 1 (beta)
        assert_eq!(app.list_index, 1);
        unlock(&mut app, PASSWORD);
        assert_eq!(app.selected_vault.as_deref(), Some("beta"));
        let vault_beta_uuid = app.vault.as_ref().unwrap().root_group_uuid();
        // Verify the vault UUID changed.
        assert_ne!(
            vault_alpha_uuid, vault_beta_uuid,
            "switching vaults should change the root group UUID"
        );
    }

    /// Journey: auto-lock fires → unlock different vault → verify the new
    /// vault is active (not the one that was locked).
    #[test]
    fn auto_lock_then_unlock_different_vault() {
        let (_dir, mut app) = fixture_app(&["alpha", "beta"], Duration::from_millis(900));
        // Unlock the first vault.
        unlock(&mut app, PASSWORD);
        assert_eq!(app.selected_vault.as_deref(), Some("alpha"));
        // Tick past the idle deadline (two ticks: Active → Expired → Locked).
        let t0 = Instant::now();
        app.tick(t0 + Duration::from_millis(950));
        assert!(
            app.vault.is_some(),
            "first tick: Expired warning, vault still present"
        );
        app.tick(t0 + Duration::from_secs(1));
        assert!(app.vault.is_none());
        assert!(matches!(app.phase, Phase::LockScreen));
        // Return to list and unlock the second vault.
        app.handle_event(&key(' ')); // any key on lock screen → UnlockList
        app.handle_event(&key('j')); // list_index → 1 (beta)
        unlock(&mut app, PASSWORD);
        assert_eq!(app.selected_vault.as_deref(), Some("beta"));
        assert!(app.vault.is_some());
    }

    /// Journey: unlock → lock → return to list → verify the list highlights
    /// the previously unlocked vault.
    #[test]
    fn lock_screen_returns_to_list_with_prior_highlight() {
        let (_dir, mut app) = fixture_app(&["first", "second", "third"], Duration::from_secs(300));
        // Unlock the second vault.
        app.handle_event(&key('j')); // list_index → 1 (second)
        unlock(&mut app, PASSWORD);
        assert_eq!(app.selected_vault.as_deref(), Some("second"));
        // Lock.
        app.handle_event(&key_ctrl('l'));
        assert!(matches!(app.phase, Phase::LockScreen));
        // Return to list.
        app.handle_event(&key(' '));
        assert!(matches!(app.phase, Phase::UnlockList));
        // The list should highlight the previously unlocked vault.
        assert_eq!(app.list_index, 1, "second vault re-highlighted");
        assert_eq!(
            app.selected_vault.as_deref(),
            Some("second"),
            "selected_vault tracks the prior unlock"
        );
    }

    // T-IT-2: idle past the deadline auto-locks (Active → Expired → Locked).
    #[test]
    fn idle_timeout_auto_locks() {
        let (_dir, mut app) = fixture_app(&["personal"], Duration::from_secs(1));
        unlock(&mut app, PASSWORD);
        let t0 = Instant::now();
        // First over-deadline tick: Active → Expired; not locked yet.
        app.tick(t0 + Duration::from_millis(1_100));
        assert!(
            app.vault.is_some(),
            "Expired is a one-tick warning, not a lock"
        );
        // Next tick: Expired → Locked.
        app.tick(t0 + Duration::from_millis(1_200));
        assert!(app.vault.is_none());
        assert!(matches!(app.phase, Phase::LockScreen));
    }

    // T-IT-2: the lock clock does not run while locked (no spurious lock churn).
    #[test]
    fn tick_does_not_lock_when_already_locked() {
        let (_dir, mut app) = single_vault_app();
        // Never unlocked → tick far in the future must not panic or change phase.
        app.tick(Instant::now() + Duration::from_secs(10_000));
        assert!(matches!(app.phase, Phase::UnlockList));
    }

    #[test]
    fn quit_sets_should_quit() {
        let (_dir, mut app) = single_vault_app();
        app.handle_event(&key_ctrl('q'));
        assert!(app.should_quit);
    }

    #[test]
    fn unlock_list_navigation_clamps_at_bounds() {
        let (_dir, mut app) = fixture_app(&["a", "b"], Duration::from_secs(300));
        assert_eq!(app.list_index, 0);
        app.handle_event(&key('k')); // up at top: clamp
        assert_eq!(app.list_index, 0);
        app.handle_event(&key('j')); // down
        assert_eq!(app.list_index, 1);
        app.handle_event(&key('j')); // down at bottom: clamp
        assert_eq!(app.list_index, 1);
    }

    // T2.4: workspace tab navigation (the gt/gT/{count}gt/Alt+N dispatcher).

    #[test]
    fn workspace_gt_gt_cycle_tabs_with_wrap() {
        let (_dir, mut app) = single_vault_app();
        unlock(&mut app, PASSWORD);
        assert_eq!(app.tabs.active_index(), 0); // Secrets
        app.handle_event(&key('g'));
        app.handle_event(&key('t'));
        assert_eq!(app.tabs.active_index(), 1); // Settings
        app.handle_event(&key('g'));
        app.handle_event(&key('t'));
        assert_eq!(app.tabs.active_index(), 0); // wrapped back to Secrets
        app.handle_event(&key('g'));
        app.handle_event(&key('T')); // gT → previous
        assert_eq!(app.tabs.active_index(), 1);
    }

    #[test]
    fn workspace_alt_digit_jumps_directly() {
        let (_dir, mut app) = single_vault_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_alt('2'));
        assert_eq!(app.tabs.active_index(), 1); // ordinal 2 = Settings
        app.handle_event(&key_alt('1'));
        assert_eq!(app.tabs.active_index(), 0); // ordinal 1 = Secrets
    }

    #[test]
    fn workspace_count_prefix_gt_jumps_to_ordinal() {
        let (_dir, mut app) = single_vault_app();
        unlock(&mut app, PASSWORD);
        // "2gt" → jump to tab 2 (Settings).
        app.handle_event(&key('2'));
        app.handle_event(&key('g'));
        app.handle_event(&key('t'));
        assert_eq!(app.tabs.active_index(), 1);
    }

    #[test]
    fn workspace_stray_key_resets_pending_tab_motion() {
        let (_dir, mut app) = single_vault_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('g')); // pending g
        app.handle_event(&key('x')); // not a motion → resets
        app.handle_event(&key('t')); // lone 't' (no pending g) → no-op
        assert_eq!(app.tabs.active_index(), 0, "stray keys must not move tabs");
    }

    #[test]
    fn tabs_reset_to_secrets_on_each_unlock() {
        let (_dir, mut app) = single_vault_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_alt('2')); // → Settings
        assert_eq!(app.tabs.active_index(), 1);
        app.handle_event(&key_ctrl('l')); // lock
        app.handle_event(&key(' ')); // lock screen → list
        unlock(&mut app, PASSWORD); // re-unlock
        assert_eq!(app.tabs.active_index(), 0, "re-unlock starts on Secrets");
    }

    // Phase 3: Secrets-tab dispatch wiring. Tree/detail internals are covered
    // by the `entry_tree`/`entry_detail` unit tests; these assert that
    // `on_workspace_key` routes keys to the Secrets handlers correctly.

    /// Unlock an `App` over a vault with `Personal/{Alpha,Bravo}` + a loose
    /// `Root1` entry. After unlock the tree selects the first visible node
    /// (the `Personal` group, collapsed).
    fn populated_app() -> (TempDir, App) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("personal.kdbx");
        let mut vault = Vault::create(
            &path,
            &MasterPassword::new(PASSWORD.to_string()),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create");
        let root = vault.root_group_uuid();
        let group = vault.create_group(root, "Personal").expect("group");
        vault
            .add_entry(group, EntryBuilder::credential("Alpha").build())
            .expect("alpha");
        vault
            .add_entry(group, EntryBuilder::credential("Bravo").build())
            .expect("bravo");
        vault
            .add_entry(
                root,
                EntryBuilder::credential("Root1")
                    .username("alice")
                    .password("s3cr3t")
                    .build(),
            )
            .expect("root1");
        vault.save().expect("save");
        drop(vault);

        let paths = FalachPaths::with_state_dir(dir.path().join("state"));
        let mut registry = VaultRegistry::with_paths(paths.clone());
        registry
            .register(RegisteredVault {
                name: "personal".to_string(),
                path,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                keyfile_path: None,
                extra: toml::Table::new(),
            })
            .expect("register");
        registry.save().expect("save fixture registry");
        let app =
            App::from_registry(registry, paths, AutoLockConfig::default()).expect("from_registry");
        (dir, app)
    }

    #[test]
    fn unlock_selects_first_visible_node_and_focuses_tree() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        assert!(matches!(app.focus, Focus::Tree));
        assert!(app.tree.selected().is_some(), "first node auto-selected");
    }

    #[test]
    fn secrets_j_k_move_tree_selection() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let first = app.tree.selected();
        app.handle_event(&key('j'));
        let second = app.tree.selected();
        assert_ne!(first, second, "j advances selection");
        app.handle_event(&key('k'));
        assert_eq!(app.tree.selected(), first, "k returns to the prior node");
    }

    #[test]
    fn secrets_l_expands_and_h_collapses_group() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Selection starts on the Personal group (collapsed). `l` expands it.
        let vault = app.vault.as_ref().unwrap();
        let rows_before = entry_tree::build_rows(vault, &app.tree, &app.recents).len();
        app.handle_event(&key('l'));
        let vault = app.vault.as_ref().unwrap();
        let rows_after = entry_tree::build_rows(vault, &app.tree, &app.recents).len();
        assert!(rows_after > rows_before, "l expands the group");
        app.handle_event(&key('h'));
        let vault = app.vault.as_ref().unwrap();
        assert_eq!(
            entry_tree::build_rows(vault, &app.tree, &app.recents).len(),
            rows_before,
            "h collapses the group"
        );
    }

    #[test]
    fn secrets_space_toggles_reveal() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Post-unlock the selection is the `Personal` group; reveal is a no-op on
        // a group row (T2.1: pairs with `command_state(RevealPassword)==Disabled`).
        assert!(!app.reveal_password);
        app.handle_event(&key(' '));
        assert!(!app.reveal_password, "reveal is a no-op on a group row");
        // Move to the loose `Root1` entry. Tree-space marks it; detail-space
        // retains the password reveal action.
        app.handle_event(&key('j'));
        assert!(app.selected_entry_uuid().is_some(), "Root1 is an entry");
        app.handle_event(&key(' '));
        assert_eq!(app.marks.len(), 1, "tree-space toggles a persistent mark");
        app.handle_event(&key_code(KeyCode::Tab));
        app.handle_event(&key(' '));
        assert!(app.reveal_password);
        app.handle_event(&key(' '));
        assert!(!app.reveal_password);
    }

    #[test]
    fn secrets_tab_toggles_pane_focus() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        assert!(matches!(app.focus, Focus::Tree));
        app.handle_event(&key_code(KeyCode::Tab));
        assert!(matches!(app.focus, Focus::Detail));
        app.handle_event(&key_code(KeyCode::Tab));
        assert!(matches!(app.focus, Focus::Tree));
    }

    #[test]
    fn secrets_o_cycles_sort_order() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let before = app.tree.sort();
        app.handle_event(&key('o'));
        assert_ne!(before, app.tree.sort(), "o advances the sort order");
    }

    // ---- T4.4: two-axis navigation + jump history ----

    /// Look up an entry UUID by exact title in the unlocked fixture.
    fn entry_uuid(app: &App, title: &str) -> Uuid {
        let vault = app.vault.as_ref().expect("unlocked");
        vault
            .search(SearchOptions::new(title))
            .expect("search")
            .first()
            .expect("entry present")
            .uuid
    }

    #[test]
    fn l_on_leaf_focuses_detail_h_returns() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Move to the loose `Root1` entry (a leaf) and step in with `l`/→.
        app.handle_event(&key('j'));
        assert!(app.selected_entry_uuid().is_some(), "Root1 is a leaf entry");
        app.handle_event(&key('l'));
        assert!(
            matches!(app.focus, Focus::Detail),
            "l on a leaf opens detail"
        );
        // `h` in the detail pane returns focus to the tree.
        app.handle_event(&key('h'));
        assert!(
            matches!(app.focus, Focus::Tree),
            "h in detail returns to tree"
        );
        // Arrow parity: → opens detail, ← returns.
        app.handle_event(&key_code(KeyCode::Right));
        assert!(matches!(app.focus, Focus::Detail));
        app.handle_event(&key_code(KeyCode::Left));
        assert!(matches!(app.focus, Focus::Tree));
        // `l` on a group still expands rather than changing focus.
        let rows_before = {
            let v = app.vault.as_ref().unwrap();
            entry_tree::build_rows(v, &app.tree, &app.recents).len()
        };
        app.handle_event(&key('k')); // back up onto the Personal group
        app.handle_event(&key('l')); // expands
        let rows_after = {
            let v = app.vault.as_ref().unwrap();
            entry_tree::build_rows(v, &app.tree, &app.recents).len()
        };
        assert!(rows_after > rows_before, "l on a group expands it");
        assert!(
            matches!(app.focus, Focus::Tree),
            "expanding keeps tree focus"
        );
    }

    #[test]
    fn jump_selects_and_expands() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // `Alpha` lives under the (collapsed) `Personal` group.
        let alpha = entry_uuid(&app, "Alpha");
        app.jump_to_history(alpha);
        assert_eq!(app.tree.selected(), Some(alpha), "jump selects the entry");
        assert!(
            matches!(app.focus, Focus::Detail),
            "jump to an entry focuses detail"
        );
        let rows = {
            let v = app.vault.as_ref().unwrap();
            entry_tree::build_rows(v, &app.tree, &app.recents)
        };
        assert!(
            rows.iter().any(|r| r.uuid == alpha),
            "ancestor group expanded so the entry is visible"
        );
    }

    #[test]
    fn history_cleared_on_lock() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let a = entry_uuid(&app, "Root1");
        let b = entry_uuid(&app, "Alpha");
        app.jump_history.push(a);
        app.jump_history.push(b);
        app.lock_app();
        assert_eq!(
            app.jump_history.back(b),
            None,
            "lock clears the jump history (no earlier node remains)"
        );
    }

    #[test]
    fn ctrl_o_walks_history_back_and_forward() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let root1 = entry_uuid(&app, "Root1");
        let alpha = entry_uuid(&app, "Alpha");
        app.jump_history.push(root1);
        app.jump_history.push(alpha);
        app.tree.select(alpha);
        app.focus = Focus::Detail;
        // Ctrl+O walks back to Root1 (works from either pane).
        app.handle_event(&key_ctrl('o'));
        assert_eq!(app.tree.selected(), Some(root1), "Ctrl+O jumps back");
        // Ctrl+O again on the oldest node posts a status note and does not move.
        app.handle_event(&key_ctrl('o'));
        assert_eq!(app.tree.selected(), Some(root1));
        assert_eq!(app.status.as_deref(), Some("no earlier entry"));
        // Ctrl+I (tree focus after the back-jump landed on an entry → detail;
        // step back to the tree first) walks forward to Alpha.
        app.focus = Focus::Tree;
        app.handle_event(&key_ctrl('i'));
        assert_eq!(app.tree.selected(), Some(alpha), "Ctrl+I jumps forward");
    }

    // ---- T4.5: visual mode + bulk operations ----

    #[test]
    fn visual_mode_range_marks_and_deescalation() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('l')); // expand Personal so Alpha/Bravo are visible
                                     // rows: [Personal(group), Alpha, Bravo, Root1]. `v` anchors on the group.
        app.handle_event(&key('v'));
        assert!(matches!(app.tree_mode, TreeMode::Visual { .. }));
        assert!(app.marks.is_empty(), "anchoring on a group marks nothing");
        app.handle_event(&key('j')); // → Alpha
        app.handle_event(&key('j')); // → Bravo
        app.handle_event(&key('j')); // → Root1
        assert_eq!(
            app.marks.len(),
            3,
            "range marks the 3 entries, skips the group"
        );
        // Space toggles the current row (Root1) out of the marks.
        app.handle_event(&key(' '));
        assert_eq!(app.marks.len(), 2, "Space toggles one mark off");
        assert!(matches!(app.tree_mode, TreeMode::Visual { .. }));
        // Esc ladder: Visual → Normal (marks kept) → cleared → normal.
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(
            matches!(app.tree_mode, TreeMode::Normal),
            "Esc leaves visual mode"
        );
        assert_eq!(app.marks.len(), 2, "de-escalation keeps marks");
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(app.marks.is_empty(), "second Esc clears the marks");
    }

    // ---- T4.7: read-only sessions ----

    /// Unlock the fixture and flip it into a read-only session, with the tree
    /// selection moved onto the loose `Root1` entry (so entry-scoped commands
    /// would otherwise be Enabled).
    fn readonly_app() -> (TempDir, App) {
        let (dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // select Root1 (an entry)
        app.read_only = true;
        (dir, app)
    }

    #[test]
    fn readonly_disables_mutating_commands() {
        let (_dir, app) = readonly_app();
        for &id in RO_MUTATING_COMMANDS {
            assert_eq!(
                app.command_state(id),
                CmdState::Disabled,
                "{id:?} must be disabled in a read-only session"
            );
        }
    }

    #[test]
    fn readonly_mutating_set_is_complete() {
        // Backstop meta-test (T4.7): dispatching *every* command in a read-only
        // session must never advance the vault save counter — the persist guard
        // (layer 2) covers anything the const set (layer 1) might miss. Set up
        // marks + a selected entry so the mutating handlers would otherwise run.
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j'));
        let alpha = entry_uuid(&app, "Alpha");
        app.marks.insert(alpha);
        app.read_only = true;
        let before = app.save_count;
        for spec in crate::command::registry::COMMANDS {
            app.execute_command(spec.id, None);
        }
        assert_eq!(
            app.save_count, before,
            "no command may write the vault in a read-only session"
        );
    }

    #[test]
    fn readonly_blocks_sync() {
        // Sync writes the vault + pushes to the remote via `engine.sync_now`,
        // bypassing `persist_vault` — so read-only must block it at the command
        // and at the `start_sync` choke point (the code-review finding).
        let (_dir, mut app) = readonly_app();
        app.handle_event(&key('s')); // manual sync command
        assert!(
            app.overlay.is_none(),
            "read-only refuses the manual sync command"
        );
        assert!(!app.is_syncing());
        // The choke point is guarded even if reached directly (auto-sync
        // triggers on unlock / lock-quit bypass `execute_command`).
        app.start_sync(
            crate::sync_runtime::SyncTrigger::OnUnlock,
            MasterPassword::new(PASSWORD.to_string()),
        );
        assert!(!app.is_syncing(), "read-only start_sync is a no-op");
        assert!(
            app.vault.is_some(),
            "read-only start_sync does not consume the vault"
        );
        assert!(
            !app.should_sync_on_leave(),
            "read-only never syncs on lock/quit"
        );
    }

    #[test]
    fn readonly_blocks_in_memory_mutation() {
        // The bug the review caught: `persist_vault` returning Ok in read-only
        // let the in-memory `delete_entry` run first, so the session *reflected*
        // the mutation (and sync would push it). The command must be blocked
        // before it mutates the in-memory vault at all.
        let (_dir, mut app) = readonly_app(); // Root1 selected
        let root1 = entry_uuid(&app, "Root1");
        app.handle_event(&key('d')); // delete command
        assert!(
            app.overlay.is_none(),
            "read-only blocks the delete command (no confirm)"
        );
        app.handle_event(&key('y')); // stray confirm — nothing to confirm
        assert!(
            app.vault.as_ref().unwrap().get_entry(root1).is_ok(),
            "the entry must remain in the in-memory vault (not deleted)"
        );
    }

    #[test]
    fn readonly_persist_guard() {
        let (_dir, mut app) = readonly_app();
        let before = app.save_count;
        // A forced persist fails closed and neither writes nor advances the count.
        assert!(
            app.persist_vault().is_err(),
            "read-only persistence is denied"
        );
        assert_eq!(app.save_count, before, "read-only persist writes nothing");
        assert_eq!(
            app.status_bar.current(),
            Some("Read-only session — vault not saved.")
        );
    }

    #[test]
    fn readonly_allows_copy_pins_and_theme() {
        let (_dir, mut app) = readonly_app();
        let sink = crate::clipboard::RecordingClipboard::new();
        let log = sink.log.clone();
        app.set_clipboard(Box::new(sink));
        // Copy is a read, not a write — allowed.
        app.handle_event(&key('c'));
        assert_eq!(
            log.borrow().copies,
            1,
            "clipboard copy allowed in read-only"
        );
        // Pin toggles write only tui.toml UI state — allowed.
        let pins_before = app.tabs.count();
        app.handle_event(&key('p'));
        assert!(
            app.tabs.count() > pins_before,
            "pinning allowed in read-only"
        );
        // Theme cycling writes config.toml prefs — allowed, no panic.
        let theme_before = app.current_theme_name().to_string();
        app.cycle_theme();
        assert_ne!(
            theme_before,
            app.current_theme_name(),
            "theme cycle allowed"
        );
    }

    #[test]
    fn readonly_badge_rendered() {
        use ratatui::backend::TestBackend;
        use ratatui::style::Modifier;
        use ratatui::Terminal;
        let (_dir, app) = readonly_app();
        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal
            .draw(|frame| app.render(frame, Instant::now()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let status_y = 19;
        let mut row = String::new();
        let mut has_reversed = false;
        for x in 0..80u16 {
            let cell = buffer.cell((x, status_y)).unwrap();
            row.push_str(cell.symbol());
            if cell.symbol() == "R" && cell.style().add_modifier.contains(Modifier::REVERSED) {
                has_reversed = true;
            }
        }
        assert!(
            row.contains("RO"),
            "read-only badge in the status row: {row:?}"
        );
        assert!(
            has_reversed,
            "RO badge carries the REVERSED modifier (not colour alone)"
        );
    }

    #[test]
    fn readonly_vault_file_mtime_unchanged() {
        let (dir, mut app) = populated_app();
        let kdbx = dir.path().join("personal.kdbx");
        let before = std::fs::metadata(&kdbx).unwrap().modified().unwrap();
        unlock(&mut app, PASSWORD);
        app.read_only = true;
        app.handle_event(&key('j')); // select Root1
        app.handle_event(&key('d')); // attempt delete
        app.handle_event(&key('y')); // confirm — guarded, no write
        let after = std::fs::metadata(&kdbx).unwrap().modified().unwrap();
        assert_eq!(
            before, after,
            "read-only session never rewrites the vault file"
        );
    }

    // ---- T4.6: mouse as accelerator ----

    /// Draw the app into a fixed-size backend so renderers populate the exact
    /// mouse hit map.
    fn render_to(app: &App, w: u16, h: u16) {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal
            .draw(|frame| app.render(frame, Instant::now()))
            .unwrap();
    }

    fn mouse_down(col: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: col,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn mouse_scroll(col: u16, row: u16, down: bool) -> MouseEvent {
        MouseEvent {
            kind: if down {
                MouseEventKind::ScrollDown
            } else {
                MouseEventKind::ScrollUp
            },
            column: col,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[test]
    fn hit_map_maps_click_to_expected_target() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        render_to(&app, 80, 24);
        // Row 0 = exact tab labels; tree pane left, detail right.
        assert!(matches!(
            app.mouse_target_at(2, 0),
            Some(MouseTarget::Tab(0))
        ));
        let more = app
            .mouse_regions
            .borrow()
            .iter()
            .find(|(_, target)| matches!(target, MouseTarget::HintMore))
            .map(|(area, _)| *area)
            .expect("rendered more affordance");
        assert_eq!(
            app.mouse_target_at(more.x, more.y),
            Some(MouseTarget::HintMore)
        );
        let tree_row = app
            .mouse_regions
            .borrow()
            .iter()
            .find(|(_, target)| matches!(target, MouseTarget::TreeRow(_)))
            .map(|(area, _)| *area)
            .expect("rendered tree row");
        assert!(matches!(
            app.mouse_target_at(tree_row.x, tree_row.y),
            Some(MouseTarget::TreeRow(_))
        ));
        assert!(
            matches!(app.mouse_target_at(60, 10), Some(MouseTarget::DetailPane)),
            "a click in the detail pane focuses it"
        );
    }

    #[test]
    fn every_mouse_target_maps_to_registry_command() {
        // Exhaustive over MouseTarget: adding a variant without a mapping breaks
        // this match — the structural guarantee that mouse ⊆ keyboard (US-071).
        fn mapping(t: MouseTarget) -> &'static str {
            match t {
                MouseTarget::TreeRow(_) => "select-row (j/k)",
                MouseTarget::DetailPane => "focus-pane (Tab)",
                MouseTarget::Tab(_) => "jump-to-tab ({count}gt)",
                MouseTarget::HintMore => "help (?)",
                MouseTarget::SearchRow(_) => "search selection (up/down)",
                MouseTarget::PaletteRow(_) => "palette selection (up/down)",
            }
        }
        for t in [
            MouseTarget::TreeRow(0),
            MouseTarget::DetailPane,
            MouseTarget::Tab(1),
            MouseTarget::HintMore,
            MouseTarget::SearchRow(0),
            MouseTarget::PaletteRow(0),
        ] {
            assert!(!mapping(t).is_empty());
        }
        // And the effects go through existing dispatch:
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        render_to(&app, 80, 24);
        app.apply_mouse_target(MouseTarget::HintMore);
        assert!(
            matches!(app.overlay, Some(Overlay::Palette(_))),
            "HintMore opens the palette"
        );

        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let before = app.tabs.active_index();
        app.apply_mouse_target(MouseTarget::Tab(1));
        assert_ne!(app.tabs.active_index(), before, "tab target jumps directly");

        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.apply_mouse_target(MouseTarget::DetailPane);
        assert!(
            matches!(app.focus, Focus::Detail),
            "DetailPane focuses detail"
        );
    }

    #[test]
    fn wheel_scrolls_focused_pane() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        render_to(&app, 80, 24);
        let first = app.tree.selected();
        app.handle_mouse_event(mouse_scroll(3, 5, true)); // wheel down over the tree
        assert_ne!(
            app.tree.selected(),
            first,
            "wheel-down moves the tree selection"
        );
    }

    #[test]
    fn mouse_click_selects_tree_row() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        render_to(&app, 80, 24);
        let rows = {
            let v = app.vault.as_ref().unwrap();
            entry_tree::build_rows(v, &app.tree, &app.recents)
        };
        // Click the second visible row (index 1).
        app.handle_mouse_event(mouse_down(3, 4));
        assert_eq!(
            app.tree.selected(),
            Some(rows[1].uuid),
            "click selects that row"
        );
        assert!(matches!(app.focus, Focus::Tree));
    }

    /// An app whose root holds `n` loose entries — enough to scroll a short pane.
    fn many_entry_app(n: usize) -> (TempDir, App) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("many.kdbx");
        let mut vault = Vault::create(
            &path,
            &MasterPassword::new(PASSWORD.to_string()),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create");
        let root = vault.root_group_uuid();
        for i in 0..n {
            vault
                .add_entry(
                    root,
                    EntryBuilder::credential(format!("Entry{i:02}")).build(),
                )
                .expect("add");
        }
        vault.save().expect("save");
        drop(vault);
        let paths = FalachPaths::with_state_dir(dir.path().join("state"));
        let mut registry = VaultRegistry::with_paths(paths.clone());
        registry
            .register(RegisteredVault {
                name: "many".to_string(),
                path,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                keyfile_path: None,
                extra: toml::Table::new(),
            })
            .expect("register");
        registry.save().expect("save registry");
        let app =
            App::from_registry(registry, paths, AutoLockConfig::default()).expect("from_registry");
        (dir, app)
    }

    #[test]
    fn mouse_hit_test_accounts_for_tree_scroll() {
        let (_dir, mut app) = many_entry_app(30);
        unlock(&mut app, PASSWORD);
        // Scroll far down so the top of the pane is well past row 0.
        for _ in 0..25 {
            app.handle_event(&key('j'));
        }
        render_to(&app, 80, 12); // short pane → the list must scroll
                                 // A click on the first VISIBLE tree row maps to a scrolled-past index,
                                 // not absolute row 0 (the bug this fix closes).
        match app.mouse_target_at(3, 3) {
            Some(MouseTarget::TreeRow(i)) => {
                assert!(i > 0, "click maps past the scroll offset, got {i}");
                // And clicking it selects that entry, not the first one.
                app.handle_mouse_event(mouse_down(3, 3));
                let rows = {
                    let v = app.vault.as_ref().unwrap();
                    entry_tree::build_rows(v, &app.tree, &app.recents)
                };
                assert_eq!(app.tree.selected(), Some(rows[i].uuid));
            }
            other => panic!("expected a tree row, got {other:?}"),
        }
    }

    #[test]
    fn mouse_disabled_processes_no_mouse_events() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.mouse_enabled = false;
        render_to(&app, 80, 24);
        let before = app.tree.selected();
        app.handle_mouse_event(mouse_down(3, 4));
        assert_eq!(app.tree.selected(), before, "disabled mouse is inert");
    }

    #[test]
    fn overlay_shadows_workspace_clicks() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        render_to(&app, 80, 24);
        let before = app.tree.selected();
        app.handle_event(&key('/')); // open search overlay
        app.handle_mouse_event(mouse_down(3, 4)); // click "behind" the modal
        assert_eq!(
            app.tree.selected(),
            before,
            "clicks are ignored while an overlay is open"
        );
        assert!(matches!(app.overlay, Some(Overlay::Search(_))));
    }

    #[test]
    fn search_and_palette_rows_are_clickable_without_click_through() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('/'));
        render_to(&app, 80, 24);
        let search_area = app
            .mouse_regions
            .borrow()
            .iter()
            .find(|(_, target)| matches!(target, MouseTarget::SearchRow(1)))
            .map(|(area, _)| *area)
            .expect("second search row is visible");
        app.handle_mouse_event(mouse_down(search_area.x, search_area.y));
        assert_eq!(search_state(&app).selected, 1);

        app.handle_event(&key_code(KeyCode::Esc));
        app.handle_event(&key('?'));
        render_to(&app, 80, 24);
        let palette_area = app
            .mouse_regions
            .borrow()
            .iter()
            .find(|(_, target)| matches!(target, MouseTarget::PaletteRow(2)))
            .map(|(area, _)| *area)
            .expect("third palette row is visible");
        app.handle_mouse_event(mouse_down(palette_area.x, palette_area.y));
        match app.overlay.as_ref() {
            Some(Overlay::Palette(state)) => assert_eq!(state.selected, 2),
            _ => panic!("palette remains open"),
        }
    }

    // ---- T4.2: search overlay ----

    /// Borrow the open search overlay's state, or panic.
    fn search_state(app: &App) -> &crate::overlay::SearchState {
        match app.overlay.as_ref() {
            Some(Overlay::Search(state)) => state,
            _ => panic!("search overlay not open"),
        }
    }

    #[test]
    fn open_useful_before_typing() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('/'));
        let state = search_state(&app);
        assert!(
            !state.results.is_empty(),
            "empty-query browse mode lists entries before any keystroke"
        );
    }

    #[test]
    fn typing_requeries_and_shows_count() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('/'));
        for c in "root".chars() {
            app.handle_event(&key(c));
        }
        let state = search_state(&app);
        assert_eq!(state.results.len(), 1, "fuzzy 'root' matches only Root1");
        assert_eq!(app.entry_title(state.results[0].uuid), "Root1");
    }

    #[test]
    fn enter_copies_tab_opens_per_config() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let sink = crate::clipboard::RecordingClipboard::new();
        let log = sink.log.clone();
        app.set_clipboard(Box::new(sink));
        // Default enter-action = Copy: Enter copies the password and closes.
        app.handle_event(&key('/'));
        for c in "root".chars() {
            app.handle_event(&key(c));
        }
        app.handle_event(&key_code(KeyCode::Enter));
        assert_eq!(log.borrow().copies, 1, "Enter copies the password");
        assert!(app.overlay.is_none(), "search closes after copy");

        // With the default Copy preference, Tab is the opposite Open action.
        app.handle_event(&key('/'));
        for c in "root".chars() {
            app.handle_event(&key(c));
        }
        let root1 = search_state(&app).results[0].uuid;
        app.handle_event(&key_code(KeyCode::Tab));
        assert!(app.overlay.is_none(), "Tab closes search");
        assert_eq!(
            app.tree.selected(),
            Some(root1),
            "Tab jumps the tree to the entry"
        );
        assert!(
            matches!(app.focus, Focus::Detail),
            "Tab focuses the detail pane"
        );

        // Switching the preference truly swaps the keys: Enter opens and Tab
        // copies, rather than making both keys open.
        app.user_config.search.enter_action = crate::user_config::EnterAction::Open;
        app.handle_event(&key('/'));
        type_str(&mut app, "alpha");
        let alpha = search_state(&app).results[0].uuid;
        app.handle_event(&key_code(KeyCode::Enter));
        assert_eq!(app.tree.selected(), Some(alpha), "Enter opens in Open mode");

        app.handle_event(&key('/'));
        type_str(&mut app, "root");
        app.handle_event(&key_code(KeyCode::Tab));
        assert_eq!(log.borrow().copies, 2, "Tab copies in Open mode");
    }

    #[test]
    fn esc_restores_pre_search_selection_and_scroll() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let before_sel = app.tree.selected();
        let before_focus = app.focus;
        app.handle_event(&key('/'));
        for c in "alpha".chars() {
            app.handle_event(&key(c));
        }
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(app.overlay.is_none(), "Esc closes search");
        assert_eq!(
            app.tree.selected(),
            before_sel,
            "Esc restores the tree selection"
        );
        assert_eq!(app.focus, before_focus, "Esc restores the pane focus");
    }

    #[test]
    fn scope_cycles_with_visible_indicator() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Selection starts on the Personal group.
        app.handle_event(&key('/'));
        assert!(matches!(search_state(&app).scope, SearchScope::All));
        app.handle_event(&key_ctrl('s')); // All → GroupSubtree(Personal)
        assert!(
            matches!(search_state(&app).scope, SearchScope::GroupSubtree(_)),
            "Ctrl+S scopes to the current group"
        );
        // GroupSubtree → (first result untagged → skip Tag) → All.
        app.handle_event(&key_ctrl('s'));
        assert!(
            matches!(search_state(&app).scope, SearchScope::All),
            "cycling past an untagged selection returns to ALL"
        );
    }

    #[test]
    fn configured_default_search_scope_is_applied() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.user_config.search.default_scope = "group".to_string();
        app.handle_event(&key('/'));
        assert!(matches!(
            search_state(&app).scope,
            SearchScope::GroupSubtree(_)
        ));
    }

    #[test]
    fn quick_select_acts_on_visible_row() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('/')); // browse: Alpha, Bravo, Root1 (alphabetical)
        let third = {
            let state = search_state(&app);
            assert!(state.results.len() >= 3);
            state.results[2].uuid
        };
        // Alt+3 opens visible row 3 (enter-action defaults to Copy, but Root1's
        // copy path bumps recents; assert via the jump when we switch to Open).
        app.user_config.search.enter_action = crate::user_config::EnterAction::Open;
        app.handle_event(&key_alt('3'));
        assert!(app.overlay.is_none(), "quick-select acts and closes");
        assert_eq!(
            app.tree.selected(),
            Some(third),
            "Alt+3 acts on visible row 3"
        );
    }

    // ---- T4.8: quit confirmation ----

    /// Force `behavior.confirm-quit = true` on an unlocked app.
    fn confirm_quit_app() -> (TempDir, App) {
        let (dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.user_config.set_confirm_quit_for_test(true);
        (dir, app)
    }

    #[test]
    fn confirm_quit_default_false_is_immediate() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        assert!(
            !app.user_config.confirm_quit(),
            "default preserves immediate quit"
        );
        app.handle_event(&key_ctrl('q'));
        assert!(
            app.should_quit,
            "quit is immediate when confirm-quit is off"
        );
        assert!(app.overlay.is_none(), "no confirmation overlay by default");
    }

    #[test]
    fn confirm_quit_true_opens_confirmation() {
        let (_dir, mut app) = confirm_quit_app();
        app.handle_event(&key_ctrl('q'));
        assert!(
            matches!(app.overlay, Some(Overlay::ConfirmQuit)),
            "confirm-quit opens the confirmation overlay"
        );
        assert!(!app.should_quit, "quit does not proceed until confirmed");
    }

    #[test]
    fn confirm_quit_yes_resumes_once() {
        let (_dir, mut app) = confirm_quit_app();
        app.handle_event(&key_ctrl('q'));
        app.handle_event(&key('y'));
        assert!(app.should_quit, "y proceeds through the quit path");
        assert!(app.overlay.is_none(), "confirmation closes on quit");
    }

    #[test]
    fn confirm_quit_no_and_esc_cancel() {
        for cancel in [key('n'), key_code(KeyCode::Esc)] {
            let (_dir, mut app) = confirm_quit_app();
            app.handle_event(&key_ctrl('q'));
            app.handle_event(&cancel);
            assert!(!app.should_quit, "cancel does not quit");
            assert!(app.overlay.is_none(), "cancel closes the confirmation");
        }
    }

    #[test]
    fn confirm_quit_second_quit_does_not_duplicate() {
        let (_dir, mut app) = confirm_quit_app();
        app.handle_event(&key_ctrl('q')); // opens confirmation
        app.handle_event(&key_ctrl('q')); // second quit while open — ignored
        assert!(
            matches!(app.overlay, Some(Overlay::ConfirmQuit)),
            "a second quit does not enqueue or duplicate"
        );
        assert!(!app.should_quit);
    }

    #[test]
    fn selection_indicator_reflects_mode_and_marks() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        assert_eq!(app.selection_indicator(), None, "no indicator when idle");
        app.tree_mode = TreeMode::Visual { anchor: 0 };
        assert_eq!(app.selection_indicator().as_deref(), Some("VISUAL"));
        app.marks.insert(entry_uuid(&app, "Alpha"));
        assert_eq!(
            app.selection_indicator().as_deref(),
            Some("VISUAL · 1 selected")
        );
        app.tree_mode = TreeMode::Normal;
        assert_eq!(app.selection_indicator().as_deref(), Some("1 selected"));
    }

    #[test]
    fn bulk_marks_survive_group_collapse() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let alpha = entry_uuid(&app, "Alpha");
        app.marks.insert(alpha);
        // Collapse then re-expand Personal: the UUID-keyed mark survives.
        app.handle_event(&key('l')); // expand
        app.handle_event(&key('h')); // collapse
        assert!(
            app.marks.contains(&alpha),
            "marks are UUID-keyed, survive collapse"
        );
    }

    #[test]
    fn bulk_ops_apply_to_all_marked_in_one_save() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let alpha = entry_uuid(&app, "Alpha");
        let bravo = entry_uuid(&app, "Bravo");
        app.marks.insert(alpha);
        app.marks.insert(bravo);
        let before = app.save_count;
        app.apply_tag(TagAction::Add, "urgent");
        assert_eq!(
            app.save_count,
            before + 1,
            "a bulk op is exactly one atomic save"
        );
        assert!(app.marks.is_empty(), "marks clear after a bulk op");
    }

    #[test]
    fn bulk_tag_add_remove() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let alpha = entry_uuid(&app, "Alpha");
        let bravo = entry_uuid(&app, "Bravo");
        let has_tag = |app: &App, uuid: Uuid| {
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(uuid)
                .unwrap()
                .tags()
                .iter()
                .any(|t| t.as_str() == "urgent")
        };
        let before_alpha_history = app
            .vault
            .as_ref()
            .unwrap()
            .get_entry(alpha)
            .unwrap()
            .history()
            .len();
        let before_bravo_history = app
            .vault
            .as_ref()
            .unwrap()
            .get_entry(bravo)
            .unwrap()
            .history()
            .len();
        app.marks.insert(alpha);
        app.marks.insert(bravo);
        app.apply_tag(TagAction::Add, "urgent");
        assert!(
            has_tag(&app, alpha) && has_tag(&app, bravo),
            "tag added to both"
        );
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(alpha)
                .unwrap()
                .history()
                .len(),
            before_alpha_history + 1
        );
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(bravo)
                .unwrap()
                .history()
                .len(),
            before_bravo_history + 1
        );
        app.marks.insert(alpha);
        app.marks.insert(bravo);
        app.apply_tag(TagAction::Remove, "urgent");
        assert!(
            !has_tag(&app, alpha) && !has_tag(&app, bravo),
            "tag removed from both"
        );
    }

    #[test]
    fn bulk_tag_rejects_invalid_input_without_panicking_or_mutating() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let alpha = entry_uuid(&app, "Alpha");
        app.marks.insert(alpha);
        let before_save = app.save_count;
        let before_history = app
            .vault
            .as_ref()
            .unwrap()
            .get_entry(alpha)
            .unwrap()
            .history()
            .len();
        app.apply_tag(TagAction::Add, "invalid;tag");
        assert_eq!(app.save_count, before_save);
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(alpha)
                .unwrap()
                .history()
                .len(),
            before_history
        );
        assert!(
            app.marks.contains(&alpha),
            "failed batch keeps its operands"
        );
    }

    #[test]
    fn stale_bulk_mark_fails_before_mutating_any_valid_entry() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let alpha = entry_uuid(&app, "Alpha");
        app.marks.extend([alpha, Uuid::new_v4()]);
        app.apply_tag(TagAction::Add, "urgent");
        let entry = app.vault.as_ref().unwrap().get_entry(alpha).unwrap();
        assert!(entry.tags().iter().all(|tag| tag.as_str() != "urgent"));
    }

    #[test]
    fn bulk_move_to_group() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let alpha = entry_uuid(&app, "Alpha");
        let bravo = entry_uuid(&app, "Bravo");
        let archive = {
            let vault = app.vault.as_mut().unwrap();
            let root = vault.root_group_uuid();
            vault.create_group(root, "Archive").unwrap()
        };
        app.marks.insert(alpha);
        app.marks.insert(bravo);
        app.apply_move_to_group(archive);
        let members = app
            .vault
            .as_ref()
            .unwrap()
            .group_view(archive)
            .unwrap()
            .entry_uuids();
        assert!(
            members.contains(&alpha) && members.contains(&bravo),
            "marked entries reparented into Archive"
        );
    }

    #[test]
    fn bulk_delete_confirm_pluralized() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let alpha = entry_uuid(&app, "Alpha");
        let bravo = entry_uuid(&app, "Bravo");
        app.marks.insert(alpha);
        app.marks.insert(bravo);
        app.handle_event(&key('d')); // delete → bulk confirmation
        match app.overlay.as_ref() {
            Some(Overlay::ConfirmBulkDelete { uuids, titles }) => {
                assert_eq!(uuids.len(), 2, "confirmation covers both marked entries");
                assert_eq!(titles.len(), 2);
            }
            other => panic!(
                "expected bulk-delete confirmation, got {other:?}",
                other = other.is_some()
            ),
        }
        app.handle_event(&key('y')); // confirm
        let vault = app.vault.as_ref().unwrap();
        assert!(
            vault
                .search(SearchOptions::new("Alpha"))
                .unwrap()
                .is_empty(),
            "Alpha deleted"
        );
        assert!(
            vault
                .search(SearchOptions::new("Bravo"))
                .unwrap()
                .is_empty(),
            "Bravo deleted"
        );
    }

    #[test]
    fn bulk_commands_disabled_without_marks() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // No marks → the bulk commands are Disabled and dispatch is a no-op.
        for id in [Command::MoveToGroup, Command::AddTag, Command::RemoveTag] {
            assert_eq!(
                app.command_state(id),
                CmdState::Disabled,
                "{id:?} is disabled without marks"
            );
        }
        app.handle_event(&key('m')); // move — no overlay opens
        app.handle_event(&key('t')); // add-tag — no overlay opens
        assert!(app.overlay.is_none(), "bulk commands no-op without marks");
        // With a mark, they enable.
        app.marks.insert(entry_uuid(&app, "Alpha"));
        assert_eq!(app.command_state(Command::MoveToGroup), CmdState::Enabled);
    }

    #[test]
    fn secrets_enter_on_entry_focuses_detail_and_jk_then_scrolls() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Move down to the loose Root1 entry (after the collapsed Personal group).
        app.handle_event(&key('j'));
        assert!(matches!(app.focus, Focus::Tree));
        app.handle_event(&key_code(KeyCode::Enter)); // entry → focus Detail
        assert!(matches!(app.focus, Focus::Detail));
        // In detail focus, j scrolls the pane (the loose Root1 entry has a few
        // detail lines, so the offset can advance by one).
        assert_eq!(app.detail_scroll, 0);
        app.handle_event(&key('j'));
        assert_eq!(app.detail_scroll, 1, "j scrolls the detail pane");
        // h returns focus to the tree.
        app.handle_event(&key('h'));
        assert!(matches!(app.focus, Focus::Tree));
    }

    // The highest-value render test: drive the *composed* draw path
    // (`App::render` → workspace → secrets → tree + detail) at several terminal
    // sizes, including degenerate ones, to prove the layout/scroll arithmetic
    // never panics. Lands on the Root1 entry with the password revealed so the
    // `Some(data)` detail branch (block + wrap + scroll clamp) is exercised, not
    // just the empty placeholder.
    #[test]
    fn workspace_renders_without_panic_across_sizes() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // Personal (group) → Root1 (entry)
        app.handle_event(&key_code(KeyCode::Tab)); // focus Detail
        app.handle_event(&key(' ')); // reveal the password
        for (w, h) in [(80u16, 24u16), (40, 12), (10, 5), (1, 1)] {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).expect("backend");
            terminal
                .draw(|frame| app.render(frame, Instant::now()))
                .expect("draw must not panic");
        }
    }

    #[test]
    fn tab_motions_work_when_detail_focused() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_code(KeyCode::Tab)); // focus Detail
        assert!(matches!(app.focus, Focus::Detail));
        // `gt` is workspace-global: it switches tabs regardless of pane focus.
        app.handle_event(&key('g'));
        app.handle_event(&key('t'));
        assert_eq!(app.tabs.active_index(), 1, "gt switched to Settings");
    }

    // ---- Phase 4: persistence + pins + recents ----

    #[test]
    fn unlock_defaults_tree_sort_to_recently_used() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        assert_eq!(
            app.tree.sort(),
            crate::widgets::entry_tree::SortOrder::RecentlyUsed,
            "the redesign default sort is RecentlyUsed (T4.3)"
        );
    }

    // T4.3: unlock honours the *persisted* global sort, not the hardcoded
    // `TreeState::new()` default. Injecting a non-default value (Title) proves
    // `reset_secrets_view` reads `ui_config.default_sort()` — the assertion would
    // still pass against either default if we only checked RecentlyUsed.
    #[test]
    fn unlock_applies_persisted_non_default_global_sort() {
        use crate::widgets::entry_tree::SortOrder;
        let (_dir, mut app) = populated_app();
        app.user_config.set_default_sort_for_test(SortOrder::Title);
        unlock(&mut app, PASSWORD);
        assert_eq!(
            app.tree.sort(),
            SortOrder::Title,
            "unlock must honour the persisted global sort"
        );
    }

    // T4.4: pinning an entry persists to tui.toml and survives a lock/unlock.
    #[test]
    fn pin_persists_to_config_and_rehydrates_on_relock() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // Personal (group) → Root1 (entry)
        let pinned = app.tree.selected().expect("an entry is selected");
        app.handle_event(&key('p')); // pin it
        assert!(app.tabs.is_pinned(pinned), "entry is pinned after `p`");

        // The pin reached tui.toml on disk (best-effort persistence).
        let toml_path = config::config_path(&app.paths);
        let on_disk = std::fs::read_to_string(&toml_path).expect("tui.toml written");
        assert!(
            on_disk.contains(&pinned.to_string()),
            "pinned UUID present in tui.toml: {on_disk}"
        );

        // Lock and re-unlock: the pin is hydrated from the persisted config.
        app.handle_event(&key_ctrl('l'));
        app.handle_event(&key(' ')); // lock screen → list
        unlock(&mut app, PASSWORD);
        assert!(
            app.tabs.is_pinned(pinned),
            "pin survived lock/unlock via tui.toml"
        );
    }

    // Regression: pinned-tab body keys were dead (`Tab::Pinned(_) => {}`)
    // while the pane rendered "(Space: reveal)" / "(Shift+H to view)" hints
    // and shared the App's reveal/scroll state. Reveal, history, and detail
    // scrolling must work on a pinned tab.
    #[test]
    fn pinned_tab_reveal_scroll_and_history_keys_work() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // Personal (group) → Root1 (entry)
        let pinned = app.tree.selected().expect("an entry is selected");
        app.handle_event(&key('p')); // pin it
        assert!(app.tabs.is_pinned(pinned));

        // Switch to the pinned tab.
        app.handle_event(&key('g'));
        app.handle_event(&key('t'));
        assert!(
            matches!(app.tabs.active_tab(), Tab::Pinned(u) if u == pinned),
            "gt lands on the pinned tab"
        );

        // Space toggles reveal.
        assert!(!app.reveal_password);
        app.handle_event(&key(' '));
        assert!(app.reveal_password, "Space reveals on a pinned tab");

        // j scrolls the pinned detail body.
        assert_eq!(app.detail_scroll, 0);
        app.handle_event(&key('j'));
        assert_eq!(app.detail_scroll, 1, "j scrolls the pinned detail");
        app.handle_event(&key('k'));
        assert_eq!(app.detail_scroll, 0, "k scrolls back");

        // Shift+H opens the history overlay for the pinned entry.
        app.handle_event(&key('H'));
        assert!(
            matches!(app.overlay, Some(Overlay::History(_))),
            "H opens history on a pinned tab"
        );
    }

    #[test]
    fn unpin_toggles_off_and_persists() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // → Root1 entry
        let uuid = app.tree.selected().unwrap();
        app.handle_event(&key('p')); // pin
        assert!(app.tabs.is_pinned(uuid));
        app.handle_event(&key('p')); // unpin
        assert!(!app.tabs.is_pinned(uuid), "second `p` unpins");
        assert_eq!(app.tabs.pins().len(), 0);
    }

    #[test]
    fn pinning_a_group_is_rejected() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Selection starts on the Personal *group*.
        app.handle_event(&key('p'));
        assert_eq!(app.tabs.pins().len(), 0, "groups are not pinnable");
    }

    // T4.2 / ADR-T5: opening an entry's detail (Enter) bumps it to the front of
    // the recents list and persists.
    #[test]
    fn enter_on_entry_bumps_recents() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // → Root1 entry
        let uuid = app.tree.selected().unwrap();
        assert_eq!(app.recents.rank(uuid), None, "not used yet");
        app.handle_event(&key_code(KeyCode::Enter)); // open detail → bump
        assert_eq!(
            app.recents.rank(uuid),
            Some(0),
            "opened entry is most-recently-used"
        );
        // And it reached tui.toml.
        let on_disk = std::fs::read_to_string(config::config_path(&app.paths)).unwrap();
        assert!(on_disk.contains(&uuid.to_string()), "recents persisted");
    }

    // Point F: the shared reveal/scroll state does not bleed across a tab switch.
    #[test]
    fn switching_tabs_resets_reveal_and_scroll() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // select an entry
        app.handle_event(&key_code(KeyCode::Tab)); // focus detail
        app.handle_event(&key(' ')); // reveal its password
        assert!(app.reveal_password);
        app.handle_event(&key_alt('2')); // → Settings tab
        assert!(!app.reveal_password, "reveal reset on tab switch");
        assert_eq!(app.detail_scroll, 0, "scroll reset on tab switch");
    }

    // A stale pin (entry deleted between sessions) must not crash; hydration
    // drops it so the pinned tab never points at a missing entry.
    #[test]
    fn stale_pin_is_dropped_on_hydrate() {
        let (_dir, mut app) = populated_app();
        // Seed the config with a pin for a UUID that does not exist in the vault.
        let ghost = Uuid::new_v4();
        app.ui_config
            .set_vault_state("personal", vec![ghost], Vec::new());
        unlock(&mut app, PASSWORD);
        assert!(
            !app.tabs.is_pinned(ghost),
            "a pin for a missing entry is dropped on hydrate"
        );
        assert_eq!(app.tabs.pins().len(), 0);
    }

    // ---- Phase 5: action overlays ----

    fn type_str(app: &mut App, s: &str) {
        for c in s.chars() {
            app.handle_event(&key(c));
        }
    }

    fn first_match(app: &App, query: &str) -> Uuid {
        let results = app
            .vault
            .as_ref()
            .unwrap()
            .search(SearchOptions::new(query))
            .unwrap();
        results.first().expect("a search hit").uuid
    }

    #[test]
    fn slash_opens_search_overlay() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('/'));
        assert!(matches!(app.overlay, Some(Overlay::Search(_))));
    }

    // Migrated from the pre-T4.2 `search_filters_and_enter_jumps_to_entry`:
    // the jump-to-entry behavior moved from Enter (now copy, per config) to Tab.
    #[test]
    fn search_filters_and_tab_opens_entry() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('/'));
        type_str(&mut app, "Root1");
        let expected = match app.overlay.as_ref() {
            Some(Overlay::Search(s)) => {
                assert!(!s.results.is_empty(), "query matches Root1");
                s.selected_uuid().unwrap()
            }
            _ => panic!("expected search overlay"),
        };
        app.handle_event(&key_code(KeyCode::Tab));
        assert!(app.overlay.is_none(), "Tab closes search");
        assert_eq!(app.tree.selected(), Some(expected));
        assert!(matches!(app.focus, Focus::Detail));
        assert_eq!(app.recents.rank(expected), Some(0), "jump bumps recents");
    }

    // ---- Journey tests: search → jump → verify selection state ----

    /// Journey: search with zero results → Esc → verify tree selection and
    /// overlay state are unchanged (no side effects from empty search).
    #[test]
    fn search_zero_results_esc_does_not_affect_tree() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let initial_selection = app.tree.selected();
        // Open search, type a query with no matches.
        app.handle_event(&key('/'));
        type_str(&mut app, "zzznonexistentzzz");
        match app.overlay.as_ref() {
            Some(Overlay::Search(s)) => assert!(s.results.is_empty()),
            _ => panic!("expected search overlay"),
        }
        // Cancel with Esc.
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(app.overlay.is_none());
        // Tree selection should be unchanged.
        assert_eq!(app.tree.selected(), initial_selection);
        assert!(matches!(app.focus, Focus::Tree));
    }

    /// Journey: search → Enter on an entry inside a collapsed group → verify
    /// the entry is selected and focus moves to detail (search jump selects
    /// the entry regardless of group expansion state).
    #[test]
    fn search_jump_selects_entry_in_collapsed_group() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Collapse the Personal group.
        app.handle_event(&key('h'));
        let vault = app.vault.as_ref().unwrap();
        let rows_before = entry_tree::build_rows(vault, &app.tree, &app.recents);
        let collapsed_count = rows_before.len();
        // Open search, type "Alpha" (inside Personal group).
        app.handle_event(&key('/'));
        type_str(&mut app, "Alpha");
        let alpha_uuid = match app.overlay.as_ref() {
            Some(Overlay::Search(s)) => {
                assert!(!s.results.is_empty(), "query matches Alpha entry");
                s.selected_uuid().unwrap()
            }
            _ => panic!("expected search overlay"),
        };
        // With default enter-action=copy, Tab is the open action.
        app.handle_event(&key_code(KeyCode::Tab));
        assert!(app.overlay.is_none());
        // The entry is selected and its ancestors are expanded so it is visible.
        assert_eq!(app.tree.selected(), Some(alpha_uuid));
        assert_eq!(app.focus, Focus::Detail);
        let vault = app.vault.as_ref().unwrap();
        let rows_after = entry_tree::build_rows(vault, &app.tree, &app.recents);
        assert!(rows_after.len() > collapsed_count, "ancestor group expands");
        assert!(
            rows_after.iter().any(|row| row.uuid == alpha_uuid),
            "jumped entry is visible in the expanded tree"
        );
    }

    /// Journey: search → jump to entry → change focus to detail → search again
    /// → verify focus stays on Detail (search overlay doesn't reset focus),
    /// and after closing search, focus is unchanged.
    #[test]
    fn search_preserves_focus_across_open_close() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Navigate to an entry and switch focus to detail.
        app.handle_event(&key('j')); // → Root1 entry
        app.handle_event(&key_code(KeyCode::Enter)); // open detail → Focus::Detail
        assert_eq!(app.focus, Focus::Detail);
        // Now open search.
        app.handle_event(&key('/'));
        assert!(matches!(app.overlay, Some(Overlay::Search(_))));
        // Focus stays on Detail (search doesn't reset it).
        assert_eq!(app.focus, Focus::Detail);
        // Type a query and close.
        type_str(&mut app, "Alpha");
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(app.overlay.is_none());
        // Focus should still be Detail after closing search.
        assert_eq!(app.focus, Focus::Detail);
    }

    /// Journey: search → Enter on entry → verify tree selection, detail focus,
    /// and that the entry's vault data matches (round-trip through the state
    /// machine).
    #[test]
    fn search_jump_verifies_vault_entry_matches_selection() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Open search and find "Bravo".
        app.handle_event(&key('/'));
        type_str(&mut app, "Bravo");
        let expected_uuid = match app.overlay.as_ref() {
            Some(Overlay::Search(s)) => s.selected_uuid().unwrap(),
            _ => panic!("expected search overlay"),
        };
        // Verify the vault contains an entry with this UUID and title "Bravo".
        {
            let vault = app.vault.as_ref().unwrap();
            let entry = vault.get_entry(expected_uuid).unwrap();
            assert_eq!(entry.title(), "Bravo");
        }
        // With default enter-action=copy, Tab is the open action.
        app.handle_event(&key_code(KeyCode::Tab));
        assert!(app.overlay.is_none());
        // Verify tree selection matches the searched entry.
        assert_eq!(app.tree.selected(), Some(expected_uuid));
        // Verify focus moved to Detail.
        assert_eq!(app.focus, Focus::Detail);
        // Verify the detail pane shows the correct entry.
        let vault = app.vault.as_ref().unwrap();
        let entry = vault.get_entry(expected_uuid).unwrap();
        assert_eq!(entry.title(), "Bravo");
    }

    #[test]
    fn add_overlay_saves_new_entry() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('a'));
        assert!(matches!(app.overlay, Some(Overlay::Edit(_))));
        // Kind (focus 0) → Title, then type the title and save.
        app.handle_event(&key_code(KeyCode::Tab));
        type_str(&mut app, "NewEntry");
        app.handle_event(&key_ctrl('s'));
        assert!(app.overlay.is_none(), "save closes the overlay");
        let uuid = first_match(&app, "NewEntry");
        assert_eq!(
            app.vault.as_ref().unwrap().get_entry(uuid).unwrap().title(),
            "NewEntry"
        );
        assert_eq!(app.tree.selected(), Some(uuid), "new entry selected");
        assert_eq!(app.recents.rank(uuid), Some(0), "new entry in recents");
    }

    // Regression: a failed `vault.save()` after a successful add left the
    // form in "add" mode, so retrying Ctrl+S inserted a duplicate entry
    // under a fresh UUID. The retry must update the already-added entry.
    #[cfg(unix)]
    #[test]
    fn failed_save_after_add_does_not_duplicate_on_retry() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('a'));
        app.handle_event(&key_code(KeyCode::Tab)); // Kind → Title
        type_str(&mut app, "RetryMe");

        // Make the save fail: the vault's directory refuses new files, so
        // the atomic write's temp-file creation errors out.
        let dir_path = dir.path();
        std::fs::set_permissions(dir_path, std::fs::Permissions::from_mode(0o555))
            .expect("make dir read-only");
        app.handle_event(&key_ctrl('s'));
        std::fs::set_permissions(dir_path, std::fs::Permissions::from_mode(0o755))
            .expect("restore dir permissions");

        match app.overlay.as_ref() {
            Some(Overlay::Edit(s)) => {
                assert!(s.error.is_some(), "failed save surfaces an error");
                assert!(
                    s.target.is_some(),
                    "the added entry is recorded as the form's target"
                );
            }
            _ => panic!("overlay must stay open after a failed save"),
        }

        // Retry now that the disk cooperates.
        app.handle_event(&key_ctrl('s'));
        assert!(app.overlay.is_none(), "retried save closes the overlay");

        let vault = app.vault.as_ref().unwrap();
        let matches: Vec<_> = vault
            .database()
            .iter_all_entries()
            .filter(|e| {
                e.get(falach_core::fields::TITLE)
                    .is_some_and(|t| t == "RetryMe")
            })
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "retrying a failed add must not duplicate the entry"
        );
    }

    #[test]
    fn add_overlay_rejects_empty_title() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('a'));
        app.handle_event(&key_ctrl('s')); // no title typed
        match app.overlay.as_ref() {
            Some(Overlay::Edit(s)) => assert!(s.error.is_some(), "empty title is rejected"),
            _ => panic!("overlay should stay open on validation error"),
        }
    }

    #[test]
    fn edit_overlay_updates_entry_and_appends_history() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // → Root1 entry
        let uuid = app.tree.selected().unwrap();
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(uuid)
                .unwrap()
                .history()
                .len(),
            0
        );
        app.handle_event(&key('e'));
        assert!(matches!(app.overlay, Some(Overlay::Edit(_))));
        // Title is the first field for an edit (no Kind row); append a char.
        type_str(&mut app, "Z");
        app.handle_event(&key_ctrl('s'));
        assert!(app.overlay.is_none());
        let view = app.vault.as_ref().unwrap();
        let entry = view.get_entry(uuid).unwrap();
        assert!(entry.title().contains('Z'), "title was edited");
        assert_eq!(entry.history().len(), 1, "one history snapshot appended");
    }

    #[test]
    fn delete_confirm_removes_entry_recents_and_unpins() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // → Root1 entry
        let uuid = app.tree.selected().unwrap();
        app.handle_event(&key('p')); // pin it
        app.handle_event(&key_code(KeyCode::Enter)); // open detail → bump recents
        assert!(app.tabs.is_pinned(uuid));
        assert_eq!(app.recents.rank(uuid), Some(0));
        // Delete: `d` then confirm `y`.
        app.handle_event(&key('d'));
        assert!(matches!(app.overlay, Some(Overlay::ConfirmDelete { .. })));
        app.handle_event(&key('y'));
        assert!(app.overlay.is_none());
        assert_eq!(app.recents.rank(uuid), None, "delete removes from recents");
        assert!(!app.tabs.is_pinned(uuid), "delete unpins the tab");
        // No longer present in the visible tree (moved to the skipped Recycle Bin).
        let rows = entry_tree::build_rows(app.vault.as_ref().unwrap(), &app.tree, &app.recents);
        assert!(!rows.iter().any(|r| r.uuid == uuid));
    }

    // ---- Journey tests: confirm-delete → verify removal ----

    /// Journey: delete entry → y → verify the entry is no longer in the
    /// visible tree (moved to Recycle Bin, not permanently removed from vault).
    #[test]
    fn delete_confirm_verifies_entry_removed_from_tree() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Navigate to Root1 (j from Personal → Root1, since Personal is collapsed).
        app.handle_event(&key('j'));
        app.handle_event(&key('j'));
        let target_uuid = app.tree.selected().unwrap();
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(target_uuid)
                .unwrap()
                .title(),
            "Root1"
        );
        // Delete it.
        app.handle_event(&key('d'));
        app.handle_event(&key('y'));
        assert!(app.overlay.is_none());
        // The entry should not appear in the visible tree rows (moved to Recycle Bin).
        let vault = app.vault.as_ref().unwrap();
        let rows = entry_tree::build_rows(vault, &app.tree, &app.recents);
        assert!(
            !rows.iter().any(|r| r.uuid == target_uuid),
            "deleted entry should not appear in tree rows"
        );
    }

    /// Journey: delete entry → `n` → verify the confirmation is cancelled and
    /// the entry survives in both the vault and the visible tree. Covers the
    /// `'n' | 'N' | Esc` cancel arm of `on_confirm_delete_key` (the `y` confirm
    /// path is covered by `delete_confirm_verifies_entry_removed_from_tree`).
    #[test]
    fn delete_confirm_n_cancels() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Navigate to Root1 (j past the collapsed Personal group; the second j
        // clamps at the last row).
        app.handle_event(&key('j'));
        app.handle_event(&key('j'));
        let target_uuid = app.tree.selected().unwrap();
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(target_uuid)
                .unwrap()
                .title(),
            "Root1"
        );
        // Open the delete confirmation, then cancel with `n`.
        app.handle_event(&key('d'));
        assert!(matches!(app.overlay, Some(Overlay::ConfirmDelete { .. })));
        app.handle_event(&key('n'));
        assert!(app.overlay.is_none(), "n closes the confirmation");
        // The entry survives in the vault and remains in the visible tree.
        let vault = app.vault.as_ref().unwrap();
        assert!(
            vault.get_entry(target_uuid).is_ok(),
            "cancelled delete leaves the entry intact"
        );
        let rows = entry_tree::build_rows(vault, &app.tree, &app.recents);
        assert!(
            rows.iter().any(|r| r.uuid == target_uuid),
            "entry still present in tree after cancel"
        );
    }

    /// Journey: delete an entry in an expanded group → verify tree selection
    /// moves off the deleted node to another valid node. (Personal starts
    /// collapsed; `l` expands it, then two `j` presses land on the last entry,
    /// Bravo, which is then deleted.)
    #[test]
    fn delete_entry_moves_selection_off_deleted_node() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Expand Personal to see Alpha and Bravo.
        app.handle_event(&key('l'));
        // Navigate to the last entry in Personal (Bravo).
        app.handle_event(&key('j'));
        app.handle_event(&key('j'));
        let deleted_uuid = app.tree.selected().unwrap();
        // Delete it.
        app.handle_event(&key('d'));
        app.handle_event(&key('y'));
        assert!(app.overlay.is_none());
        // Selection should have moved to another valid node, not the deleted one.
        let new_selection = app.tree.selected();
        assert!(
            new_selection.is_some(),
            "selection should move to a valid node"
        );
        assert_ne!(
            new_selection,
            Some(deleted_uuid),
            "selection should not stay on deleted entry"
        );
    }

    /// Journey: delete + y → verify the entry is removed from recents
    /// and the tree row count decreases.
    #[test]
    fn delete_removes_from_recents_and_tree_rows() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Navigate to Root1 (j from Personal → Root1, since Personal is collapsed).
        app.handle_event(&key('j'));
        app.handle_event(&key('j'));
        let target_uuid = app.tree.selected().unwrap();
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(target_uuid)
                .unwrap()
                .title(),
            "Root1"
        );
        // Open detail to bump it into recents.
        app.handle_event(&key_code(KeyCode::Enter));
        assert_eq!(app.recents.rank(target_uuid), Some(0));
        // Delete it.
        app.handle_event(&key('d'));
        app.handle_event(&key('y'));
        // Verify it's removed from recents.
        assert_eq!(app.recents.rank(target_uuid), None);
        // Verify tree rows decreased.
        let vault = app.vault.as_ref().unwrap();
        let rows = entry_tree::build_rows(vault, &app.tree, &app.recents);
        assert!(
            !rows.iter().any(|r| r.uuid == target_uuid),
            "deleted entry should not appear in tree rows"
        );
    }

    #[test]
    fn copy_password_and_username_via_recording_sink() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let sink = crate::clipboard::RecordingClipboard::new();
        let log = sink.log.clone();
        app.set_clipboard(Box::new(sink));
        app.handle_event(&key('j')); // → Root1 (username alice / password s3cr3t)
        let uuid = app.tree.selected().unwrap();
        app.handle_event(&key('c')); // copy password
        {
            let l = log.borrow();
            assert_eq!(l.copies, 1);
            assert_eq!(l.last.as_ref().unwrap().0, "s3cr3t");
        }
        assert_eq!(app.recents.rank(uuid), Some(0), "copy bumps recents");
        app.handle_event(&key('C')); // copy username
        assert_eq!(log.borrow().last.as_ref().unwrap().0, "alice");
    }

    #[test]
    fn copy_on_a_group_reports_no_entry() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Selection starts on the Personal group.
        let sink = crate::clipboard::RecordingClipboard::new();
        let log = sink.log.clone();
        app.set_clipboard(Box::new(sink));
        app.handle_event(&key('c'));
        assert_eq!(log.borrow().copies, 0, "no copy without a selected entry");
    }

    #[test]
    fn generate_panel_fills_password() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('a')); // add overlay (credential)
        app.handle_event(&key_ctrl('g')); // open generate panel
        match app.overlay.as_ref() {
            Some(Overlay::Edit(s)) => assert!(s.generating.is_some()),
            _ => panic!("expected edit overlay"),
        }
        app.handle_event(&key_code(KeyCode::Enter)); // accept → fill password
        match app.overlay.as_ref() {
            Some(Overlay::Edit(s)) => {
                assert!(s.generating.is_none(), "panel closed on accept");
                assert!(
                    !s.password.as_str().is_empty(),
                    "password filled from preview"
                );
            }
            _ => panic!("expected edit overlay"),
        }
    }

    #[test]
    fn history_overlay_opens_and_esc_closes() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // → Root1
        app.handle_event(&key('H')); // history
        assert!(matches!(app.overlay, Some(Overlay::History(_))));
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(app.overlay.is_none());
    }

    // Zeroize-on-lock: a lock while an overlay is open clears it (dropping its
    // secret-bearing buffers) — the App invariant the advisor flagged.
    #[test]
    fn lock_clears_open_overlay() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('a')); // open edit overlay
        assert!(app.overlay.is_some());
        app.handle_event(&key_ctrl('l')); // lock
        assert!(matches!(app.phase, Phase::LockScreen));
        assert!(app.overlay.is_none(), "lock drops the overlay (zeroize)");
    }

    // Idle auto-lock also clears the overlay (same buffers, via tick→lock_app).
    #[test]
    fn idle_lock_clears_open_overlay() {
        let (_dir, mut app) = fixture_app(&["personal"], Duration::from_secs(1));
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('a'));
        assert!(app.overlay.is_some());
        let t0 = Instant::now();
        app.tick(t0 + Duration::from_millis(1_100));
        app.tick(t0 + Duration::from_millis(1_200));
        assert!(matches!(app.phase, Phase::LockScreen));
        assert!(app.overlay.is_none());
    }

    fn edit_values(kind: EntryKind, title: &str) -> EditValues {
        EditValues {
            kind,
            title: title.to_string(),
            username: String::new(),
            password: falach_core::Zeroizing::new(String::new()),
            url: String::new(),
            totp_uri: falach_core::Zeroizing::new(String::new()),
            notes: String::new(),
            tags: Vec::new(),
            custom: Vec::new(),
            removed_custom: Vec::new(),
        }
    }

    // The "full field set" the maintainer asked for: a credential with a custom
    // field round-trips through apply_add, and a TOTP entry is created from a
    // valid otpauth URI.
    #[test]
    fn apply_add_round_trips_custom_fields_and_totp() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let group = app.vault.as_ref().unwrap().root_group_uuid();

        let mut values = edit_values(EntryKind::Credential, "WithCustom");
        values.custom = vec![(
            "API".to_string(),
            falach_core::Zeroizing::new("k1".to_string()),
            false,
        )];
        let uuid = App::apply_add(app.vault.as_mut().unwrap(), group, &values).unwrap();
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(uuid)
                .unwrap()
                .custom_field("API"),
            Some("k1")
        );

        let mut totp = edit_values(EntryKind::Totp, "TotpEntry");
        totp.totp_uri = falach_core::Zeroizing::new(
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP".to_string(),
        );
        let tu = App::apply_add(app.vault.as_mut().unwrap(), group, &totp).unwrap();
        assert_eq!(
            app.vault.as_ref().unwrap().get_entry(tu).unwrap().kind(),
            EntryKind::Totp
        );
    }

    // apply_update sets a new custom field and later removes it (the
    // `removed_custom` path / ADR-T5 custom-field editing).
    #[test]
    fn apply_update_sets_then_removes_custom_field() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // → Root1
        let uuid = app.tree.selected().unwrap();

        let mut add = edit_values(EntryKind::Credential, "Root1");
        add.username = "alice".to_string();
        add.password = falach_core::Zeroizing::new("s3cr3t".to_string());
        add.custom = vec![(
            "API".to_string(),
            falach_core::Zeroizing::new("k1".to_string()),
            false,
        )];
        App::apply_update(app.vault.as_mut().unwrap(), uuid, &add).unwrap();
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(uuid)
                .unwrap()
                .custom_field("API"),
            Some("k1")
        );

        let mut remove = edit_values(EntryKind::Credential, "Root1");
        remove.username = "alice".to_string();
        remove.removed_custom = vec!["API".to_string()];
        App::apply_update(app.vault.as_mut().unwrap(), uuid, &remove).unwrap();
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .get_entry(uuid)
                .unwrap()
                .custom_field("API"),
            None,
            "removed_custom drops the field"
        );
    }

    // PMF-5: `from_entry` seeds each custom row's protectedness from the loaded
    // entry, and `snapshot()` preserves it into `EditValues.custom`.
    #[test]
    fn from_entry_seeds_and_snapshot_preserves_custom_field_protectedness() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let group = app.vault.as_ref().unwrap().root_group_uuid();
        let uuid = app
            .vault
            .as_mut()
            .unwrap()
            .add_entry(
                group,
                EntryBuilder::credential("Secrets")
                    .custom_field("PIN", "4242", true) // protected
                    .custom_field("Note", "memo", false) // not protected
                    .build(),
            )
            .unwrap();

        let view = app.vault.as_ref().unwrap().get_entry(uuid).unwrap();
        let state = EditState::from_entry(uuid, &view);
        let pin = state
            .custom
            .iter()
            .find(|r| r.name.value() == "PIN")
            .expect("PIN row");
        let note = state
            .custom
            .iter()
            .find(|r| r.name.value() == "Note")
            .expect("Note row");
        assert!(pin.protected, "protected field seeds protected=true");
        assert!(!note.protected, "unprotected field seeds protected=false");

        let values = state.snapshot().expect("valid snapshot");
        let pin_v = values
            .custom
            .iter()
            .find(|(n, _, _)| n == "PIN")
            .expect("PIN value");
        let note_v = values
            .custom
            .iter()
            .find(|(n, _, _)| n == "Note")
            .expect("Note value");
        assert!(pin_v.2, "snapshot preserves protected=true");
        assert!(!note_v.2, "snapshot preserves protected=false");
    }

    // PMF-5 regression: editing an entry through the real load → snapshot →
    // apply_update path must preserve a protected custom field's flag (the
    // write site used to hardcode `false`, silently demoting it and breaking
    // PMF-1's detail mask).
    #[test]
    fn apply_update_preserves_protected_custom_field_through_round_trip() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let group = app.vault.as_ref().unwrap().root_group_uuid();
        let uuid = app
            .vault
            .as_mut()
            .unwrap()
            .add_entry(
                group,
                EntryBuilder::credential("Secrets")
                    .custom_field("PIN", "4242", true)
                    .custom_field("Note", "memo", false)
                    .build(),
            )
            .unwrap();

        // The edit the user would make: open the form, change nothing, save.
        let values = {
            let view = app.vault.as_ref().unwrap().get_entry(uuid).unwrap();
            EditState::from_entry(uuid, &view)
                .snapshot()
                .expect("snapshot")
        };
        App::apply_update(app.vault.as_mut().unwrap(), uuid, &values).unwrap();

        let view = app.vault.as_ref().unwrap().get_entry(uuid).unwrap();
        assert_eq!(
            view.custom_field_is_protected("PIN"),
            Some(true),
            "a protected custom field must survive edit→save as protected (PMF-5)"
        );
        assert_eq!(
            view.custom_field_is_protected("Note"),
            Some(false),
            "an unprotected field stays unprotected"
        );
    }

    // Highest-leverage render test (design R-1/R-5): draw every overlay variant
    // over the workspace across terminal sizes, including degenerate ones, to
    // prove the modal layout / caret / indexing arithmetic never panics. Mirrors
    // `workspace_renders_without_panic_across_sizes` but with overlays set.
    #[test]
    fn overlays_render_without_panic_across_sizes() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        // Each opener drives a fresh unlocked app into one overlay variant the
        // way a user would, so the render path matches real state.
        let openers: [fn(&mut App); 7] = [
            |app| app.handle_event(&key('?')), // Help (T7.2)
            |app| {
                app.handle_event(&key('/'));
                type_str(app, "a"); // a query with results → list branch
            },
            |app| app.handle_event(&key('a')), // Edit (add)
            |app| {
                app.handle_event(&key('a'));
                app.handle_event(&key_ctrl('g')); // nested Generate panel
            },
            |app| {
                app.handle_event(&key('j'));
                app.handle_event(&key('e')); // Edit (existing)
            },
            |app| {
                // Create a history snapshot, then open the (non-empty) viewer.
                app.handle_event(&key('j'));
                app.handle_event(&key('e'));
                type_str(app, "x");
                app.handle_event(&key_ctrl('s'));
                app.handle_event(&key('H'));
            },
            |app| {
                app.handle_event(&key('j'));
                app.handle_event(&key('d')); // ConfirmDelete
            },
        ];
        for open in openers {
            let (_dir, mut app) = populated_app();
            unlock(&mut app, PASSWORD);
            open(&mut app);
            assert!(app.overlay.is_some(), "opener left an overlay open");
            for (w, h) in [(80u16, 24u16), (40, 12), (10, 5), (1, 1)] {
                let mut terminal = Terminal::new(TestBackend::new(w, h)).expect("backend");
                terminal
                    .draw(|frame| app.render(frame, Instant::now()))
                    .expect("overlay draw must not panic");
            }
        }
    }

    // ---- Palette (T2.3) — the executable help/palette (replaces the read-only
    // Help overlay). `?` IS the palette (D-3). ----

    #[test]
    fn palette_opens_on_question_mark_and_esc_closes() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('?'));
        assert!(
            matches!(app.overlay, Some(Overlay::Palette(_))),
            "? opens the palette"
        );
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(app.overlay.is_none(), "Esc closes the palette");
    }

    #[test]
    fn palette_question_mark_types_into_filter() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('?')); // opens
        app.handle_event(&key('?')); // typed into the filter, palette stays open
        match &app.overlay {
            Some(Overlay::Palette(state)) => {
                assert_eq!(state.filter(), "?", "the second ? edits the filter");
            }
            _ => panic!("palette stays open with the char in its filter"),
        }
    }

    #[test]
    fn palette_selection_moves_with_arrows() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('?'));
        // Up at the top is a clamped no-op; Down then advances the selection.
        app.handle_event(&key_code(KeyCode::Up));
        match &app.overlay {
            Some(Overlay::Palette(s)) => assert_eq!(s.selected, 0, "selection clamps at the top"),
            _ => panic!("palette open"),
        }
        app.handle_event(&key_code(KeyCode::Down));
        match &app.overlay {
            Some(Overlay::Palette(s)) => assert_eq!(s.selected, 1, "Down advances the selection"),
            _ => panic!("palette open"),
        }
    }

    #[test]
    fn ctrl_l_locks_from_palette() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('?'));
        // Globals are dispatched before the overlay layer, so Ctrl+L still locks.
        app.handle_event(&key_ctrl('l'));
        assert!(matches!(app.phase, Phase::LockScreen));
        assert!(app.overlay.is_none(), "lock clears the palette overlay");
    }

    #[test]
    fn palette_opens_from_settings_tab() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_alt('2')); // → Settings tab
        assert!(matches!(app.tabs.active_tab(), Tab::Settings));
        app.handle_event(&key('?'));
        assert!(
            matches!(app.overlay, Some(Overlay::Palette(_))),
            "the palette is workspace-global, not Secrets-only"
        );
    }

    // ---- Phase 6: sync + Settings ----

    use crate::screens::settings;
    use crate::sync_runtime::SyncEngine;
    use falach_sync::{CredentialSource, EntryDelta, S3Config, Sync, SyncError, SyncOutcome};
    use std::sync::Arc;

    /// A fake engine returning a fixed `AlreadyInSync` (enough to exercise the
    /// App-side start/teardown; outcome handling is tested directly via
    /// `integrate_sync_result`).
    struct AlreadyInSyncEngine;
    impl SyncEngine for AlreadyInSyncEngine {
        fn sync_now(
            &self,
            _vault: &mut Vault,
            _vault_name: &str,
            _registry: &mut VaultRegistry,
            _master_password: &MasterPassword,
            _opts: falach_sync::SyncOptions,
        ) -> Result<SyncOutcome, SyncError> {
            Ok(SyncOutcome::AlreadyInSync)
        }
    }

    /// Configure an S3 sync target on the app's registry using `EnvVars`
    /// credentials (no encryption needed — keeps the helper simple). The target
    /// is persisted to `vaults.toml`, so `sync_configured()` becomes true.
    fn configure_target(app: &mut App, vault_name: &str) {
        let s3 = S3Config::new(
            "bkt".to_string(),
            "v.kdbx".to_string(),
            "us-east-1".to_string(),
            CredentialSource::EnvVars {
                prefix: "TEST_".to_string(),
            },
        );
        let mp = MasterPassword::new(PASSWORD.to_string());
        Sync::configure_remote(app.registry.as_mut().unwrap(), vault_name, s3, &mp)
            .expect("configure target");
    }

    /// Take the app's vault + registry out and feed them back through
    /// `integrate_sync_result` with the given outcome + trigger — the threading
    /// is bypassed (the advisor's "test the reintegration logic synchronously"
    /// guidance).
    fn integrate(app: &mut App, outcome: Result<SyncOutcome, SyncError>, trigger: SyncTrigger) {
        let vault = app.vault.take().expect("vault present");
        let registry = app.registry.take().expect("registry present");
        app.integrate_sync_result(
            SyncResult {
                vault,
                registry,
                outcome,
                trigger,
            },
            Instant::now(),
        );
    }

    #[test]
    fn settings_row_count_matches_labels() {
        assert_eq!(SETTINGS_ROW_COUNT, settings::ROW_LABELS.len());
    }

    #[test]
    fn settings_renderer_adopts_editor_and_status_border_slots() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let (_dir, app) = populated_app();
        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal
            .draw(|frame| crate::screens::settings::render(&app, frame, frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let editor = buffer.cell((0, 0)).unwrap().style();
        let status = buffer.cell((0, 12)).unwrap().style();
        if let Some(expected) = app.theme.border_focused().fg {
            assert_eq!(editor.fg, Some(expected));
        }
        assert!(editor
            .add_modifier
            .contains(app.theme.border_focused().add_modifier));
        if let Some(expected) = app.theme.border().fg {
            assert_eq!(status.fg, Some(expected));
        }
        assert!(status
            .add_modifier
            .contains(app.theme.border().add_modifier));
    }

    #[test]
    fn settings_toggle_sync_on_unlock_persists() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_alt('2')); // → Settings tab
        assert!(matches!(app.tabs.active_tab(), Tab::Settings));
        // Rows: 0 Default sort, 1 Theme, 2 Auto-lock, 3 Auto-sync on unlock.
        for _ in 0..3 {
            app.handle_event(&key('j'));
        }
        assert_eq!(app.settings_index, 3);
        assert!(!app.user_config.sync_on_unlock());
        app.handle_event(&key_code(KeyCode::Enter)); // toggle on
        assert!(
            app.user_config.sync_on_unlock(),
            "Enter toggles the setting"
        );
        // Prefs now persist to config.toml (T3.1), not tui.toml.
        let on_disk = std::fs::read_to_string(app.paths.config_toml()).unwrap();
        assert!(on_disk.contains("sync-on-unlock = true"), "{on_disk}");
    }

    #[test]
    fn settings_enter_on_first_row_cycles_default_sort() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_alt('2')); // → Settings
        let before = app.user_config.default_sort();
        app.handle_event(&key_code(KeyCode::Enter)); // cycle default sort
        assert_ne!(before, app.user_config.default_sort());
    }

    #[test]
    fn settings_theme_cycle_and_persist() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_alt('2')); // → Settings
        app.handle_event(&key('j')); // row 0 → row 1 (Theme)
        assert_eq!(app.settings_index, 1);

        let before = app.current_theme_name().to_string();
        app.handle_event(&key_code(KeyCode::Enter)); // cycle theme
        let after = app.current_theme_name().to_string();
        assert_ne!(before, after, "Enter cycles the theme to a new name");
        assert!(
            app.theme.name == after || app.theme.name == "accessible",
            "runtime uses the selected theme unless accessibility forcing wins"
        );

        // Persisted to config.toml (the fixture env is dark, so the dark slot).
        let (persisted, warnings) = UserConfig::load(&app.paths);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(persisted.theme.dark, after);
    }

    #[test]
    fn autolock_row_shows_current_value() {
        // The Settings row reflects the vault's configured idle timeout.
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // No override yet → the default (600s = 10 min).
        assert_eq!(app.current_auto_lock_seconds(), 600);
    }

    #[test]
    fn settings_autolock_cycle_saves_and_rearms() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_alt('2')); // → Settings
        app.handle_event(&key('j')); // → row 1 (Theme)
        app.handle_event(&key('j')); // → row 2 (Auto-lock)
        assert_eq!(app.settings_index, 2);

        // Default 600s (10 min); Enter cycles to the next value (15 min = 900s).
        assert_eq!(app.current_auto_lock_seconds(), 600);
        app.handle_event(&key_code(KeyCode::Enter));
        assert_eq!(
            app.current_auto_lock_seconds(),
            900,
            "cycled to the next timeout"
        );

        // Persisted to vaults.toml (via the core write path) — reload proves it.
        let reloaded =
            falach_core::VaultRegistry::load(app.paths.clone()).expect("reload registry");
        let vault = reloaded.get("personal").expect("vault present");
        assert_eq!(
            falach_security::vault_lock::VaultLockConfig::idle_timeout_seconds_from_extra(
                &vault.extra
            ),
            Some(900),
            "the new timeout persisted to vaults.toml"
        );

        // The live controller was re-armed with the new deadline: its
        // time-until-lock reflects ~900s, not the old 600s.
        let remaining = app
            .controller
            .time_until_lock(Instant::now())
            .expect("armed controller has a deadline");
        assert!(
            remaining > Duration::from_secs(600),
            "controller re-armed to the longer 900s timeout, got {remaining:?}"
        );
    }

    #[test]
    fn settings_save_failure_keeps_config_state_and_reports_error() {
        let (dir, mut app) = populated_app();
        let bad_path = dir.path().join("config-is-a-directory");
        std::fs::create_dir(&bad_path).unwrap();
        app.user_config_path = bad_path;
        let before = app.user_config.default_sort();
        app.settings_index = 0;
        app.activate_settings_row();
        assert_eq!(app.user_config.default_sort(), before);
        assert_eq!(
            app.status_bar.current_severity(),
            Some(crate::widgets::status_bar::Severity::Error)
        );
        assert!(app.status_bar.current().unwrap().contains("Could not read"));
    }

    #[test]
    fn custom_config_path_drives_generation_display_and_settings_save() {
        let (dir, mut app) = populated_app();
        let custom = dir.path().join("custom/falach.toml");
        let args = Args {
            config: Some(custom.clone()),
            ..Args::default()
        };
        app.apply_args(&args).expect("apply custom config");
        assert!(custom.exists());
        assert_eq!(app.config_file_display(), custom.display().to_string());
        app.settings_index = 0;
        app.activate_settings_row();
        let written = std::fs::read_to_string(&custom).expect("custom config saved");
        assert!(written.contains("default-sort"));
        assert!(
            !app.paths.config_toml().exists(),
            "default path was not written"
        );
    }

    #[test]
    fn malformed_user_theme_is_parsed_lazily_with_path_and_line_notice() {
        let (_dir, app) = populated_app();
        let themes = app.paths.config_dir().join("themes");
        std::fs::create_dir_all(&themes).unwrap();
        let path = themes.join("broken.toml");
        std::fs::write(&path, "accent = \"#ffffff\"\ninvalid = [\n").unwrap();
        let (found, notices) = theme::discover_user_themes(&themes);
        assert_eq!(found.len(), 1);
        assert!(notices.is_empty());
        let mut cfg = app.user_config.theme.clone();
        cfg.mode = crate::user_config::ThemeMode::Dark;
        cfg.dark = "broken".to_string();
        let (_theme, notices) = theme::resolve_theme(EnvParts::default(), &cfg, None, &found);
        assert_eq!(notices.len(), 1);
        assert!(notices[0].message.contains(&path.display().to_string()));
        assert!(notices[0].message.contains("line "));
        assert!(
            !notices[0].message.contains("invalid"),
            "theme contents stay private"
        );
    }

    #[test]
    fn autolock_save_failure_keeps_registry_and_controller_state() {
        let (_dir, mut app) = populated_app();
        app.selected_vault = Some("personal".to_string());
        let observed_at = Instant::now();
        app.controller.unlock(observed_at);
        let deadline_before = app.controller.time_until_lock(observed_at);
        let path = app.paths.vaults_toml();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        app.set_auto_lock(900);
        assert_eq!(app.current_auto_lock_seconds(), 600);
        assert_eq!(app.controller.time_until_lock(observed_at), deadline_before);
        assert_eq!(
            app.status_bar.current_severity(),
            Some(crate::widgets::status_bar::Severity::Error)
        );
        assert!(app
            .status_bar
            .current()
            .unwrap()
            .contains("Could not save auto-lock"));
    }

    #[test]
    fn vault_flag_unknown_errors_cleanly() {
        // `--vault NAME` for an unregistered vault must return a clean
        // `UnknownVault` error naming the vault (surfaced pre-terminal), never
        // panic (T3.2).
        let (_dir, mut app) = populated_app();
        let args = Args {
            vault: Some("does-not-exist".to_string()),
            ..Args::default()
        };
        match app.apply_args(&args) {
            Err(TuiError::UnknownVault(name)) => assert_eq!(name, "does-not-exist"),
            other => panic!("expected UnknownVault, got {other:?}"),
        }
    }

    #[test]
    fn vault_flag_known_opens_unlock_prompt() {
        // The fast path: a registered `--vault NAME` jumps straight to that
        // vault's unlock prompt.
        let (_dir, mut app) = populated_app();
        let args = Args {
            vault: Some("personal".to_string()),
            ..Args::default()
        };
        app.apply_args(&args).expect("known vault applies");
        assert!(
            matches!(&app.phase, Phase::UnlockPrompt { vault_name, .. } if vault_name == "personal"),
            "known --vault must open its unlock prompt"
        );
        assert_eq!(app.selected_vault.as_deref(), Some("personal"));
    }

    #[test]
    fn request_sync_without_target_shows_status_no_overlay() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('s')); // manual sync, but nothing configured
        assert!(app.overlay.is_none(), "no overlay without a target");
    }

    #[test]
    fn manual_sync_with_target_opens_unlock_overlay() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        configure_target(&mut app, "personal");
        app.handle_event(&key('s'));
        assert!(
            matches!(
                app.overlay,
                Some(Overlay::SyncUnlock {
                    pending: SyncTrigger::Manual,
                    ..
                })
            ),
            "manual sync re-prompts the master password"
        );
    }

    #[test]
    fn sync_unlock_submit_starts_background_sync() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        configure_target(&mut app, "personal");
        app.set_sync_engine(Arc::new(AlreadyInSyncEngine));
        app.handle_event(&key('s')); // open SyncUnlock
        type_str(&mut app, PASSWORD);
        app.handle_event(&key_code(KeyCode::Enter)); // submit → start
                                                     // We deliberately do NOT drain, so the in-flight handle stays set.
        assert!(app.is_syncing(), "submit moves the vault to the worker");
        assert!(app.vault.is_none(), "vault is owned by the worker mid-sync");
        assert!(app.overlay.is_none(), "the unlock overlay closed on submit");
    }

    // ---- Journey tests: sync unlock overlay error paths ----

    /// Journey: sync unlock → wrong password → submit → verify overlay closes
    /// and sync starts (password validation happens during sync, not at unlock).
    #[test]
    fn sync_unlock_submits_regardless_of_password_correctness() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        configure_target(&mut app, "personal");
        app.set_sync_engine(Arc::new(AlreadyInSyncEngine));
        app.handle_event(&key('s')); // open SyncUnlock
                                     // Type wrong password and submit.
        type_str(&mut app, "wrong-password");
        app.handle_event(&key_code(KeyCode::Enter));
        // Overlay closes on submit (password validation is deferred to sync).
        assert!(app.overlay.is_none(), "overlay closes on submit");
        // Sync starts (the engine will fail with wrong password, but that's
        // handled by the sync runtime, not the unlock overlay).
        assert!(app.is_syncing(), "sync starts regardless of password");
    }

    /// Journey: sync unlock → Esc → verify overlay closes and no sync starts.
    #[test]
    fn sync_unlock_esc_closes_overlay_no_sync() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        configure_target(&mut app, "personal");
        app.handle_event(&key('s')); // open SyncUnlock
        assert!(
            matches!(app.overlay, Some(Overlay::SyncUnlock { .. })),
            "should be on SyncUnlock overlay"
        );
        // Cancel with Esc.
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(app.overlay.is_none(), "Esc closes the overlay");
        assert!(!app.is_syncing(), "no sync started");
    }

    #[test]
    fn auto_sync_on_unlock_when_enabled_and_configured() {
        let (_dir, mut app) = populated_app();
        // Configure the target on the registry before unlocking.
        unlock(&mut app, PASSWORD);
        configure_target(&mut app, "personal");
        app.user_config.set_sync_on_unlock(true);
        app.set_sync_engine(Arc::new(AlreadyInSyncEngine));
        // Lock and re-unlock: the auto-trigger fires.
        app.handle_event(&key_ctrl('l'));
        app.handle_event(&key(' '));
        unlock(&mut app, PASSWORD);
        assert!(
            app.is_syncing(),
            "auto-sync-on-unlock kicked a background sync"
        );
    }

    #[test]
    fn no_auto_sync_on_unlock_when_toggle_off() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        configure_target(&mut app, "personal");
        // Toggle stays off (default).
        app.set_sync_engine(Arc::new(AlreadyInSyncEngine));
        app.handle_event(&key_ctrl('l'));
        app.handle_event(&key(' '));
        unlock(&mut app, PASSWORD);
        assert!(!app.is_syncing(), "no auto-sync with the toggle off");
    }

    #[test]
    fn integrate_success_restores_vault_and_surfaces_outcome() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        integrate(
            &mut app,
            Ok(SyncOutcome::Merged {
                delta: EntryDelta {
                    added: vec![Uuid::new_v4()],
                    removed: Vec::new(),
                    modified: vec![Uuid::new_v4(), Uuid::new_v4()],
                },
                attempts: 1,
            }),
            SyncTrigger::Manual,
        );
        assert!(app.vault.is_some(), "vault handed back on success");
        assert!(matches!(app.phase, Phase::Workspace), "stays unlocked");
        let status = app.sync_status_line().unwrap();
        assert!(status.contains("1 added"), "delta surfaced: {status}");
        assert!(status.contains("2 changed"), "delta surfaced: {status}");
    }

    #[test]
    fn integrate_success_prunes_stale_marks_and_exits_empty_visual_mode() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.marks.insert(Uuid::new_v4());
        app.tree_mode = TreeMode::Visual { anchor: 0 };
        integrate(
            &mut app,
            Ok(SyncOutcome::AlreadyInSync),
            SyncTrigger::Manual,
        );
        assert!(app.marks.is_empty());
        assert_eq!(app.tree_mode, TreeMode::Normal);
    }

    #[test]
    fn integrate_error_drops_to_lockscreen() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        integrate(&mut app, Err(SyncError::NotConfigured), SyncTrigger::Manual);
        assert!(
            matches!(app.phase, Phase::LockScreen),
            "any SyncError → lock"
        );
        assert!(app.vault.is_none(), "vault dropped on error");
        assert!(app.status.as_deref().unwrap_or("").contains("Sync failed"));
    }

    #[test]
    fn lost_worker_reloads_registry_and_locks() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Simulate an in-flight sync: the worker owns the moved vault + registry.
        let _vault = app.vault.take().expect("vault present");
        let _registry = app.registry.take().expect("registry present");
        app.lock_pending = true; // a lock had fired mid-sync

        // The worker panicked — `drain` surfaced `WorkerLost`.
        app.on_sync_message(SyncMsg::WorkerLost, Instant::now());

        assert!(
            matches!(app.phase, Phase::LockScreen),
            "a lost worker drops to LockScreen"
        );
        assert!(app.vault.is_none(), "no vault after a lost worker");
        assert!(
            app.registry.is_some(),
            "registry reloaded so the post-lock UnlockList does not panic"
        );
        assert!(!app.lock_pending, "deferred-lock flag cleared");
        assert!(
            app.status
                .as_deref()
                .unwrap_or("")
                .contains("Sync worker failed"),
            "surfaces a worker-failure message"
        );
    }

    #[test]
    fn integrate_unresolvable_mentions_backup() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        integrate(
            &mut app,
            Err(SyncError::Unresolvable {
                reason: "same-second edit on both sides".to_string(),
                backup_path: std::path::PathBuf::from("/tmp/v.kdbx.bak"),
            }),
            SyncTrigger::Manual,
        );
        assert!(matches!(app.phase, Phase::LockScreen));
        let status = app.status.as_deref().unwrap_or("");
        assert!(
            status.contains(".kdbx.bak"),
            "points at the backup: {status}"
        );
    }

    #[test]
    fn deferred_lock_applies_after_sync_completes() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.lock_pending = true; // a lock fired mid-sync
        integrate(
            &mut app,
            Ok(SyncOutcome::AlreadyInSync),
            SyncTrigger::Manual,
        );
        assert!(
            matches!(app.phase, Phase::LockScreen),
            "deferred lock applied"
        );
        assert!(app.vault.is_none());
        assert!(!app.lock_pending, "pending flag cleared");
    }

    #[test]
    fn on_lock_trigger_locks_after_sync() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        integrate(
            &mut app,
            Ok(SyncOutcome::AlreadyInSync),
            SyncTrigger::OnLock,
        );
        assert!(
            matches!(app.phase, Phase::LockScreen),
            "on-lock flush then lock"
        );
    }

    #[test]
    fn on_quit_trigger_quits_after_sync() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        integrate(
            &mut app,
            Ok(SyncOutcome::AlreadyInSync),
            SyncTrigger::OnQuit,
        );
        assert!(app.should_quit, "on-quit flush then quit");
    }

    // T-SEC-CRED-1 (the security gate for the whole credential surface): the
    // two-call flow (`encrypt_credential` → `configure_remote`, RST-CRED-1)
    // persists ONLY the ciphertext container. The plaintext S3 secret and the
    // master password never reach EITHER on-disk file (`vaults.toml` or
    // `tui.toml`); only the non-secret access-key id is stored in the clear.
    // The test is constructed so it would FAIL if plaintext ever leaked.
    #[test]
    fn t_sec_cred_1_persists_only_ciphertext() {
        const SECRET: &str = "super-secret-key";
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.paths.ensure_exists().unwrap();

        let mut state = SyncConfigState::new();
        state.region = tui_input::Input::new("us-east-1".to_string());
        state.bucket = tui_input::Input::new("bkt".to_string());
        state.key = tui_input::Input::new("v.kdbx".to_string());
        state.access_key_id = tui_input::Input::new("AKIAEXAMPLE".to_string());
        // The S3 secret is collected ONLY through the echo-suppressed
        // `PasswordInput` (its buffer is `Zeroizing`), never a plain `Input`.
        state.secret = PasswordInput::with_value(SECRET);
        state.master = PasswordInput::with_value(PASSWORD);

        assert!(
            app.perform_configure_sync(&mut state),
            "two-call flow succeeds"
        );
        assert!(app.sync_configured(), "target configured after save");

        let vaults_toml =
            std::fs::read_to_string(app.paths.state_dir().join("vaults.toml")).unwrap();
        assert!(
            !vaults_toml.contains(SECRET),
            "plaintext S3 secret must never reach vaults.toml: {vaults_toml}"
        );
        assert!(
            !vaults_toml.contains(PASSWORD),
            "the master password must never reach vaults.toml"
        );
        assert!(
            vaults_toml.contains("AKIAEXAMPLE"),
            "the non-secret access key id is stored in the clear"
        );
        // RST-CRED-1 container marker proves the secret was encrypted, not stored.
        assert!(
            vaults_toml.contains("RC01") || vaults_toml.contains("secret_access_key_encrypted"),
            "only the encrypted container is persisted: {vaults_toml}"
        );

        // The TUI's own non-secret store must never see either secret. The file
        // may not exist (nothing here writes it) — that trivially contains no
        // secret, hence `unwrap_or_default`.
        let tui_toml = std::fs::read_to_string(config::config_path(&app.paths)).unwrap_or_default();
        assert!(
            !tui_toml.contains(SECRET) && !tui_toml.contains(PASSWORD),
            "no secret may reach tui.toml (non-secret store, ADR-T3): {tui_toml}"
        );
    }

    // T-SEC-CRED-1 (zeroize half): cancelling the credential overlay, and a lock
    // while it is open, both drop it — so its two `Zeroizing` `PasswordInput`
    // buffers (S3 secret + master password) are wiped, never left resident.
    #[test]
    fn t_sec_cred_1_cancel_and_lock_drop_the_credential_overlay() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Esc cancels → overlay dropped (buffers zeroize on drop).
        app.open_sync_config();
        assert!(matches!(app.overlay, Some(Overlay::SyncConfig(_))));
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(app.overlay.is_none(), "Esc drops the credential overlay");
        // Lock while it is open → `lock_app` clears the overlay too.
        app.open_sync_config();
        assert!(app.overlay.is_some());
        app.handle_event(&key_ctrl('l'));
        assert!(matches!(app.phase, Phase::LockScreen));
        assert!(app.overlay.is_none(), "lock drops the credential overlay");
    }

    // T-SYNC (surfacing matrix, ADR-T4a): each benign/quiet `SyncOutcome` gets
    // its distinct, never-swallowed status line. `Merged`/error/`Unresolvable`
    // are covered by the integrate_* tests above; this pins the quiet trio.
    #[test]
    fn t_sync_quiet_outcomes_surface_distinct_status() {
        let cases = [
            (SyncOutcome::AlreadyInSync, "Up to date"),
            (
                SyncOutcome::Pushed {
                    is_first_seed: false,
                },
                "Synced",
            ),
            (SyncOutcome::FastReplaced, "Updated from remote"),
        ];
        for (outcome, expected) in cases {
            let (_dir, mut app) = populated_app();
            unlock(&mut app, PASSWORD);
            integrate(&mut app, Ok(outcome.clone()), SyncTrigger::Manual);
            assert!(matches!(app.phase, Phase::Workspace), "stays unlocked");
            let status = app.sync_status_line().unwrap_or("");
            assert!(
                status.contains(expected),
                "{outcome:?} should surface {expected:?}, got {status:?}"
            );
        }
    }

    #[test]
    fn credential_overlay_rejects_missing_required_fields() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let mut state = SyncConfigState::new(); // all blank
        assert!(
            !app.perform_configure_sync(&mut state),
            "blanks are rejected"
        );
        assert!(state.error.is_some());
        assert!(!app.sync_configured());
    }

    #[test]
    fn settings_configure_row_opens_credential_overlay() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_alt('2')); // → Settings
                                         // "Configure sync target…" is the last row (index 5
                                         // after Theme (T3.4) and Auto-lock (T3.5) landed).
        for _ in 0..5 {
            app.handle_event(&key('j'));
        }
        assert_eq!(app.settings_index, 5);
        app.handle_event(&key_code(KeyCode::Enter));
        assert!(matches!(app.overlay, Some(Overlay::SyncConfig(_))));
    }

    // ---- Journey tests: edit overlay save-and-verify round-trip ----

    /// Journey: add a credential with all fields → verify it appears in the tree
    /// with the correct title, username, and password (round-trip through
    /// `App::apply_edit`).
    #[test]
    fn add_credential_with_full_fields_round_trips() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Open add overlay (credential, focus on Kind).
        app.handle_event(&key('a'));
        assert!(matches!(app.overlay, Some(Overlay::Edit(_))));
        // Tab to Title (field 1), type title.
        app.handle_event(&key_code(KeyCode::Tab));
        type_str(&mut app, "MyService");
        // Tab to Username (field 2), type username.
        app.handle_event(&key_code(KeyCode::Tab));
        type_str(&mut app, "myuser");
        // Tab to Password (field 3), type password.
        app.handle_event(&key_code(KeyCode::Tab));
        type_str(&mut app, "p@ssw0rd!");
        // Save.
        app.handle_event(&key_ctrl('s'));
        assert!(app.overlay.is_none());
        // Verify round-trip through the vault.
        let vault = app.vault.as_ref().unwrap();
        let uuid = app.tree.selected().unwrap();
        let entry = vault.get_entry(uuid).unwrap();
        assert_eq!(entry.title(), "MyService");
        assert_eq!(entry.username(), "myuser");
        assert_eq!(entry.password(), "p@ssw0rd!");
        // New entry should be in recents.
        assert_eq!(app.recents.rank(uuid), Some(0));
    }

    /// Journey: add a secure note (no username/password) → verify kind-specific
    /// fields are absent from the vault entry.
    #[test]
    fn add_secure_note_has_no_username_or_password() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('a')); // add overlay (focus on Kind field)
                                     // Cycle kind from Credential → SecureNote (space on Kind field).
        app.handle_event(&key(' '));
        // Tab to Title, type title.
        app.handle_event(&key_code(KeyCode::Tab));
        type_str(&mut app, "Meeting Notes");
        // Tab to Notes (skip username/password for secure note).
        app.handle_event(&key_code(KeyCode::Tab));
        type_str(&mut app, "Discussed roadmap for Q1");
        app.handle_event(&key_ctrl('s'));
        assert!(app.overlay.is_none());
        let vault = app.vault.as_ref().unwrap();
        let uuid = app.tree.selected().unwrap();
        let entry = vault.get_entry(uuid).unwrap();
        assert_eq!(entry.kind(), EntryKind::SecureNote);
        assert!(entry.username().is_empty(), "secure note has no username");
        assert!(entry.password().is_empty(), "secure note has no password");
    }

    /// Journey: edit an existing entry's password → verify the vault persists
    /// the new password and a history snapshot is appended.
    #[test]
    fn edit_password_round_trips_with_history() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // → Root1 entry
        let uuid = app.tree.selected().unwrap();
        // Verify initial state.
        let vault = app.vault.as_ref().unwrap();
        let initial_password = vault.get_entry(uuid).unwrap().password().to_string();
        assert_eq!(initial_password, "s3cr3t");
        assert_eq!(vault.get_entry(uuid).unwrap().history().len(), 0);
        // Open edit.
        app.handle_event(&key('e'));
        assert!(matches!(app.overlay, Some(Overlay::Edit(_))));
        // Password is field 3 for a credential edit (title, username, password).
        app.handle_event(&key_code(KeyCode::Tab));
        app.handle_event(&key_code(KeyCode::Tab));
        // Clear existing password and type new one.
        for _ in 0..initial_password.len() {
            app.handle_event(&key_code(KeyCode::Backspace));
        }
        type_str(&mut app, "newpass");
        app.handle_event(&key_ctrl('s'));
        assert!(app.overlay.is_none());
        // Verify round-trip.
        let vault = app.vault.as_ref().unwrap();
        assert_eq!(vault.get_entry(uuid).unwrap().password(), "newpass");
        assert_eq!(
            vault.get_entry(uuid).unwrap().history().len(),
            1,
            "history snapshot appended"
        );
    }

    /// Journey: edit an entry and change title → verify the vault persists the
    /// new title and a history snapshot is appended. (Kind is immutable on
    /// edit; `cycle_kind` only works on new add forms.)
    #[test]
    fn edit_changes_title_and_appends_history() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // → Root1 entry
        let uuid = app.tree.selected().unwrap();
        // Verify initial state.
        let vault = app.vault.as_ref().unwrap();
        assert_eq!(vault.get_entry(uuid).unwrap().title(), "Root1");
        assert_eq!(vault.get_entry(uuid).unwrap().history().len(), 0);
        assert_eq!(vault.get_entry(uuid).unwrap().kind(), EntryKind::Credential);
        // Open edit.
        app.handle_event(&key('e'));
        // Title is field 0 for edit (no Kind row on edit forms).
        // Append a character to the title.
        type_str(&mut app, "Z");
        app.handle_event(&key_ctrl('s'));
        assert!(app.overlay.is_none());
        // Verify title changed, kind unchanged, and history appended.
        let vault = app.vault.as_ref().unwrap();
        let entry = vault.get_entry(uuid).unwrap();
        assert!(entry.title().contains('Z'), "title was edited");
        assert_eq!(
            entry.kind(),
            EntryKind::Credential,
            "kind is immutable on edit"
        );
        assert_eq!(entry.history().len(), 1, "history snapshot appended");
    }

    /// Journey: open add → type title → tab to password → Ctrl+G → generate →
    /// Enter to accept → save → verify password field is filled from the
    /// generated preview.
    #[test]
    fn generate_panel_fills_password_and_survives_save() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('a')); // add overlay (credential, focus on Kind)
                                     // Tab to Title, type title.
        app.handle_event(&key_code(KeyCode::Tab));
        type_str(&mut app, "GeneratedEntry");
        // Tab to Username, then to Password.
        app.handle_event(&key_code(KeyCode::Tab));
        app.handle_event(&key_code(KeyCode::Tab));
        // Open generate panel.
        app.handle_event(&key_ctrl('g'));
        match app.overlay.as_ref() {
            Some(Overlay::Edit(s)) => assert!(s.generating.is_some()),
            _ => panic!("expected edit overlay"),
        }
        // Accept the generated password.
        app.handle_event(&key_code(KeyCode::Enter));
        match app.overlay.as_ref() {
            Some(Overlay::Edit(s)) => {
                assert!(s.generating.is_none(), "panel closed on accept");
                assert!(
                    !s.password.as_str().is_empty(),
                    "password filled from preview"
                );
                let generated = s.password.as_str().to_string();
                // Save (Title is already filled, password was just generated).
                app.handle_event(&key_ctrl('s'));
                assert!(app.overlay.is_none());
                // Verify the generated password persisted through the vault round-trip.
                let vault = app.vault.as_ref().unwrap();
                let uuid = app.tree.selected().unwrap();
                assert_eq!(vault.get_entry(uuid).unwrap().title(), "GeneratedEntry");
                assert_eq!(vault.get_entry(uuid).unwrap().password(), generated);
            }
            _ => panic!("overlay should still be Edit"),
        }
    }

    /// A `Debug`-friendly phase name for assertion messages (Phase itself is not
    /// `Debug` to avoid risk of embedding the `PasswordInput` buffer).
    struct PhaseName<'a>(&'a Phase);
    impl std::fmt::Debug for PhaseName<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let s = match self.0 {
                Phase::UnlockList => "UnlockList",
                Phase::UnlockPrompt { .. } => "UnlockPrompt",
                Phase::LockScreen => "LockScreen",
                Phase::Workspace => "Workspace",
            };
            f.write_str(s)
        }
    }

    // --- Command registry (T1.1) — the App-dependent registry tests. The pure
    // structural tests live in `command::registry`; these need a real unlocked
    // App, so they live here where `populated_app()` is in scope. ---

    #[test]
    fn commands_for_filters_by_context() {
        use crate::command::registry::{commands_for, Contexts};
        // Every command surfaced in a single-bit context must declare that
        // context — the exact "no wrong-context hints" guarantee.
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        for ctx in Contexts::each_bit() {
            for (spec, _state) in commands_for(ctx, &app) {
                assert!(
                    spec.contexts.contains(ctx),
                    "{:?} surfaced in a context it does not declare",
                    spec.id
                );
            }
        }
        // Non-tautological membership/absence: a known command appears only in
        // the contexts it declares. `Generate` is EDIT-only.
        let present = |ctx, id| commands_for(ctx, &app).iter().any(|(s, _)| s.id == id);
        assert!(
            present(Contexts::EDIT, Command::Generate),
            "Generate must surface in EDIT"
        );
        assert!(
            !present(Contexts::SECRETS_TREE, Command::Generate),
            "Generate must not surface in the tree"
        );
        assert!(
            present(Contexts::SECRETS_TREE, Command::CopyPassword),
            "CopyPassword must surface in the tree"
        );
    }

    #[test]
    fn hint_bar_ordering_is_stable() {
        use crate::command::registry::{
            commands_for, commands_for_specs, CommandSpec, Contexts, Group,
        };
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let ctx = Contexts::SECRETS_TREE;
        let first: Vec<Command> = commands_for(ctx, &app)
            .iter()
            .map(|(spec, _)| spec.id)
            .collect();
        let second: Vec<Command> = commands_for(ctx, &app)
            .iter()
            .map(|(spec, _)| spec.id)
            .collect();
        assert_eq!(first, second, "commands_for must be deterministic");
        // Output is sorted by `order` (ties keep declaration order — a stable
        // sort — so the hint bar never reshuffles on unrelated edits).
        let orders: Vec<i16> = commands_for(ctx, &app)
            .iter()
            .map(|(spec, _)| spec.order)
            .collect();
        assert!(
            orders.windows(2).all(|w| w[0] <= w[1]),
            "commands_for output must be sorted by order: {orders:?}"
        );

        let tied = [
            CommandSpec {
                id: Command::Prev,
                name: "prev",
                desc: "previous",
                group: Group::Navigation,
                contexts: ctx,
                order: 10,
                quick_bar: true,
            },
            CommandSpec {
                id: Command::Next,
                name: "next",
                desc: "next",
                group: Group::Navigation,
                contexts: ctx,
                order: 10,
                quick_bar: true,
            },
        ];
        let tied_ids: Vec<Command> = commands_for_specs(&tied, ctx, &app)
            .into_iter()
            .map(|(spec, _)| spec.id)
            .collect();
        assert_eq!(tied_ids, [Command::Prev, Command::Next]);
    }

    // --- Derived hint bar (T2.1) — App-dependent (need a real unlocked App;
    // the pure width-fitting tests live in `widgets::hint_bar`). ---

    #[test]
    fn build_reflects_context_and_rebinds() {
        use crate::command::keymap::KeymapPatch;
        use crate::command::registry::{CmdState, Contexts};
        use crate::command::Keymap;
        use crate::widgets::hint_bar::build_hint_bar;

        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Select the loose `Root1` entry so copy-password is Enabled.
        app.handle_event(&key('j'));
        assert!(app.selected_entry_uuid().is_some());

        // Wide bar: every quick_bar command for the tree fits, in registry order,
        // with the `? more` affordance last.
        let cells = build_hint_bar(Contexts::SECRETS_TREE, &app, 200);
        let descs: Vec<&str> = cells.iter().map(|c| c.desc).collect();
        assert_eq!(
            descs,
            [
                "down",
                "up",
                "search",
                "add entry",
                "edit entry",
                "copy password",
                "more"
            ],
            "cells are the tree's quick_bar commands in order, then `? more`"
        );
        // Every non-affordance cell here is Enabled (an entry is selected).
        assert!(cells[..cells.len() - 1]
            .iter()
            .all(|c| c.state == CmdState::Enabled));

        // A rebind is reflected everywhere the bar derives from the keymap.
        let toml = r#"
            [bindings]
            "copy-password" = "y"
        "#;
        let (km, warnings): (Keymap, _) =
            Keymap::from_patch(&toml::from_str::<KeymapPatch>(toml).unwrap());
        assert!(warnings.is_empty());
        app.keys = km;
        let cells = build_hint_bar(Contexts::SECRETS_TREE, &app, 200);
        let copy = cells
            .iter()
            .find(|c| c.desc == "copy password")
            .expect("copy cell present");
        assert_eq!(copy.keys, "y", "rebound key shows in the hint bar");
    }

    #[test]
    fn disabled_commands_render_dimmed_not_dropped() {
        use crate::command::registry::{CmdState, Contexts};
        use crate::widgets::hint_bar::{build_hint_bar, hint_line};
        use ratatui::style::Modifier;

        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Post-unlock the selection is the `Personal` group → copy is Disabled.
        let cells = build_hint_bar(Contexts::SECRETS_TREE, &app, 200);
        let copy = cells
            .iter()
            .find(|c| c.desc == "copy password")
            .expect("copy cell is present, not dropped");
        assert_eq!(
            copy.state,
            CmdState::Disabled,
            "copy is present-but-disabled on a group row"
        );

        // The renderer dims disabled cells (muted carries DIM — never dropped,
        // never colour-only).
        let line = hint_line(&cells, &app.theme);
        let copy_span = line
            .spans
            .iter()
            .find(|s| s.content.as_ref() == "copy password")
            .expect("copy desc span present");
        assert!(
            copy_span.style.add_modifier.contains(Modifier::DIM),
            "a disabled cell renders dimmed"
        );
    }

    #[test]
    fn truncation_keeps_whole_cells_and_more_indicator() {
        use crate::command::registry::Contexts;
        use crate::widgets::hint_bar::{build_hint_bar, hint_line};

        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        for width in [200u16, 80, 40, 10] {
            let cells = build_hint_bar(Contexts::SECRETS_TREE, &app, width);
            // The affordance is always the last cell.
            assert_eq!(
                cells.last().map(|c| c.desc),
                Some("more"),
                "`? more` is always the last cell (width {width})"
            );
            // Whole cells only: the rendered line never exceeds the width.
            let line = hint_line(&cells, &app.theme);
            let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
            assert!(
                unicode_width::UnicodeWidthStr::width(rendered.as_str()) <= width as usize,
                "rendered bar fits width {width}: {rendered:?}"
            );
        }
        // At 10 columns only the affordance survives.
        let narrow = build_hint_bar(Contexts::SECRETS_TREE, &app, 10);
        assert_eq!(narrow.len(), 1, "only `? more` survives a 10-column bar");
    }

    #[test]
    fn every_context_has_nonempty_hint_bar() {
        use crate::command::registry::Contexts;
        use crate::widgets::hint_bar::build_hint_bar;

        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        // Panic-smoke across every context bit: the builder never yields an empty
        // bar (the `? more` affordance is always last). This alone is structurally
        // guaranteed, so the content-bearing contexts below carry the real check.
        for ctx in Contexts::each_bit() {
            let cells = build_hint_bar(ctx, &app, 200);
            assert!(!cells.is_empty(), "a context produced no hint cells");
            assert!(
                matches!(cells.last().map(|c| c.desc), Some("more" | "palette")),
                "the reserved palette cell is always last"
            );
        }
        // The contexts that MUST show real commands (a forgotten quick_bar flag
        // would leave only `? more`, which the affordance-always-present rule
        // would otherwise mask): at least one real hint cell plus the affordance.
        for ctx in [
            Contexts::SECRETS_TREE,
            Contexts::SECRETS_DETAIL,
            Contexts::PINNED_TAB,
            Contexts::SETTINGS_TAB,
            Contexts::UNLOCK_LIST,
        ] {
            let cells = build_hint_bar(ctx, &app, 200);
            assert!(
                cells.len() >= 2,
                "{ctx:?} must show ≥1 real command plus the `? more` affordance, got {} cell(s)",
                cells.len()
            );
        }
    }

    // --- Which-key menu (T2.2) — App-dependent integration (the pure gate /
    // build tests live in `widgets::which_key`). ---

    #[test]
    fn which_key_menu_respects_delay_and_completion() {
        use crate::widgets::which_key::{which_key_menu, WHICH_KEY_DELAY};
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);

        // `g` leaves a chord prefix pending, stamped with a start instant.
        app.handle_event(&key('g'));
        let since = app.pending_seq().since.expect("g stamps a pending prefix");
        let ctx = app.current_context();

        // Before the delay (a fast typist completing `gt`) the menu never shows.
        assert!(
            which_key_menu(app.pending_seq(), &app.keys, ctx, since).is_none(),
            "no menu before the delay — fast `gt` never flashes it"
        );
        // Past the delay the two-continuation `g` shows the candidate menu.
        assert!(
            which_key_menu(app.pending_seq(), &app.keys, ctx, since + WHICH_KEY_DELAY).is_some(),
            "past the delay, `g`'s continuations render"
        );
        // Completing the sequence clears the pending state → no menu.
        app.handle_event(&key('t'));
        assert!(
            app.pending_seq().since.is_none(),
            "completing the chord resets the stamp"
        );
    }

    #[test]
    fn plain_preset_shows_no_which_key() {
        use crate::widgets::which_key::{which_key_menu, WHICH_KEY_DELAY};
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.keys = Keymap::preset(Preset::Plain);

        // `g` is not a motion in the chord-free Plain preset — it routes to the
        // tab body and pends no prefix, so the which-key menu can never fire.
        app.handle_event(&key('g'));
        assert!(
            app.pending_seq().since.is_none(),
            "the plain preset pends no chord"
        );
        let ctx = app.current_context();
        assert!(
            which_key_menu(
                app.pending_seq(),
                &app.keys,
                ctx,
                Instant::now() + WHICH_KEY_DELAY
            )
            .is_none(),
            "plain preset has no sequences → no menu even past the delay"
        );
    }

    // ---- Palette row-building (T2.3) — App-dependent (the pure logic lives in
    // `overlay::palette`; these need a real unlocked App via `populated_app`). ----

    #[test]
    fn every_visible_command_listed_unfiltered() {
        use crate::command::registry::{CmdState, COMMANDS};
        use crate::overlay::palette::build_palette_rows;

        // US-070 AC: the unfiltered palette documents every bound command — it
        // lists exactly the non-Hidden registry commands (no drift).
        let (_dir, app) = populated_app();
        let rows = build_palette_rows(&app, Contexts::SECRETS_TREE, "");
        let listed: std::collections::HashSet<Command> = rows.iter().map(|r| r.spec.id).collect();
        for spec in COMMANDS {
            if app.command_state(spec.id) == CmdState::Hidden {
                continue;
            }
            assert!(
                listed.contains(&spec.id),
                "{:?} is missing from the unfiltered palette",
                spec.id
            );
        }
        // The key strings still come from the live keymap (verbatim projection).
        let keys_for = |id| {
            rows.iter()
                .find(|r| r.spec.id == id)
                .map(|r| r.keys.as_str())
        };
        assert_eq!(keys_for(Command::Quit), Some("Ctrl+q"));
        assert_eq!(keys_for(Command::CopyPassword), Some("c"));
        assert_eq!(keys_for(Command::JumpToTab), Some("{count}gt / Alt+1..9"));
    }

    #[test]
    fn rows_grouped_and_ordered() {
        use crate::overlay::palette::build_palette_rows;

        // Unfiltered: rows are grouped (group rank non-decreasing), and within a
        // group ordered by registry `order`.
        let (_dir, app) = populated_app();
        let rows = build_palette_rows(&app, Contexts::SECRETS_TREE, "");
        let mut prev: Option<(u8, i16)> = None;
        for row in &rows {
            let key = (row.spec.group.rank(), row.spec.order);
            if let Some(p) = prev {
                assert!(
                    p <= key,
                    "palette rows must be grouped then ordered: {p:?} !<= {key:?}"
                );
            }
            prev = Some(key);
        }
    }

    #[test]
    fn filter_ranks_via_core_matcher() {
        use crate::overlay::palette::build_palette_rows;

        // Filtering `cppw` ranks copy-password first, with populated match
        // indices — the palette shares the core matcher with search.
        let (_dir, app) = populated_app();
        let rows = build_palette_rows(&app, Contexts::SECRETS_TREE, "cppw");
        assert_eq!(
            rows.first().map(|r| r.spec.id),
            Some(Command::CopyPassword),
            "cppw ranks copy-password first"
        );
        assert!(
            !rows[0].match_indices.is_empty(),
            "match indices populate for highlighting"
        );
    }

    #[test]
    fn enter_executes_selected_command_via_dispatch() {
        use crate::overlay::palette::build_palette_rows;
        // Proves the palette shares `execute_command` with keys: selecting
        // lock-now and pressing Enter locks the vault.
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('?'));
        // Unfiltered order: Global group first (Quit, LockNow, …). Down once
        // selects LockNow (row 1, after Quit).
        app.handle_event(&key_code(KeyCode::Down));
        match &app.overlay {
            Some(Overlay::Palette(s)) => {
                let rows = build_palette_rows(&app, s.underlying, s.filter());
                assert_eq!(
                    rows[s.selected].spec.id,
                    Command::LockNow,
                    "row 1 is lock-now"
                );
            }
            _ => panic!("palette open"),
        }
        app.handle_event(&key_code(KeyCode::Enter));
        assert!(matches!(app.phase, Phase::LockScreen), "Enter ran lock-now");
        assert!(app.overlay.is_none(), "the palette closed on execute");
    }

    #[test]
    fn disabled_rows_listed_but_not_executable() {
        use crate::command::registry::CmdState;
        use crate::overlay::palette::build_palette_rows;
        // On the Settings tab, copy-password is out of context → listed Disabled;
        // Enter on it neither dispatches nor closes the palette.
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key_alt('2')); // Settings tab
        app.handle_event(&key('?')); // palette over SETTINGS_TAB
        let idx = match &app.overlay {
            Some(Overlay::Palette(s)) => {
                let rows = build_palette_rows(&app, s.underlying, "");
                let i = rows
                    .iter()
                    .position(|r| r.spec.id == Command::CopyPassword)
                    .expect("copy-password is listed even out of context");
                assert_eq!(rows[i].state, CmdState::Disabled, "listed but disabled");
                i
            }
            _ => panic!("palette open"),
        };
        for _ in 0..idx {
            app.handle_event(&key_code(KeyCode::Down));
        }
        app.handle_event(&key_code(KeyCode::Enter));
        assert!(
            matches!(app.overlay, Some(Overlay::Palette(_))),
            "Enter on a disabled row keeps the palette open (no dispatch)"
        );
        // …and dispatched nothing: still on the Settings tab, vault unlocked.
        assert!(matches!(app.phase, Phase::Workspace));
        assert!(matches!(app.tabs.active_tab(), Tab::Settings));
    }

    #[test]
    fn syncing_disables_body_commands_for_palette_and_keys() {
        use crate::command::registry::CmdState;
        use crate::overlay::palette::build_palette_rows;

        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // Root1
        assert!(app.selected_entry_uuid().is_some());
        app.handle_event(&key('p')); // create a pinned tab before the vault moves
        assert_eq!(app.tabs.count(), 3, "Secrets + pin + Settings");
        configure_target(&mut app, "personal");
        app.set_sync_engine(Arc::new(AlreadyInSyncEngine));
        app.handle_event(&key('s'));
        type_str(&mut app, PASSWORD);
        app.handle_event(&key_code(KeyCode::Enter));
        assert!(app.is_syncing());

        let focus_before = app.focus;
        app.handle_event(&key_code(KeyCode::Tab));
        assert_eq!(
            app.focus, focus_before,
            "a body-command key is refused by execute_command during sync"
        );
        let selection_before = app.tree.selected();
        app.handle_event(&key('k'));
        assert_eq!(
            app.tree.selected(),
            selection_before,
            "tree navigation cannot bypass the shared sync guard"
        );

        app.handle_event(&key_alt('2')); // pinned tab remains independently navigable
        assert!(matches!(app.tabs.active_tab(), Tab::Pinned(_)));
        app.detail_scroll = 5;
        app.handle_event(&key('k'));
        assert_eq!(
            app.detail_scroll, 5,
            "pinned navigation cannot bypass the shared sync guard"
        );
        app.handle_event(&key_alt('3')); // Settings after Secrets + pin
        app.settings_index = 0;
        app.handle_event(&key('j'));
        assert_eq!(
            app.settings_index, 0,
            "Settings navigation cannot bypass the shared sync guard"
        );

        app.handle_event(&key('?'));
        let search_idx = match &app.overlay {
            Some(Overlay::Palette(state)) => {
                let rows = build_palette_rows(&app, state.underlying, "");
                let idx = rows
                    .iter()
                    .position(|row| row.spec.id == Command::Search)
                    .expect("search is listed");
                assert_eq!(rows[idx].state, CmdState::Disabled);
                assert_eq!(
                    rows.iter()
                        .find(|row| row.spec.id == Command::Help)
                        .map(|row| row.state),
                    Some(CmdState::Enabled),
                    "read-only chrome remains available during sync"
                );
                idx
            }
            _ => panic!("Help remains available during sync"),
        };
        for _ in 0..search_idx {
            app.handle_event(&key_code(KeyCode::Down));
        }
        app.handle_event(&key_code(KeyCode::Enter));
        assert!(
            matches!(app.overlay, Some(Overlay::Palette(_))),
            "disabled Enter keeps the palette open instead of closing silently"
        );
    }

    #[test]
    fn palette_esc_closes_without_side_effects() {
        // Select an *entry* first so a leaked action key (`c` copy / `space`
        // reveal / `e` edit) would actually mutate state — then filtering, moving
        // the selection, and Esc must leave everything untouched.
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('j')); // select the Root1 entry
        assert!(app.selected_entry_uuid().is_some());
        let sel_before = app.tree.selected();
        let focus_before = app.focus;
        let reveal_before = app.reveal_password;
        let scroll_before = app.detail_scroll;
        app.handle_event(&key('?'));
        // Type keys that, if they leaked past the palette, would copy / reveal /
        // edit the selected entry.
        for c in "c e".chars() {
            app.handle_event(&key(c));
        }
        app.handle_event(&key(' '));
        app.handle_event(&key_code(KeyCode::Down));
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(app.overlay.is_none(), "Esc closes the palette");
        assert!(matches!(app.phase, Phase::Workspace), "phase unchanged");
        assert_eq!(app.tree.selected(), sel_before, "tree selection unchanged");
        assert_eq!(app.focus, focus_before, "focus unchanged");
        assert_eq!(
            app.reveal_password, reveal_before,
            "no reveal leaked past the palette"
        );
        assert_eq!(
            app.detail_scroll, scroll_before,
            "no scroll leaked past the palette"
        );
    }

    #[test]
    fn palette_command_opening_overlay_sequences_correctly() {
        // Executing a command that opens another overlay (search) closes the
        // palette FIRST — the result is a single Search overlay, not two.
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('?'));
        for c in "search".chars() {
            app.handle_event(&key(c));
        }
        app.handle_event(&key_code(KeyCode::Enter));
        assert!(
            matches!(app.overlay, Some(Overlay::Search(_))),
            "search runs and its overlay replaces the palette"
        );
    }

    #[test]
    fn palette_floor_geometry_40x12() {
        // D-8 subsumption: the palette must render usably at the 40×12 floor
        // (filter row + several command rows), never panicking.
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('?'));
        let mut terminal = Terminal::new(TestBackend::new(
            crate::overlay::palette::FLOOR_W,
            crate::overlay::palette::FLOOR_H,
        ))
        .expect("backend");
        terminal
            .draw(|frame| app.render(frame, Instant::now()))
            .expect("palette renders at the 40×12 floor without panic");
        // ≥6 command rows exist to fill the floor list area.
        let rows = crate::overlay::palette::build_palette_rows(&app, Contexts::SECRETS_TREE, "");
        assert!(
            rows.len() >= 6,
            "the palette has enough rows to fill the floor"
        );
    }

    // ---- Pre-unlock palette / breadcrumb (T2.4) ----

    #[test]
    fn palette_opens_pre_unlock_with_context_commands() {
        use crate::command::registry::CmdState;
        use crate::overlay::palette::build_palette_rows;
        // `?` opens the palette on the unlock list (TUIE-4 pre-unlock reach),
        // filtered to the UNLOCK_LIST context: unlock (Confirm) enabled,
        // workspace-only commands (copy) listed disabled.
        let (_dir, mut app) = populated_app();
        assert!(matches!(app.phase, Phase::UnlockList));
        app.handle_event(&key('?'));
        match &app.overlay {
            Some(Overlay::Palette(s)) => {
                assert_eq!(s.underlying, Contexts::UNLOCK_LIST);
                let rows = build_palette_rows(&app, s.underlying, "");
                let state_of = |id| rows.iter().find(|r| r.spec.id == id).map(|r| r.state);
                assert_eq!(
                    state_of(Command::Confirm),
                    Some(CmdState::Enabled),
                    "unlock (Confirm) is available on the unlock list"
                );
                assert_eq!(
                    state_of(Command::CopyPassword),
                    Some(CmdState::Disabled),
                    "a workspace-only command lists disabled pre-unlock"
                );
            }
            _ => panic!("? opens the palette pre-unlock"),
        }
        app.handle_event(&key_code(KeyCode::Esc));
        assert!(app.overlay.is_none(), "Esc closes the pre-unlock palette");
    }

    #[test]
    fn master_password_with_question_mark_is_typeable() {
        // KDBX interop (engineering principle #1): `?` is a valid master-password
        // character, so at the unlock prompt it must reach the password input —
        // it does NOT open the palette there (unlike every other phase). A
        // `?`-containing password round-trips through unlock, exactly as it would
        // in KeePassXC.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("q.kdbx");
        let pw = "pa?ss";
        let mut vault = Vault::create(
            &path,
            &MasterPassword::new(pw.to_string()),
            None,
            fast_kdf(),
            NoRecoveryConfirmed::yes(),
        )
        .expect("create");
        vault.save().expect("save");
        drop(vault);
        let paths = FalachPaths::with_state_dir(dir.path().join("state"));
        let mut registry = VaultRegistry::with_paths(paths.clone());
        registry
            .register(RegisteredVault {
                name: "q".to_string(),
                path,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                keyfile_path: None,
                extra: toml::Table::new(),
            })
            .expect("register");
        let mut app =
            App::from_registry(registry, paths, AutoLockConfig::default()).expect("from_registry");

        app.handle_event(&key_code(KeyCode::Enter)); // UnlockList → UnlockPrompt
        assert!(matches!(app.phase, Phase::UnlockPrompt { .. }));
        // Typing the password — including the `?` — must NOT open the palette.
        for c in pw.chars() {
            app.handle_event(&key(c));
        }
        assert!(
            app.overlay.is_none(),
            "`?` at the prompt types into the password, not the palette"
        );
        app.handle_event(&key_code(KeyCode::Enter)); // submit
        assert!(
            matches!(app.phase, Phase::Workspace),
            "a `?`-containing master password unlocks the vault"
        );
    }

    #[test]
    fn unlock_prompt_hint_does_not_advertise_question_mark_palette() {
        use crate::widgets::hint_bar::{build_hint_bar, hint_line};

        let (_dir, mut app) = populated_app();
        app.handle_event(&key_code(KeyCode::Enter));
        assert!(matches!(app.phase, Phase::UnlockPrompt { .. }));
        let cells = build_hint_bar(Contexts::UNLOCK_PROMPT, &app, 80);
        let more = cells.last().expect("reserved palette documentation cell");
        assert_eq!(more.state, CmdState::Disabled);
        assert_eq!(more.keys, "—");
        assert_eq!(more.desc, "palette");
        let rendered: String = hint_line(&cells, &app.theme)
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(
            !rendered.contains("? more"),
            "the password prompt must not advertise `?` as a palette key: {rendered:?}"
        );
    }

    #[test]
    fn explicitly_unbound_help_renders_disabled_not_fake_question_mark() {
        use crate::command::keymap::KeymapPatch;
        use crate::widgets::hint_bar::build_hint_bar;

        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let patch: KeymapPatch = toml::from_str(
            r"
                [bindings]
                help = false
            ",
        )
        .expect("patch");
        let (keys, warnings) = Keymap::from_patch(&patch);
        assert!(warnings.is_empty());
        app.keys = keys;

        let cells = build_hint_bar(Contexts::SECRETS_TREE, &app, 80);
        let more = cells.last().expect("reserved palette documentation cell");
        assert_eq!(more.state, CmdState::Disabled);
        assert_eq!(more.keys, "—");
        assert_eq!(more.desc, "palette");
        app.handle_event(&key('?'));
        assert!(
            app.overlay.is_none(),
            "an invented fallback key must not fire"
        );
    }

    #[test]
    fn breadcrumb_reflects_selection() {
        // The breadcrumb shows `vault › Group › Entry` for the live selection.
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        app.handle_event(&key('l')); // expand the Personal group
        app.handle_event(&key('j')); // select its first child entry
        assert!(app.selected_entry_uuid().is_some(), "an entry is selected");
        let crumb = crate::screens::secrets::build_breadcrumb(&app, 80);
        assert!(
            crumb.starts_with("personal › Personal › "),
            "breadcrumb roots at vault › group: {crumb}"
        );
        assert!(crumb.contains("Alpha"), "includes the entry title: {crumb}");
    }

    #[test]
    fn breadcrumb_resolves_selection_inside_collapsed_group() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let alpha = {
            let vault = app.vault.as_ref().unwrap();
            let root = vault.group_view(vault.root_group_uuid()).unwrap();
            let personal = root
                .child_group_uuids()
                .into_iter()
                .find(|uuid| {
                    vault
                        .group_view(*uuid)
                        .is_ok_and(|g| g.name() == "Personal")
                })
                .expect("Personal group");
            let alpha = vault
                .group_view(personal)
                .unwrap()
                .entry_uuids()
                .into_iter()
                .find(|uuid| vault.get_entry(*uuid).is_ok_and(|e| e.title() == "Alpha"))
                .expect("Alpha entry");
            let visible = entry_tree::build_rows(vault, &app.tree, &app.recents);
            assert!(
                visible.iter().all(|row| row.uuid != alpha),
                "Alpha starts hidden inside the collapsed group"
            );
            alpha
        };
        app.tree.select(alpha);

        assert_eq!(
            crate::screens::secrets::build_breadcrumb(&app, 80),
            "personal › Personal › Alpha"
        );
    }

    #[test]
    fn breadcrumb_resolves_three_deep_collapsed_selection() {
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let selected = {
            let vault = app.vault.as_mut().unwrap();
            let root = vault.root_group_uuid();
            let group_a = vault.create_group(root, "Group A").unwrap();
            let group_b = vault.create_group(group_a, "Group B").unwrap();
            vault
                .add_entry(group_b, EntryBuilder::credential("Deep Entry").build())
                .unwrap()
        };
        let visible = entry_tree::build_rows(app.vault.as_ref().unwrap(), &app.tree, &app.recents);
        assert!(visible.iter().all(|row| row.uuid != selected));
        app.tree.select(selected);

        assert_eq!(
            crate::screens::secrets::build_breadcrumb(&app, 80),
            "personal › Group A › Group B › Deep Entry"
        );
    }

    #[test]
    fn command_state_disabled_matches_dispatch_guard() {
        use crate::command::registry::{commands_for, Contexts};
        // The registry's enablement must agree with dispatch: a Disabled command
        // is a no-op if invoked; an Enabled one performs its effect.
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let sink = crate::clipboard::RecordingClipboard::new();
        let log = sink.log.clone();
        app.set_clipboard(Box::new(sink));

        // The state a command carries in the `commands_for` projection (what the
        // T2.1 hint bar dims) must equal `command_state` for that command.
        let projected = |app: &App, id: Command| {
            commands_for(Contexts::SECRETS_TREE, app)
                .into_iter()
                .find(|(s, _)| s.id == id)
                .map(|(_, state)| state)
        };

        // --- CopyPassword: selection starts on the Personal group (not an
        // entry) → Disabled ⟺ dispatching 'c' copies nothing. ---
        assert_eq!(
            app.command_state(Command::CopyPassword),
            CmdState::Disabled,
            "copy is disabled with no entry selected"
        );
        assert_eq!(
            projected(&app, Command::CopyPassword),
            Some(CmdState::Disabled),
            "the hint-bar projection must dim copy too"
        );
        app.handle_event(&key('c'));
        assert_eq!(log.borrow().copies, 0, "disabled copy is a no-op");

        // --- The other entry-scoped commands are likewise Disabled on the group
        // row, and dispatch is a no-op for each (the disabled⟺guard pairing that
        // the T2.1 refinement adds). ---
        for id in [
            Command::EditEntry,
            Command::DeleteEntry,
            Command::PinToggle,
            Command::RevealPassword,
            Command::History,
        ] {
            assert_eq!(
                app.command_state(id),
                CmdState::Disabled,
                "{id:?} is disabled on a group row"
            );
        }
        let tabs_before = app.tabs.count();
        app.handle_event(&key('e')); // edit — no overlay on a group row
        app.handle_event(&key('d')); // delete — no overlay
        app.handle_event(&key('p')); // pin — groups are not pinnable
        app.handle_event(&key(' ')); // reveal — nothing to reveal
        app.handle_event(&key('H')); // history — no overlay
        assert!(
            app.overlay.is_none(),
            "no entry-scoped overlay opens on a group row"
        );
        assert!(!app.reveal_password, "reveal is a no-op on a group row");
        assert_eq!(
            app.tabs.count(),
            tabs_before,
            "pin is a no-op on a group row"
        );

        // Move to the loose `Root1` entry → Enabled ⟺ 'c' copies its password.
        app.handle_event(&key('j'));
        assert_eq!(
            app.command_state(Command::CopyPassword),
            CmdState::Enabled,
            "copy is enabled on a selected entry"
        );
        assert_eq!(
            projected(&app, Command::CopyPassword),
            Some(CmdState::Enabled),
            "the hint-bar projection must enable copy too"
        );
        app.handle_event(&key('c'));
        assert_eq!(log.borrow().copies, 1, "enabled copy performs the copy");

        // --- Sync: the fixture has no configured remote → Disabled ⟺
        // dispatching 's' opens no sync overlay. ---
        assert_eq!(
            app.command_state(Command::Sync),
            CmdState::Disabled,
            "sync is disabled without a configured remote"
        );
        app.handle_event(&key('s'));
        assert!(
            app.overlay.is_none(),
            "disabled sync opens no overlay (no-op)"
        );

        // --- Pinned tab: reveal/history act on the pinned entry, so they stay
        // Enabled there even when the *tree* selection is a group again — the
        // tab-aware branch of command_state, paired with `on_pinned_key`. ---
        app.handle_event(&key('p')); // pin the still-selected Root1 → a pinned tab
        app.handle_event(&key('k')); // move the tree selection back up to the group
        assert!(
            app.selected_entry_uuid().is_none(),
            "the tree selection is the group again"
        );
        app.handle_event(&key_alt('2')); // jump to the pinned tab (ordinal 2)
        assert!(matches!(app.tabs.active_tab(), Tab::Pinned(_)));
        assert_eq!(
            app.command_state(Command::RevealPassword),
            CmdState::Enabled,
            "reveal is enabled on a pinned tab regardless of the tree selection"
        );
        assert_eq!(app.command_state(Command::History), CmdState::Enabled);
        app.handle_event(&key(' ')); // reveal acts on the pinned entry
        assert!(app.reveal_password, "reveal toggled on the pinned tab");
    }

    #[test]
    fn persist_vault_choke_point_counts_saves() {
        // The `save_count` seam (OQ-1) exists so T4.5/T4.7 can assert "exactly
        // one atomic write per operation". Pin the contract now: navigation
        // never persists; a mutation routes exactly one save through
        // `persist_vault`.
        let (_dir, mut app) = populated_app();
        unlock(&mut app, PASSWORD);
        let before = app.save_count;

        // Pure navigation writes nothing to the vault.
        app.handle_event(&key('j'));
        app.handle_event(&key('k'));
        assert_eq!(
            app.save_count, before,
            "navigation must not persist the vault"
        );

        // Delete the loose `Root1` entry: `d` opens the confirm overlay, `y`
        // commits → exactly one save through the choke point.
        app.handle_event(&key('j')); // select the Root1 entry
        assert!(
            app.selected_entry_uuid().is_some(),
            "an entry must be selected for the delete"
        );
        app.handle_event(&key('d')); // open delete-confirm (no save)
        assert_eq!(app.save_count, before, "opening the confirm must not save");
        app.handle_event(&key('y')); // confirm → persist_vault once
        assert_eq!(
            app.save_count,
            before + 1,
            "a delete performs exactly one atomic write"
        );
    }
}
