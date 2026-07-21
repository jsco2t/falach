//! `Theme` — all color and style decisions in one place.
//!
//! Accessibility discipline (FR-074 / NFR-015): every visual signal must have
//! a **text or style carrier**, never color alone. The style accessors below
//! therefore always add a `Modifier` (reverse / bold / dim) so they remain
//! distinguishable on a `Monochrome` palette and under screen readers; color,
//! where the palette has it, is an *additional* affordance, not the only one.
//!
//! **Theme detection (T7.1):** [`Theme::auto`] inspects the environment —
//! `FALACH_TUI_THEME=accessible` and `NO_COLOR` (and a `dumb` `TERM`) force the
//! committed `accessible` (Monochrome) theme; `COLORTERM=truecolor`/`24bit`
//! selects the truecolor `default`; everything else falls back to the
//! broadly-compatible 16-colour `default`. The pure [`Theme::from_env_parts`]
//! holds the decision ladder so the full matrix is testable without mutating
//! (racy) process environment (the `#[ignore]`d wiring tests cover `auto`).
//!
//! Some palette fields/accessors are part of a forward API not read from every
//! call site yet; `allow(dead_code)` is scoped to this module.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use ratatui::style::{Color, Modifier, Style};
use serde::Deserialize;

/// A named palette plus its capability tier.
#[derive(Debug, Clone)]
pub(crate) struct Theme {
    pub(crate) name: String,
    pub(crate) palette: Palette,
}

/// Terminal color capability tiers.
#[derive(Debug, Clone)]
pub(crate) enum Palette {
    /// 24-bit color; emphasis via color contrast + bold/underline/reverse.
    TrueColor(PaletteColors),
    /// 16-color terminal — restricted palette, but bold/underline/reverse work.
    Color16(PaletteColors),
    /// No color at all — bold / underline / reverse only.
    Monochrome,
}

/// The full set of themeable colors — one value per semantic slot (design
/// §2.2.4; grew from 5 role colors to 14 slots in T3.3). The same shape backs
/// both the truecolor and 16-color tiers — a tier is just a different set of
/// values (RGB vs the 16 ANSI colors). `Monochrome` carries no colors at all.
///
/// A [`ThemePatch`] overrides any subset of these; tier enforcement (mono
/// ignores colors; 16-color clamps user RGB patches) happens after patching.
#[derive(Debug, Clone)]
pub(crate) struct PaletteColors {
    // The five original role colors.
    pub(crate) accent: Color,
    pub(crate) muted: Color,
    pub(crate) warn: Color,
    pub(crate) error: Color,
    pub(crate) good: Color,
    // Selection surfaces (list/tree highlight).
    pub(crate) selection_bg: Color,
    pub(crate) selection_fg: Color,
    // Fuzzy-match highlight characters (T4.2).
    pub(crate) match_hl: Color,
    // Borders and tabs.
    pub(crate) border: Color,
    pub(crate) border_focused: Color,
    pub(crate) tab_active: Color,
    pub(crate) tab_inactive: Color,
    // Hint bar / which-key / palette keys + descriptions.
    pub(crate) hint_key: Color,
    pub(crate) hint_desc: Color,
}

impl Theme {
    /// Auto-detect the theme from the process environment (T7.1).
    ///
    /// Reads `FALACH_TUI_THEME`, `NO_COLOR`, `TERM`, and `COLORTERM` and
    /// delegates to [`Theme::from_env_parts`] for the decision ladder.
    pub(crate) fn auto() -> Self {
        let theme_override = std::env::var("FALACH_TUI_THEME").ok();
        // `NO_COLOR` honours *presence* (any value, including empty) per
        // <https://no-color.org>, hence `var_os(..).is_some()`, not non-empty.
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let term = std::env::var("TERM").ok();
        let colorterm = std::env::var("COLORTERM").ok();
        Self::from_env_parts(
            theme_override.as_deref(),
            no_color,
            term.as_deref(),
            colorterm.as_deref(),
        )
    }

    /// The pure detection ladder behind [`Theme::auto`] (design §2.2.4), split
    /// out so the full matrix is testable without mutating process env:
    ///
    /// 1. `FALACH_TUI_THEME=accessible` → the `accessible` (Monochrome) theme.
    /// 2. `NO_COLOR` present (any value) → Monochrome.
    /// 3. `TERM=dumb` → Monochrome (a dumb terminal cannot style).
    /// 4. `COLORTERM=truecolor|24bit` → the truecolor `default`.
    /// 5. otherwise → the broadly-compatible 16-colour `default`.
    pub(crate) fn from_env_parts(
        theme_override: Option<&str>,
        no_color: bool,
        term: Option<&str>,
        colorterm: Option<&str>,
    ) -> Self {
        if theme_override == Some("accessible") || no_color || term == Some("dumb") {
            return Self::accessible();
        }
        match colorterm {
            Some("truecolor" | "24bit") => Self::truecolor_default(),
            _ => Self::color16_default(),
        }
    }

    /// The default truecolor theme (24-bit terminals) — the `default-dark`
    /// built-in. Named `"default"` for backward-compatible env detection; the
    /// theme *resolution* ladder (T3.4) selects built-ins by their catalog name.
    fn truecolor_default() -> Self {
        Self {
            name: "default".to_string(),
            palette: Palette::TrueColor(builtins::dark_truecolor()),
        }
    }

    /// The default 16-colour theme — the broadly-compatible fallback
    /// (`default-dark`'s explicit ANSI-16 variant).
    fn color16_default() -> Self {
        Self {
            name: "default".to_string(),
            palette: Palette::Color16(builtins::dark_color16()),
        }
    }

    /// The committed `accessible` (Monochrome) theme — the screen-reader /
    /// `NO_COLOR` path. Every signal is carried by a text/style affordance,
    /// never colour (FR-074 / NFR-015).
    pub(crate) fn accessible() -> Self {
        Self {
            name: "accessible".to_string(),
            palette: Palette::Monochrome,
        }
    }

    /// Resolve one slot to its color, or `None` on `Monochrome` (which carries
    /// no colors — every signal then rides its modifier + text carrier). `pick`
    /// selects the slot field from whichever tier's [`PaletteColors`] is active.
    fn color(&self, pick: impl Fn(&PaletteColors) -> Color) -> Option<Color> {
        match &self.palette {
            Palette::TrueColor(p) | Palette::Color16(p) => Some(pick(p)),
            Palette::Monochrome => None,
        }
    }

    fn accent(&self) -> Option<Color> {
        self.color(|p| p.accent)
    }
    fn muted_color(&self) -> Option<Color> {
        self.color(|p| p.muted)
    }
    fn warn_color(&self) -> Option<Color> {
        self.color(|p| p.warn)
    }
    fn error_color(&self) -> Option<Color> {
        self.color(|p| p.error)
    }
    fn good_color(&self) -> Option<Color> {
        self.color(|p| p.good)
    }

    /// Apply an optional foreground color on top of a base style.
    fn with_fg(base: Style, color: Option<Color>) -> Style {
        match color {
            Some(c) => base.fg(c),
            None => base,
        }
    }

    /// Selected row — always reverse-video (carrier); the dedicated selection
    /// foreground/background slots supply the palette affordance.
    pub(crate) fn selected(&self) -> Style {
        let style = Style::new().add_modifier(Modifier::REVERSED);
        match &self.palette {
            Palette::TrueColor(p) | Palette::Color16(p) => {
                // REVERSED is the non-color carrier and swaps these at the
                // terminal, so assign them pre-swapped to preserve the slot
                // contract in the rendered result.
                style.fg(p.selection_bg).bg(p.selection_fg)
            }
            Palette::Monochrome => style,
        }
    }

    /// Expired entry — always bold (carrier); warn fg where available. The full
    /// affordance pairs this with a ` (expired)` text suffix at the call site.
    pub(crate) fn expired(&self) -> Style {
        Self::with_fg(Style::new().add_modifier(Modifier::BOLD), self.warn_color())
    }

    /// Modified-since-save — always bold (carrier); accent fg where available.
    /// Paired with a `* ` text prefix at the call site.
    pub(crate) fn modified(&self) -> Style {
        Self::with_fg(Style::new().add_modifier(Modifier::BOLD), self.accent())
    }

    /// Section / column header — bold.
    ///
    /// Takes `&self` for API uniformity with the other accessors (and so a
    /// future palette can vary the header color); the current style is
    /// palette-independent.
    #[allow(clippy::unused_self)]
    pub(crate) fn header(&self) -> Style {
        Style::new().add_modifier(Modifier::BOLD)
    }

    /// Less-important text — dim (carrier); muted fg where available.
    pub(crate) fn muted(&self) -> Style {
        Self::with_fg(Style::new().add_modifier(Modifier::DIM), self.muted_color())
    }

    /// Warning — bold (carrier); warn fg where available.
    pub(crate) fn warning(&self) -> Style {
        Self::with_fg(Style::new().add_modifier(Modifier::BOLD), self.warn_color())
    }

    /// Error — bold (carrier); error fg where available.
    pub(crate) fn error(&self) -> Style {
        Self::with_fg(
            Style::new().add_modifier(Modifier::BOLD),
            self.error_color(),
        )
    }

    /// Success — bold (carrier); good fg where available.
    pub(crate) fn good(&self) -> Style {
        Self::with_fg(Style::new().add_modifier(Modifier::BOLD), self.good_color())
    }

    // --- T3.3 slots. Each keeps a modifier carrier so it survives Monochrome
    // and screen readers (FR-074 / NFR-015); color is an additional affordance.

    /// Fuzzy-match highlight characters — always bold (carrier); `match_hl` fg.
    pub(crate) fn match_hl(&self) -> Style {
        Self::with_fg(
            Style::new().add_modifier(Modifier::BOLD),
            self.color(|p| p.match_hl),
        )
    }

    /// A hint-bar / which-key / palette key — always bold (carrier); `hint_key` fg.
    pub(crate) fn hint_key(&self) -> Style {
        Self::with_fg(
            Style::new().add_modifier(Modifier::BOLD),
            self.color(|p| p.hint_key),
        )
    }

    /// A hint-bar / palette description — a plain label (no signal of its own;
    /// the paired key carries the emphasis), so no modifier. `hint_desc` fg
    /// where available; on Monochrome it is plain default text.
    pub(crate) fn hint_desc(&self) -> Style {
        Self::with_fg(Style::new(), self.color(|p| p.hint_desc))
    }

    /// Unfocused pane border — dim (carrier); `border` fg where available.
    pub(crate) fn border(&self) -> Style {
        Self::with_fg(
            Style::new().add_modifier(Modifier::DIM),
            self.color(|p| p.border),
        )
    }

    /// Focused pane border — always bold (carrier); `border_focused` fg.
    pub(crate) fn border_focused(&self) -> Style {
        Self::with_fg(
            Style::new().add_modifier(Modifier::BOLD),
            self.color(|p| p.border_focused),
        )
    }

    /// Active tab — always bold (carrier); `tab_active` fg where available.
    pub(crate) fn tab_active(&self) -> Style {
        Self::with_fg(
            Style::new().add_modifier(Modifier::BOLD),
            self.color(|p| p.tab_active),
        )
    }

    /// Inactive tab — dim (carrier); `tab_inactive` fg where available.
    pub(crate) fn tab_inactive(&self) -> Style {
        Self::with_fg(
            Style::new().add_modifier(Modifier::DIM),
            self.color(|p| p.tab_inactive),
        )
    }
}

/// Terminal color capability tier — the axis the resolution ladder (T3.4)
/// selects along after picking a named theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    TrueColor,
    Color16,
    Monochrome,
}

/// A built-in theme's tier variants. Per A-2 (2026-07-18) every built-in ships
/// an explicit, hand-picked ANSI-16 palette (`color16`) alongside its truecolor
/// palette; RGB→ANSI-16 clamping is used ONLY for user [`ThemePatch`] colors, so
/// nothing we ship depends on clamp quality.
#[derive(Debug, Clone)]
pub(crate) struct ThemeDef {
    pub(crate) name: String,
    /// The `accessible` built-in is Monochrome — it has no colors at any tier.
    pub(crate) monochrome: bool,
    pub(crate) truecolor: PaletteColors,
    pub(crate) color16: PaletteColors,
}

/// The names of every shipped built-in theme, in catalog order (Settings
/// cycling + config resolution key on these).
pub(crate) const BUILTIN_NAMES: &[&str] = &[
    "default-dark",
    "default-light",
    "accessible",
    "slate",
    "paper",
];

impl ThemeDef {
    /// The built-in theme named `name`, or `None`. Five ship (see
    /// [`BUILTIN_NAMES`]); `accessible` is Monochrome.
    pub(crate) fn builtin(name: &str) -> Option<ThemeDef> {
        let def = |name: &str, truecolor, color16| ThemeDef {
            name: name.to_string(),
            monochrome: false,
            truecolor,
            color16,
        };
        Some(match name {
            "default-dark" => def(
                "default-dark",
                builtins::dark_truecolor(),
                builtins::dark_color16(),
            ),
            "default-light" => def(
                "default-light",
                builtins::light_truecolor(),
                builtins::light_color16(),
            ),
            "slate" => def(
                "slate",
                builtins::slate_truecolor(),
                builtins::slate_color16(),
            ),
            "paper" => def(
                "paper",
                builtins::paper_truecolor(),
                builtins::paper_color16(),
            ),
            "accessible" => ThemeDef {
                name: "accessible".to_string(),
                monochrome: true,
                // Unused (monochrome), but kept well-formed.
                truecolor: builtins::dark_truecolor(),
                color16: builtins::dark_color16(),
            },
            _ => return None,
        })
    }

    /// Build a concrete [`Theme`] at `tier`. A monochrome built-in
    /// (`accessible`) ignores the tier and is always [`Palette::Monochrome`];
    /// otherwise the tier picks the truecolor or 16-color palette (or forces
    /// Monochrome). Consumed by the resolution ladder (T3.4).
    pub(crate) fn theme_for_tier(&self, tier: Tier) -> Theme {
        if self.monochrome || tier == Tier::Monochrome {
            return Theme {
                name: self.name.clone(),
                palette: Palette::Monochrome,
            };
        }
        let palette = match tier {
            Tier::TrueColor => Palette::TrueColor(self.truecolor.clone()),
            Tier::Color16 => Palette::Color16(self.color16.clone()),
            Tier::Monochrome => unreachable!("handled above"),
        };
        Theme {
            name: self.name.clone(),
            palette,
        }
    }
}

// ---------------------------------------------------------------------------
// ThemePatch — user overrides of any subset of the semantic slots (design
// §2.2.4). Slot names are the `PaletteColors` field names (kebab == snake here,
// single words). Values are `"#rrggbb"` or an ANSI-16 color name. Applied over a
// built-in; unknown slots and unparseable colors warn and are ignored (lenient,
// no-content-echo discipline). Wired into resolution in T3.4.
// ---------------------------------------------------------------------------

/// A non-fatal theme-load warning (slot name / diagnostic only — never the raw
/// file content, §2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThemeWarning {
    pub message: String,
}

/// A partial theme override decoded from a `~/.config/falach/themes/*.toml`.
/// Every slot is optional; unrecognized keys are captured in `extra` so they can
/// be warned about (forward-compat leniency).
#[derive(Debug, Default, Clone, Deserialize)]
pub(crate) struct ThemePatch {
    #[serde(flatten)]
    slots: std::collections::BTreeMap<String, toml::Value>,
}

impl ThemePatch {
    /// Apply this patch over `def`, mutating both tier palettes: the truecolor
    /// slot takes the parsed color; the 16-color slot takes its
    /// nearest-ANSI-16 clamp (so a single user color works on both tiers).
    /// Returns warnings for unknown slots or unparseable colors.
    pub(crate) fn apply(&self, def: &mut ThemeDef) -> Vec<ThemeWarning> {
        let mut warnings = Vec::new();
        for (slot, value) in &self.slots {
            let Some(setter) = slot_setter(slot) else {
                warnings.push(ThemeWarning {
                    message: format!("unknown theme slot `{slot}` (ignored)"),
                });
                continue;
            };
            let parsed = value.as_str().and_then(|s| parse_color(s).ok());
            match parsed {
                Some(color) => {
                    setter(&mut def.truecolor, color);
                    setter(&mut def.color16, clamp_ansi16(color));
                }
                None => warnings.push(ThemeWarning {
                    message: format!("`{slot}`: invalid color (ignored)"),
                }),
            }
        }
        warnings
    }
}

/// Map a slot name to a setter for that [`PaletteColors`] field, or `None` if
/// the name is not a known slot.
fn slot_setter(name: &str) -> Option<fn(&mut PaletteColors, Color)> {
    Some(match name {
        "accent" => |p, c| p.accent = c,
        "muted" => |p, c| p.muted = c,
        "warn" => |p, c| p.warn = c,
        "error" => |p, c| p.error = c,
        "good" => |p, c| p.good = c,
        "selection-bg" => |p, c| p.selection_bg = c,
        "selection-fg" => |p, c| p.selection_fg = c,
        "match-hl" => |p, c| p.match_hl = c,
        "border" => |p, c| p.border = c,
        "border-focused" => |p, c| p.border_focused = c,
        "tab-active" => |p, c| p.tab_active = c,
        "tab-inactive" => |p, c| p.tab_inactive = c,
        "hint-key" => |p, c| p.hint_key = c,
        "hint-desc" => |p, c| p.hint_desc = c,
        _ => return None,
    })
}

/// Parse a color from `"#rrggbb"` or one of the 16 ANSI color names
/// (case-insensitive; spaces or hyphens accepted, e.g. `"light blue"` /
/// `"light-blue"`). Hand-rolled — no color crate (AC-8).
fn parse_color(s: &str) -> Result<Color, ()> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix('#') {
        // Require exactly 6 ASCII hex digits BEFORE slicing: `hex.len()` is a
        // byte count, so slicing `&hex[0..2]` on a multibyte value (e.g.
        // `#1Ω345`, 6 bytes) would panic mid-char. The all-ascii-hexdigit guard
        // makes the byte offsets char-boundary-safe (and the parses infallible).
        if hex.len() == 6 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            let r = u8::from_str_radix(&hex[0..2], 16).map_err(|_| ())?;
            let g = u8::from_str_radix(&hex[2..4], 16).map_err(|_| ())?;
            let b = u8::from_str_radix(&hex[4..6], 16).map_err(|_| ())?;
            return Ok(Color::Rgb(r, g, b));
        }
        return Err(());
    }
    let norm = s.to_ascii_lowercase().replace(['-', '_'], " ");
    Ok(match norm.as_str() {
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "gray" | "grey" => Color::Gray,
        "dark gray" | "dark grey" | "darkgray" => Color::DarkGray,
        "light red" => Color::LightRed,
        "light green" => Color::LightGreen,
        "light yellow" => Color::LightYellow,
        "light blue" => Color::LightBlue,
        "light magenta" => Color::LightMagenta,
        "light cyan" => Color::LightCyan,
        "white" => Color::White,
        _ => return Err(()),
    })
}

/// The RGB anchors for the 16 ANSI colors (standard xterm values). Used only by
/// [`clamp_ansi16`].
const ANSI16_ANCHORS: [(Color, (u8, u8, u8)); 16] = [
    (Color::Black, (0x00, 0x00, 0x00)),
    (Color::Red, (0x80, 0x00, 0x00)),
    (Color::Green, (0x00, 0x80, 0x00)),
    (Color::Yellow, (0x80, 0x80, 0x00)),
    (Color::Blue, (0x00, 0x00, 0x80)),
    (Color::Magenta, (0x80, 0x00, 0x80)),
    (Color::Cyan, (0x00, 0x80, 0x80)),
    (Color::Gray, (0xc0, 0xc0, 0xc0)),
    (Color::DarkGray, (0x80, 0x80, 0x80)),
    (Color::LightRed, (0xff, 0x00, 0x00)),
    (Color::LightGreen, (0x00, 0xff, 0x00)),
    (Color::LightYellow, (0xff, 0xff, 0x00)),
    (Color::LightBlue, (0x00, 0x00, 0xff)),
    (Color::LightMagenta, (0xff, 0x00, 0xff)),
    (Color::LightCyan, (0x00, 0xff, 0xff)),
    (Color::White, (0xff, 0xff, 0xff)),
];

/// Clamp a color to the nearest of the 16 ANSI colors by squared RGB distance.
/// A non-RGB color (already an ANSI-16 named color) is returned unchanged.
/// Used only for user [`ThemePatch`] colors on 16-color terminals — built-ins
/// ship explicit ANSI-16 palettes (A-2).
fn clamp_ansi16(c: Color) -> Color {
    let Color::Rgb(r, g, b) = c else {
        return c;
    };
    let (r, g, b) = (i32::from(r), i32::from(g), i32::from(b));
    ANSI16_ANCHORS
        .iter()
        .min_by_key(|(_, (ar, ag, ab))| {
            let (dr, dg, db) = (r - i32::from(*ar), g - i32::from(*ag), b - i32::from(*ab));
            dr * dr + dg * dg + db * db
        })
        .map_or(Color::White, |(color, _)| *color)
}

// ---------------------------------------------------------------------------
// Theme resolution ladder (T3.4). Pure and testable: tier from env × name from
// flag/config × light/dark mode × user-theme patches. Wired to startup +
// Settings-tab switching in `app.rs`.
// ---------------------------------------------------------------------------

use crate::user_config::{ThemeCfg, ThemeMode};

/// The environment inputs to the resolution ladder, split out so the full
/// matrix is testable without mutating process env (the `from_env_parts`
/// precedent).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct EnvParts<'a> {
    /// `FALACH_TUI_THEME` — the accessibility escape hatch (only `"accessible"`
    /// is recognized; it forces Monochrome and wins over everything).
    pub theme_override: Option<&'a str>,
    /// `NO_COLOR` present (any value).
    pub no_color: bool,
    /// `TERM`.
    pub term: Option<&'a str>,
    /// `COLORTERM`.
    pub colorterm: Option<&'a str>,
    /// `COLORFGBG` (e.g. `"15;0"`) — the light/dark background heuristic.
    pub colorfgbg: Option<&'a str>,
}

/// A user theme selection source. Production discovery records only the path;
/// tests can inject an already-parsed patch to keep resolution deterministic.
#[derive(Debug, Clone)]
pub(crate) struct UserThemeFile {
    /// The file stem — the name users select in config / `--theme`.
    pub name: String,
    source: UserThemeSource,
}

#[derive(Debug, Clone)]
enum UserThemeSource {
    File(PathBuf),
    Patch(ThemePatch),
}

impl UserThemeFile {
    #[cfg(test)]
    fn from_patch(name: &str, patch: ThemePatch) -> Self {
        Self {
            name: name.to_string(),
            source: UserThemeSource::Patch(patch),
        }
    }

    fn load_patch(&self) -> Result<ThemePatch, ThemeWarning> {
        match &self.source {
            UserThemeSource::Patch(patch) => Ok(patch.clone()),
            UserThemeSource::File(path) => {
                let contents = std::fs::read_to_string(path).map_err(|_| ThemeWarning {
                    message: format!("Could not read theme {}", path.display()),
                })?;
                toml::from_str(&contents).map_err(|error: toml::de::Error| {
                    let line = error.span().map(|span| {
                        contents[..span.start.min(contents.len())]
                            .bytes()
                            .filter(|&byte| byte == b'\n')
                            .count()
                            + 1
                    });
                    let at = line
                        .map(|line| format!(" (line {line})"))
                        .unwrap_or_default();
                    ThemeWarning {
                        message: format!("Could not parse theme {}{at}", path.display()),
                    }
                })
            }
        }
    }
}

/// Discover `*.toml` user themes without reading their contents. The selected
/// file is parsed lazily by [`resolve_theme`].
pub(crate) fn discover_user_themes(dir: &Path) -> (Vec<UserThemeFile>, Vec<ThemeWarning>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), Vec::new()),
        Err(_) => {
            return (
                Vec::new(),
                vec![ThemeWarning {
                    message: format!("Could not read theme directory {}", dir.display()),
                }],
            )
        }
    };
    let mut warnings = Vec::new();
    let mut themes = entries
        .filter_map(|entry| {
            let Ok(entry) = entry else {
                warnings.push(ThemeWarning {
                    message: format!("Could not read an entry in {}", dir.display()),
                });
                return None;
            };
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                return None;
            }
            let name = path.file_stem()?.to_str()?.to_string();
            Some(UserThemeFile {
                name,
                source: UserThemeSource::File(path),
            })
        })
        .collect::<Vec<_>>();
    themes.sort_by(|left, right| left.name.cmp(&right.name));
    (themes, warnings)
}

impl EnvParts<'_> {
    /// Whether env forces the Monochrome `accessible` theme (wins over config +
    /// flag): `FALACH_TUI_THEME=accessible`, `NO_COLOR`, or `TERM=dumb`.
    pub(crate) fn forces_monochrome(&self) -> bool {
        self.theme_override == Some("accessible") || self.no_color || self.term == Some("dumb")
    }

    /// The capability tier when color is allowed: `TrueColor` if `COLORTERM`
    /// advertises it, else the broadly-compatible 16-color tier.
    fn color_tier(&self) -> Tier {
        match self.colorterm {
            Some("truecolor" | "24bit") => Tier::TrueColor,
            _ => Tier::Color16,
        }
    }
}

/// The light/dark decision (ladder step 3): explicit `mode` override, else the
/// `COLORFGBG` heuristic, else dark. Exposed so the Settings tab knows which
/// config field (`theme.dark` vs `theme.light`) a theme cycle should edit.
pub(crate) fn wants_light(env: EnvParts, mode: ThemeMode) -> bool {
    match mode {
        ThemeMode::Light => true,
        ThemeMode::Dark => false,
        ThemeMode::Auto => colorfgbg_is_light(env.colorfgbg),
    }
}

/// Does `COLORFGBG` indicate a light background? Format is `fg;bg` (sometimes
/// `fg;default;bg`); the last component is the background ANSI index — `>= 7`
/// (bright/white range) reads as light. Absent/unparseable → dark.
fn colorfgbg_is_light(colorfgbg: Option<&str>) -> bool {
    colorfgbg
        .and_then(|s| s.rsplit(';').next())
        .and_then(|bg| bg.trim().parse::<u8>().ok())
        .is_some_and(|bg| bg >= 7)
}

/// Resolve the effective theme from the full ladder (design §2.2.4):
/// 1. env accessibility (`accessible`/`NO_COLOR`/`dumb`) → Monochrome, STOP;
/// 2. capability tier from `COLORTERM`;
/// 3. light/dark mode: `cfg.mode` override > `COLORFGBG` heuristic > dark;
/// 4. name: `flag` > (light ? `cfg.light` : `cfg.dark`);
/// 5. name → built-in, else a user theme file stem (patch over the tier-default
///    built-in), else warn + `default-dark`;
/// 6. tier selection → concrete palette.
///
/// Returns the resolved [`Theme`] plus any non-fatal warnings (unknown name,
/// patch-apply issues).
pub(crate) fn resolve_theme(
    env: EnvParts,
    cfg: &ThemeCfg,
    flag: Option<&str>,
    user_themes: &[UserThemeFile],
) -> (Theme, Vec<ThemeWarning>) {
    // 1. Accessibility short-circuit — wins over config and flag.
    if env.forces_monochrome() {
        return (Theme::accessible(), Vec::new());
    }

    let tier = env.color_tier();

    // 3. Light/dark selection.
    let light = wants_light(env, cfg.mode);

    // 4. Name: CLI flag wins, else the configured dark/light name.
    let name = flag.unwrap_or(if light { &cfg.light } else { &cfg.dark });

    let mut warnings = Vec::new();

    // 5. Resolve the name to a ThemeDef.
    let mut def = if let Some(def) = ThemeDef::builtin(name) {
        def
    } else if let Some(user) = user_themes.iter().find(|u| u.name == name) {
        // A user theme is a patch over the tier-appropriate built-in base.
        let base = if light {
            "default-light"
        } else {
            "default-dark"
        };
        let mut def = ThemeDef::builtin(base).expect("built-in base always resolves");
        match user.load_patch() {
            Ok(patch) => warnings.extend(patch.apply(&mut def)),
            Err(warning) => {
                warnings.push(warning);
                return (
                    ThemeDef::builtin("default-dark")
                        .expect("built-in fallback")
                        .theme_for_tier(tier),
                    warnings,
                );
            }
        }
        def.name.clone_from(&user.name);
        def
    } else {
        warnings.push(ThemeWarning {
            message: format!("unknown theme `{name}` — using default-dark"),
        });
        ThemeDef::builtin("default-dark").expect("built-in base always resolves")
    };

    // Preserve the user's chosen name on the resolved def (for the eprintln /
    // Settings display) unless it was a fallback.
    if ThemeDef::builtin(name).is_some() {
        def.name = name.to_string();
    }

    (def.theme_for_tier(tier), warnings)
}

/// The built-in palettes. Light-theme RGBs are provisional and marked for
/// real-terminal tuning in T5.3.
mod builtins {
    use super::PaletteColors;
    use ratatui::style::Color;

    pub(super) fn dark_truecolor() -> PaletteColors {
        PaletteColors {
            accent: Color::Rgb(0x7a, 0xa2, 0xf7),
            muted: Color::Rgb(0x6c, 0x70, 0x86),
            warn: Color::Rgb(0xe0, 0xaf, 0x68),
            error: Color::Rgb(0xf7, 0x76, 0x8e),
            good: Color::Rgb(0x9e, 0xce, 0x6a),
            selection_bg: Color::Rgb(0x28, 0x34, 0x57),
            selection_fg: Color::Rgb(0xc0, 0xca, 0xf5),
            match_hl: Color::Rgb(0xf6, 0xd3, 0x2d),
            border: Color::Rgb(0x41, 0x48, 0x68),
            border_focused: Color::Rgb(0x7a, 0xa2, 0xf7),
            tab_active: Color::Rgb(0x7a, 0xa2, 0xf7),
            tab_inactive: Color::Rgb(0x6c, 0x70, 0x86),
            hint_key: Color::Rgb(0x7a, 0xa2, 0xf7),
            hint_desc: Color::Rgb(0xa9, 0xb1, 0xd6),
        }
    }

    pub(super) fn dark_color16() -> PaletteColors {
        PaletteColors {
            accent: Color::Cyan,
            muted: Color::DarkGray,
            warn: Color::Yellow,
            error: Color::Red,
            good: Color::Green,
            selection_bg: Color::Blue,
            selection_fg: Color::White,
            match_hl: Color::Yellow,
            border: Color::DarkGray,
            border_focused: Color::Cyan,
            tab_active: Color::Cyan,
            tab_inactive: Color::DarkGray,
            hint_key: Color::Cyan,
            hint_desc: Color::Gray,
        }
    }

    // tuned: pending T5.3 display verification
    pub(super) fn light_truecolor() -> PaletteColors {
        PaletteColors {
            accent: Color::Rgb(0x2e, 0x7d, 0xe9),
            muted: Color::Rgb(0x89, 0x90, 0xb3),
            warn: Color::Rgb(0x8c, 0x6c, 0x3e),
            error: Color::Rgb(0xc6, 0x43, 0x43),
            good: Color::Rgb(0x58, 0x75, 0x39),
            selection_bg: Color::Rgb(0xd5, 0xd9, 0xe3),
            selection_fg: Color::Rgb(0x37, 0x60, 0xbf),
            match_hl: Color::Rgb(0x8c, 0x6c, 0x00),
            border: Color::Rgb(0xc4, 0xc8, 0xda),
            border_focused: Color::Rgb(0x2e, 0x7d, 0xe9),
            tab_active: Color::Rgb(0x2e, 0x7d, 0xe9),
            tab_inactive: Color::Rgb(0x89, 0x90, 0xb3),
            hint_key: Color::Rgb(0x2e, 0x7d, 0xe9),
            hint_desc: Color::Rgb(0x61, 0x72, 0xb0),
        }
    }

    // tuned: pending T5.3 display verification — dark ANSI colors readable on a
    // light background (no Yellow/White/bright-on-light traps).
    pub(super) fn light_color16() -> PaletteColors {
        PaletteColors {
            accent: Color::Blue,
            muted: Color::DarkGray,
            warn: Color::Magenta,
            error: Color::Red,
            good: Color::Green,
            selection_bg: Color::Gray,
            selection_fg: Color::Black,
            match_hl: Color::Blue,
            border: Color::DarkGray,
            border_focused: Color::Blue,
            tab_active: Color::Blue,
            tab_inactive: Color::DarkGray,
            hint_key: Color::Blue,
            hint_desc: Color::Black,
        }
    }

    pub(super) fn slate_truecolor() -> PaletteColors {
        PaletteColors {
            accent: Color::Rgb(0x6e, 0xa8, 0xfe),
            muted: Color::Rgb(0x7c, 0x84, 0x95),
            warn: Color::Rgb(0xd0, 0xa2, 0x48),
            error: Color::Rgb(0xe0, 0x6c, 0x75),
            good: Color::Rgb(0x8f, 0xbf, 0x7f),
            selection_bg: Color::Rgb(0x2d, 0x33, 0x43),
            selection_fg: Color::Rgb(0xcd, 0xd6, 0xe5),
            match_hl: Color::Rgb(0xe5, 0xc0, 0x7b),
            border: Color::Rgb(0x3b, 0x42, 0x52),
            border_focused: Color::Rgb(0x6e, 0xa8, 0xfe),
            tab_active: Color::Rgb(0x6e, 0xa8, 0xfe),
            tab_inactive: Color::Rgb(0x7c, 0x84, 0x95),
            hint_key: Color::Rgb(0x6e, 0xa8, 0xfe),
            hint_desc: Color::Rgb(0xb0, 0xb8, 0xc8),
        }
    }

    pub(super) fn slate_color16() -> PaletteColors {
        PaletteColors {
            accent: Color::Blue,
            muted: Color::DarkGray,
            warn: Color::Yellow,
            error: Color::Red,
            good: Color::Green,
            selection_bg: Color::Blue,
            selection_fg: Color::White,
            match_hl: Color::Cyan,
            border: Color::DarkGray,
            border_focused: Color::Blue,
            tab_active: Color::Blue,
            tab_inactive: Color::DarkGray,
            hint_key: Color::Blue,
            hint_desc: Color::Gray,
        }
    }

    // tuned: pending T5.3 display verification
    pub(super) fn paper_truecolor() -> PaletteColors {
        PaletteColors {
            accent: Color::Rgb(0xb5, 0x65, 0x1d),
            muted: Color::Rgb(0x9a, 0x8f, 0x80),
            warn: Color::Rgb(0x8a, 0x6d, 0x00),
            error: Color::Rgb(0xb0, 0x2e, 0x2e),
            good: Color::Rgb(0x4f, 0x7a, 0x2a),
            selection_bg: Color::Rgb(0xec, 0xe3, 0xd0),
            selection_fg: Color::Rgb(0x5b, 0x46, 0x36),
            match_hl: Color::Rgb(0x8a, 0x6d, 0x00),
            border: Color::Rgb(0xd9, 0xcf, 0xbc),
            border_focused: Color::Rgb(0xb5, 0x65, 0x1d),
            tab_active: Color::Rgb(0xb5, 0x65, 0x1d),
            tab_inactive: Color::Rgb(0x9a, 0x8f, 0x80),
            hint_key: Color::Rgb(0xb5, 0x65, 0x1d),
            hint_desc: Color::Rgb(0x6b, 0x5d, 0x4a),
        }
    }

    // tuned: pending T5.3 display verification
    pub(super) fn paper_color16() -> PaletteColors {
        PaletteColors {
            accent: Color::Red,
            muted: Color::DarkGray,
            warn: Color::Magenta,
            error: Color::Red,
            good: Color::Green,
            selection_bg: Color::Gray,
            selection_fg: Color::Black,
            match_hl: Color::Red,
            border: Color::DarkGray,
            border_focused: Color::Red,
            tab_active: Color::Red,
            tab_inactive: Color::DarkGray,
            hint_key: Color::Red,
            hint_desc: Color::Black,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All three palettes, for accessor exercise.
    fn all_palettes() -> Vec<Palette> {
        vec![
            Palette::TrueColor(builtins::dark_truecolor()),
            Palette::Color16(builtins::dark_color16()),
            Palette::Monochrome,
        ]
    }

    fn theme_with(palette: Palette) -> Theme {
        Theme {
            name: "test".to_string(),
            palette,
        }
    }

    /// Every style accessor returns a non-empty `Style` on every palette — the
    /// FR-074 "never color alone" guarantee depends on a modifier always being
    /// present, including on `Monochrome` where no color is available.
    #[test]
    fn every_accessor_is_nonempty_on_every_palette() {
        for palette in all_palettes() {
            let t = theme_with(palette.clone());
            let styles = [
                ("selected", t.selected()),
                ("expired", t.expired()),
                ("modified", t.modified()),
                ("header", t.header()),
                ("muted", t.muted()),
                ("warning", t.warning()),
                ("error", t.error()),
                ("good", t.good()),
            ];
            for (name, style) in styles {
                assert_ne!(
                    style,
                    Style::default(),
                    "{name} produced an empty style on {palette:?}"
                );
            }
        }
    }

    #[test]
    fn selected_always_carries_reverse() {
        for palette in all_palettes() {
            let t = theme_with(palette);
            assert!(
                t.selected().add_modifier.contains(Modifier::REVERSED),
                "selected must carry REVERSED"
            );
        }
    }

    #[test]
    fn expired_and_modified_always_carry_bold() {
        for palette in all_palettes() {
            let t = theme_with(palette);
            assert!(t.expired().add_modifier.contains(Modifier::BOLD));
            assert!(t.modified().add_modifier.contains(Modifier::BOLD));
        }
    }

    // ---- §8.2.3 detection matrix (pure; parallel-safe, no env mutation) ----

    #[test]
    fn from_env_accessible_override_forces_monochrome() {
        // The override wins even when truecolor is otherwise available.
        let t = Theme::from_env_parts(Some("accessible"), false, Some("xterm"), Some("truecolor"));
        assert!(matches!(t.palette, Palette::Monochrome));
        assert_eq!(t.name, "accessible");
    }

    #[test]
    fn from_env_no_color_forces_monochrome() {
        let t = Theme::from_env_parts(None, true, None, Some("truecolor"));
        assert!(matches!(t.palette, Palette::Monochrome));
        assert_eq!(t.name, "accessible");
    }

    #[test]
    fn from_env_dumb_term_forces_monochrome() {
        let t = Theme::from_env_parts(None, false, Some("dumb"), Some("truecolor"));
        assert!(matches!(t.palette, Palette::Monochrome));
    }

    #[test]
    fn from_env_colorterm_truecolor_and_24bit_select_truecolor() {
        for ct in ["truecolor", "24bit"] {
            let t = Theme::from_env_parts(None, false, Some("xterm"), Some(ct));
            assert!(matches!(t.palette, Palette::TrueColor(_)), "COLORTERM={ct}");
            assert_eq!(t.name, "default");
        }
    }

    #[test]
    fn from_env_no_relevant_signal_falls_back_to_color16() {
        let t = Theme::from_env_parts(None, false, Some("xterm-256color"), None);
        assert!(matches!(t.palette, Palette::Color16(_)));
        assert_eq!(t.name, "default");
    }

    #[test]
    fn from_env_non_accessible_override_defers_to_ladder() {
        // Only "accessible" is a recognized override; any other value falls
        // through to the COLORTERM/fallback rungs.
        let t = Theme::from_env_parts(Some("default"), false, None, Some("truecolor"));
        assert!(matches!(t.palette, Palette::TrueColor(_)));
    }

    /// NFR-015: the Monochrome palette must emit no foreground colour at all —
    /// every signal then rides its modifier (reverse/bold/dim) + text carrier.
    #[test]
    fn monochrome_palette_styles_have_no_fg_color() {
        let t = Theme::accessible();
        let styles = [
            ("selected", t.selected()),
            ("expired", t.expired()),
            ("modified", t.modified()),
            ("header", t.header()),
            ("muted", t.muted()),
            ("warning", t.warning()),
            ("error", t.error()),
            ("good", t.good()),
        ];
        for (name, style) in styles {
            assert_eq!(
                style.fg, None,
                "{name} must emit no fg colour on monochrome"
            );
        }
    }

    // ---- §8.2.11 theme system: built-ins, ThemePatch, clamp (T3.3) ----

    fn patch(toml_src: &str) -> ThemePatch {
        toml::from_str(toml_src).expect("theme patch fixture should parse")
    }

    /// Every slot color of a `PaletteColors`, for iteration.
    fn all_slot_colors(p: &PaletteColors) -> [Color; 14] {
        [
            p.accent,
            p.muted,
            p.warn,
            p.error,
            p.good,
            p.selection_bg,
            p.selection_fg,
            p.match_hl,
            p.border,
            p.border_focused,
            p.tab_active,
            p.tab_inactive,
            p.hint_key,
            p.hint_desc,
        ]
    }

    /// Signal styles that MUST always carry a modifier (NFR-015 carrier).
    /// `hint_desc` is deliberately excluded — it is a plain label, not a signal.
    fn signal_styles(t: &Theme) -> Vec<(&'static str, Style)> {
        vec![
            ("selected", t.selected()),
            ("expired", t.expired()),
            ("modified", t.modified()),
            ("header", t.header()),
            ("muted", t.muted()),
            ("warning", t.warning()),
            ("error", t.error()),
            ("good", t.good()),
            ("match_hl", t.match_hl()),
            ("hint_key", t.hint_key()),
            ("border", t.border()),
            ("border_focused", t.border_focused()),
            ("tab_active", t.tab_active()),
            ("tab_inactive", t.tab_inactive()),
        ]
    }

    #[test]
    fn builtins_resolve_by_name() {
        for name in BUILTIN_NAMES {
            assert!(
                ThemeDef::builtin(name).is_some(),
                "built-in {name} must resolve"
            );
        }
        assert!(ThemeDef::builtin("no-such-theme").is_none());
    }

    #[test]
    fn semantic_accessors_use_configured_slots() {
        let theme = ThemeDef::builtin("default-dark")
            .unwrap()
            .theme_for_tier(Tier::TrueColor);
        let Palette::TrueColor(p) = &theme.palette else {
            panic!("truecolor")
        };
        assert_eq!(theme.selected().fg, Some(p.selection_bg));
        assert_eq!(theme.selected().bg, Some(p.selection_fg));
        assert!(theme.selected().add_modifier.contains(Modifier::REVERSED));
        assert_eq!(theme.border().fg, Some(p.border));
        assert_eq!(theme.border_focused().fg, Some(p.border_focused));
        assert_eq!(theme.tab_active().fg, Some(p.tab_active));
        assert_eq!(theme.tab_inactive().fg, Some(p.tab_inactive));
    }

    #[test]
    fn builtin_color16_uses_only_ansi16() {
        // A-2: every built-in's 16-color variant is hand-picked from the ANSI-16
        // set — never an Rgb value (which a 16-color terminal cannot render).
        for name in BUILTIN_NAMES {
            let def = ThemeDef::builtin(name).unwrap();
            if def.monochrome {
                continue;
            }
            for c in all_slot_colors(&def.color16) {
                assert!(
                    !matches!(c, Color::Rgb(..) | Color::Indexed(_)),
                    "built-in {name} color16 slot uses a non-ANSI-16 color: {c:?}"
                );
            }
        }
    }

    #[test]
    fn theme_patch_applies_only_named_slots() {
        let mut def = ThemeDef::builtin("default-dark").unwrap();
        let before = def.truecolor.clone();
        let warnings = patch("accent = \"#123456\"\nmatch-hl = \"#abcdef\"").apply(&mut def);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(def.truecolor.accent, Color::Rgb(0x12, 0x34, 0x56));
        assert_eq!(def.truecolor.match_hl, Color::Rgb(0xab, 0xcd, 0xef));
        // Untouched slots keep their built-in values.
        assert_eq!(def.truecolor.muted, before.muted);
        assert_eq!(def.truecolor.good, before.good);
        assert_eq!(def.truecolor.border, before.border);
    }

    #[test]
    fn patch_affects_both_tiers_with_clamping() {
        let mut def = ThemeDef::builtin("default-dark").unwrap();
        patch("match-hl = \"#ff0000\"").apply(&mut def);
        // Truecolor tier gets the exact RGB; the 16-color tier gets the nearest
        // ANSI-16 clamp — from ONE user color, both tiers work.
        assert_eq!(def.truecolor.match_hl, Color::Rgb(0xff, 0x00, 0x00));
        assert_eq!(def.color16.match_hl, Color::LightRed);
    }

    #[test]
    fn rgb_clamp_maps_to_nearest_ansi16() {
        // Exact-anchor inputs pin the clamp deterministically (a mis-tabled
        // anchor yields invisible text on 16-color terminals).
        let cases = [
            (Color::Rgb(0x00, 0x00, 0x00), Color::Black),
            (Color::Rgb(0xff, 0xff, 0xff), Color::White),
            (Color::Rgb(0xff, 0x00, 0x00), Color::LightRed),
            (Color::Rgb(0x00, 0xff, 0x00), Color::LightGreen),
            (Color::Rgb(0x00, 0x00, 0xff), Color::LightBlue),
            (Color::Rgb(0x80, 0x80, 0x80), Color::DarkGray),
            (Color::Rgb(0xc0, 0xc0, 0xc0), Color::Gray),
            // A near-black gray clamps to Black, not DarkGray.
            (Color::Rgb(0x01, 0x01, 0x01), Color::Black),
        ];
        for (input, expected) in cases {
            assert_eq!(clamp_ansi16(input), expected, "clamp of {input:?}");
        }
        // An already-ANSI color passes through unchanged.
        assert_eq!(clamp_ansi16(Color::Cyan), Color::Cyan);
    }

    #[test]
    fn tier_enforcement_survives_hostile_patch() {
        // AC-4: a hostile all-#010101 user patch must NEVER break the FR-074 /
        // NFR-015 invariants on any built-in at any tier — every signal keeps its
        // modifier, and Monochrome emits no color at all.
        let hostile = patch(
            "accent=\"#010101\"\nmuted=\"#010101\"\nwarn=\"#010101\"\nerror=\"#010101\"\n\
             good=\"#010101\"\nselection-bg=\"#010101\"\nselection-fg=\"#010101\"\n\
             match-hl=\"#010101\"\nborder=\"#010101\"\nborder-focused=\"#010101\"\n\
             tab-active=\"#010101\"\ntab-inactive=\"#010101\"\nhint-key=\"#010101\"\n\
             hint-desc=\"#010101\"",
        );
        for name in BUILTIN_NAMES {
            let mut def = ThemeDef::builtin(name).unwrap();
            let _ = hostile.apply(&mut def);
            for tier in [Tier::TrueColor, Tier::Color16, Tier::Monochrome] {
                let theme = def.theme_for_tier(tier);
                for (slot, style) in signal_styles(&theme) {
                    assert_ne!(
                        style,
                        Style::default(),
                        "{name}/{tier:?}: {slot} lost its style under a hostile patch"
                    );
                    assert!(
                        !style.add_modifier.is_empty(),
                        "{name}/{tier:?}: {slot} lost its modifier carrier"
                    );
                }
                if matches!(theme.palette, Palette::Monochrome) {
                    // Every accessor, including the plain hint_desc label.
                    let mut all = signal_styles(&theme);
                    all.push(("hint_desc", theme.hint_desc()));
                    for (slot, style) in all {
                        assert_eq!(style.fg, None, "{name}/mono: {slot} must emit no fg");
                        assert_eq!(style.bg, None, "{name}/mono: {slot} must emit no bg");
                    }
                }
            }
        }
    }

    #[test]
    fn unknown_patch_keys_warn_and_ignore() {
        let mut def = ThemeDef::builtin("default-dark").unwrap();
        let warnings = patch("bogus-slot = \"#123456\"\naccent = \"#654321\"").apply(&mut def);
        assert_eq!(
            warnings.len(),
            1,
            "one warning for the unknown slot: {warnings:?}"
        );
        assert!(
            warnings[0].message.contains("bogus-slot"),
            "{:?}",
            warnings[0]
        );
        // The valid slot still applied.
        assert_eq!(def.truecolor.accent, Color::Rgb(0x65, 0x43, 0x21));
    }

    #[test]
    fn invalid_patch_color_warns_without_content_echo() {
        let mut def = ThemeDef::builtin("default-dark").unwrap();
        let warnings = patch("accent = \"#nothex\"").apply(&mut def);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("accent"));
        // The message names the slot only — never echoes the bad value.
        assert!(!warnings[0].message.contains("nothex"), "{:?}", warnings[0]);
    }

    #[test]
    fn color_parse_hex_and_named() {
        assert_eq!(parse_color("#f6d32d"), Ok(Color::Rgb(0xf6, 0xd3, 0x2d)));
        let named = [
            ("black", Color::Black),
            ("red", Color::Red),
            ("green", Color::Green),
            ("yellow", Color::Yellow),
            ("blue", Color::Blue),
            ("magenta", Color::Magenta),
            ("cyan", Color::Cyan),
            ("gray", Color::Gray),
            ("dark gray", Color::DarkGray),
            ("light red", Color::LightRed),
            ("light green", Color::LightGreen),
            ("light yellow", Color::LightYellow),
            ("light blue", Color::LightBlue),
            ("light magenta", Color::LightMagenta),
            ("light cyan", Color::LightCyan),
            ("white", Color::White),
            // Case- and separator-insensitive.
            ("LIGHT-BLUE", Color::LightBlue),
        ];
        for (s, expected) in named {
            assert_eq!(parse_color(s), Ok(expected), "parse {s:?}");
        }
        for junk in ["nonsense", "#12", "#zzzzzz", "", "#1234567"] {
            assert!(parse_color(junk).is_err(), "{junk:?} must fail to parse");
        }
        // A 6-BYTE hex string containing a multibyte char must be rejected
        // without panicking (the byte-slice-on-non-ASCII regression). `#1Ω345`
        // is exactly 6 bytes but not 6 ASCII hex digits.
        assert!(
            parse_color("#1\u{3a9}345").is_err(),
            "multibyte hex must not panic"
        );
    }

    // ---- §8.2.11 resolution ladder (T3.4) ----

    fn theme_cfg(dark: &str, light: &str, mode: ThemeMode) -> ThemeCfg {
        ThemeCfg {
            dark: dark.to_string(),
            light: light.to_string(),
            mode,
        }
    }

    #[test]
    fn light_dark_resolution_ladder_is_pure() {
        let cfg = theme_cfg("default-dark", "default-light", ThemeMode::Auto);
        let tc = EnvParts {
            colorterm: Some("truecolor"),
            ..EnvParts::default()
        };

        // Auto + no COLORFGBG → dark; truecolor tier.
        let (t, w) = resolve_theme(tc, &cfg, None, &[]);
        assert!(w.is_empty());
        assert_eq!(t.name, "default-dark");
        assert!(matches!(t.palette, Palette::TrueColor(_)));

        // Auto + light COLORFGBG ("...;15") → light.
        let light_env = EnvParts {
            colorterm: Some("truecolor"),
            colorfgbg: Some("0;15"),
            ..EnvParts::default()
        };
        let (t, _) = resolve_theme(light_env, &cfg, None, &[]);
        assert_eq!(t.name, "default-light");

        // Explicit mode = Light overrides a dark COLORFGBG.
        let cfg_light = theme_cfg("default-dark", "default-light", ThemeMode::Light);
        let dark_bg = EnvParts {
            colorterm: Some("truecolor"),
            colorfgbg: Some("15;0"),
            ..EnvParts::default()
        };
        let (t, _) = resolve_theme(dark_bg, &cfg_light, None, &[]);
        assert_eq!(t.name, "default-light", "mode override beats COLORFGBG");

        // No COLORTERM → 16-color tier.
        let (t, _) = resolve_theme(EnvParts::default(), &cfg, None, &[]);
        assert!(matches!(t.palette, Palette::Color16(_)));

        // Flag wins over config name.
        let (t, _) = resolve_theme(tc, &cfg, Some("slate"), &[]);
        assert_eq!(t.name, "slate");
    }

    #[test]
    fn env_accessibility_wins_over_config_and_flag() {
        let cfg = theme_cfg("slate", "paper", ThemeMode::Dark);
        for env in [
            EnvParts {
                no_color: true,
                colorterm: Some("truecolor"),
                ..EnvParts::default()
            },
            EnvParts {
                theme_override: Some("accessible"),
                ..EnvParts::default()
            },
            EnvParts {
                term: Some("dumb"),
                ..EnvParts::default()
            },
        ] {
            // Even with an explicit --theme flag, accessibility forces mono.
            let (t, w) = resolve_theme(env, &cfg, Some("slate"), &[]);
            assert!(matches!(t.palette, Palette::Monochrome), "{env:?}");
            assert_eq!(t.name, "accessible");
            assert!(w.is_empty());
        }
    }

    #[test]
    fn named_theme_resolution_falls_back_on_unknown() {
        let cfg = theme_cfg("no-such-theme", "default-light", ThemeMode::Dark);
        let env = EnvParts {
            colorterm: Some("truecolor"),
            ..EnvParts::default()
        };
        let (t, w) = resolve_theme(env, &cfg, None, &[]);
        assert_eq!(
            t.name, "default-dark",
            "unknown name falls back to default-dark"
        );
        assert_eq!(w.len(), 1);
        assert!(w[0].message.contains("no-such-theme"), "{:?}", w[0]);
    }

    #[test]
    fn user_theme_discovered_and_patch_applied() {
        let cfg = theme_cfg("mint", "default-light", ThemeMode::Dark);
        let user = vec![UserThemeFile::from_patch(
            "mint",
            patch("accent = \"#00ff00\"\nmatch-hl = \"#00ffaa\""),
        )];
        let env = EnvParts {
            colorterm: Some("truecolor"),
            ..EnvParts::default()
        };
        let (t, w) = resolve_theme(env, &cfg, None, &user);
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(t.name, "mint", "resolved theme reports the file stem");
        match &t.palette {
            Palette::TrueColor(p) => {
                assert_eq!(p.accent, Color::Rgb(0x00, 0xff, 0x00), "user patch applied");
                assert_eq!(p.match_hl, Color::Rgb(0x00, 0xff, 0xaa));
            }
            other => panic!("expected TrueColor palette, got {other:?}"),
        }
    }

    #[test]
    fn colorfgbg_light_detection() {
        assert!(colorfgbg_is_light(Some("0;15")));
        assert!(colorfgbg_is_light(Some("0;7")));
        assert!(!colorfgbg_is_light(Some("15;0")));
        assert!(!colorfgbg_is_light(Some("7;0")));
        assert!(!colorfgbg_is_light(None));
        assert!(!colorfgbg_is_light(Some("garbage")));
    }

    // ---- §8.2.3 env-wiring smoke tests (mutate process env; #[ignore]d) ----
    //
    // The matrix above proves the *logic* purely; these confirm `auto()` reads
    // the right vars. They mutate global env (which races concurrent `getenv`),
    // so they are `#[ignore]`d and run serially via `make test-ignored`
    // (vault-core `paths.rs` `EnvGuard` precedent).

    /// RAII env guard mirroring `falach_core::paths`'s: saves a var, sets or
    /// unsets it, and restores the original on drop. See that module for the
    /// `set_var`-is-unsafe rationale; only used by the `#[ignore]`d serial tests.
    #[allow(unsafe_code)]
    struct EnvGuard {
        var: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        #[allow(unsafe_code)]
        fn set(var: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(var);
            // SAFETY: documented in `falach_core::paths`; the caller runs this
            // under `--test-threads=1` (via `make test-ignored`).
            unsafe {
                std::env::set_var(var, value);
            }
            Self { var, previous }
        }

        #[allow(unsafe_code)]
        fn unset(var: &'static str) -> Self {
            let previous = std::env::var_os(var);
            // SAFETY: as above.
            unsafe {
                std::env::remove_var(var);
            }
            Self { var, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            // SAFETY: as above.
            unsafe {
                match self.previous.take() {
                    Some(v) => std::env::set_var(self.var, v),
                    None => std::env::remove_var(self.var),
                }
            }
        }
    }

    #[test]
    #[ignore = "mutates env; run via `make test-ignored`"]
    fn auto_with_falach_tui_theme_accessible_returns_monochrome() {
        let _t = EnvGuard::set("FALACH_TUI_THEME", "accessible");
        let _n = EnvGuard::unset("NO_COLOR");
        let _ct = EnvGuard::unset("COLORTERM");
        let _term = EnvGuard::unset("TERM");
        assert!(matches!(Theme::auto().palette, Palette::Monochrome));
    }

    #[test]
    #[ignore = "mutates env; run via `make test-ignored`"]
    fn auto_with_no_color_returns_monochrome() {
        let _th = EnvGuard::unset("FALACH_TUI_THEME");
        let _n = EnvGuard::set("NO_COLOR", "1");
        // NO_COLOR must win even when truecolor is advertised.
        let _ct = EnvGuard::set("COLORTERM", "truecolor");
        assert!(matches!(Theme::auto().palette, Palette::Monochrome));
    }

    #[test]
    #[ignore = "mutates env; run via `make test-ignored`"]
    fn auto_with_colorterm_truecolor_returns_truecolor() {
        let _th = EnvGuard::unset("FALACH_TUI_THEME");
        let _n = EnvGuard::unset("NO_COLOR");
        let _term = EnvGuard::unset("TERM");
        let _ct = EnvGuard::set("COLORTERM", "truecolor");
        assert!(matches!(Theme::auto().palette, Palette::TrueColor(_)));
    }

    #[test]
    #[ignore = "mutates env; run via `make test-ignored`"]
    fn auto_with_no_relevant_env_returns_color16() {
        let _th = EnvGuard::unset("FALACH_TUI_THEME");
        let _n = EnvGuard::unset("NO_COLOR");
        let _term = EnvGuard::set("TERM", "xterm-256color");
        let _ct = EnvGuard::unset("COLORTERM");
        assert!(matches!(Theme::auto().palette, Palette::Color16(_)));
    }
}
