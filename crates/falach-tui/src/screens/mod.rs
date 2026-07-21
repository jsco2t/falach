//! Per-phase rendering. Each module exposes a `render(app, frame, …)` that
//! reads `&App` immutably and composes widgets; key handling lives on `App`.

pub(crate) mod lock_screen;
pub(crate) mod secrets;
pub(crate) mod settings;
pub(crate) mod unlock_list;
pub(crate) mod unlock_prompt;
pub(crate) mod workspace;
