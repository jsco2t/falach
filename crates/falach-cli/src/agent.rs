//! [`AgentClient`] — forward-compat hook for the post-MVP `falach-agent`.
//!
//! The CLI consults the agent first when collecting a master password.
//! In Phase 0 MVP the only impl is [`NoAgentClient`], which always
//! reports `AgentError::Unavailable`. When `features/agent/` ships, the
//! real Unix-socket client implements the same trait; the CLI's
//! prompt path is unchanged.
//!
//! The trait is intentionally minimal (one method) and object-safe so
//! the implementation can be selected at runtime via `&dyn AgentClient`.

use falach_core::MasterPassword;

/// Errors the agent can surface to the CLI. `Other` exists for future
/// IPC failure modes not yet enumerated; the MVP `NoAgentClient` never
/// produces it.
#[derive(thiserror::Error, Debug)]
pub enum AgentError {
    /// No agent process is running. The CLI falls through to the prompt.
    #[error("no agent running")]
    Unavailable,
    /// Agent is running but has locked the given vault.
    #[error("agent is locked")]
    Locked,
    /// Any other agent-side failure (IPC error, protocol error, ...).
    #[error("agent error: {0}")]
    Other(String),
}

/// Contract between the CLI and a running `falach-agent`.
///
/// Object-safe (`&dyn AgentClient`) and `Send + Sync`. Future versions
/// may add methods *additively*; existing call sites stay compiling.
pub trait AgentClient: Send + Sync {
    /// Ask the agent to return an unlocked master password for `vault`.
    ///
    /// # Errors
    ///
    /// - [`AgentError::Unavailable`] if no agent is running. Callers
    ///   fall through to the secure-stdin prompt.
    /// - [`AgentError::Locked`] if the agent is up but has locked the
    ///   vault. Callers also fall through to the prompt.
    /// - [`AgentError::Other`] for unexpected IPC failures. Callers
    ///   surface as [`crate::exit::CliExit::Internal`].
    fn try_unlock(&self, vault: &str) -> Result<MasterPassword, AgentError>;
}

/// MVP impl: always reports `Unavailable`. This is what the CLI uses
/// out of the box until `features/agent/` lands.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAgentClient;

impl AgentClient for NoAgentClient {
    fn try_unlock(&self, _vault: &str) -> Result<MasterPassword, AgentError> {
        Err(AgentError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_agent_client_returns_unavailable() {
        let c = NoAgentClient;
        let err = c.try_unlock("any-vault").unwrap_err();
        assert!(matches!(err, AgentError::Unavailable));
    }

    #[test]
    fn agent_client_is_object_safe() {
        // Compiling this fn proves the trait is object-safe — adding a
        // generic method or `Self: Sized` bound would break this.
        fn accepts_dyn(_a: &dyn AgentClient) {}
        accepts_dyn(&NoAgentClient);
    }

    #[test]
    fn agent_error_display_for_each_variant() {
        assert_eq!(AgentError::Unavailable.to_string(), "no agent running");
        assert_eq!(AgentError::Locked.to_string(), "agent is locked");
        assert_eq!(
            AgentError::Other("ipc dropped".into()).to_string(),
            "agent error: ipc dropped"
        );
    }
}
