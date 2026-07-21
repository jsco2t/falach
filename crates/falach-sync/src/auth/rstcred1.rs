// Domain acronyms saturate this module's docs.
#![allow(clippy::doc_markdown)]

//! RST-CRED-1 encrypted credential container (design.md §3.5; carried
//! over verbatim from the abandoned sync-git feature's `auth::crypto`).
//!
//! **Format** (base64-encoded):
//!
//! ```text
//! "RC01" + salt[16] + nonce[12] + ciphertext + tag[16]
//! ```
//!
//! - `RC01` — 4-byte magic marker; doubles as ChaCha20-Poly1305 AAD so a
//!   tampered marker fails the AEAD verify.
//! - `salt[16]` — Argon2id salt; fresh `OsRng` per encrypt.
//! - `nonce[12]` — ChaCha20-Poly1305 nonce; fresh `OsRng` per encrypt.
//! - `ciphertext` — encrypted plaintext (variable length).
//! - `tag[16]` — Poly1305 AEAD tag.
//!
//! **KDF parameters:** Argon2id m=16384 KiB, t=3, p=1, 32-byte output.
//! Tuned to ~30 ms on M1 hardware — fast enough for sync to not feel
//! laggy, slow enough that a brute-force against a stolen `vaults.toml`
//! eats budget.
//!
//! **Cipher:** ChaCha20-Poly1305 AEAD, with `"RC01"` as associated data.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use falach_core::MasterPassword;
use secrecy::SecretString;
use zeroize::Zeroize;

use crate::auth::error::AuthError;
use crate::auth::source::ResolvedCredentials;

/// Magic prefix identifying the RST-CRED-1 format. Also used as AAD so a
/// tampered prefix fails AEAD verification rather than silently
/// succeeding into wrong-format territory.
const MAGIC: &[u8; 4] = b"RC01";

/// Salt length in bytes (Argon2id input).
const SALT_LEN: usize = 16;

/// Nonce length in bytes (ChaCha20-Poly1305 requires 12).
const NONCE_LEN: usize = 12;

/// AEAD tag length in bytes (Poly1305 produces 16).
const TAG_LEN: usize = 16;

/// Argon2id memory cost in KiB. Tuned to ~30 ms on M1; bumped at the
/// Phase-1 hardware-baseline review (PRD §11 Risk #12).
const ARGON2_M_COST: u32 = 16384;

/// Argon2id time cost (iteration count).
const ARGON2_T_COST: u32 = 3;

/// Argon2id parallelism. We're single-threaded; the spec requires
/// ≥1.
const ARGON2_P_COST: u32 = 1;

/// Derived-key length matches ChaCha20-Poly1305's key size.
const KEY_LEN: usize = 32;

/// Encrypt `plaintext` into an RST-CRED-1 base64 container, keyed by the
/// supplied master password.
///
/// The container is suitable for storage in `vaults.toml` (the orchestrator
/// writes it under `[vaults.<name>.sync.s3.credentials.secret_access_key_encrypted]`).
///
/// # Errors
///
/// Returns [`AuthError::RstCred1Malformed`] only if encryption itself fails —
/// which is unreachable in practice given valid inputs (the Argon2id KDF and
/// AEAD encrypt are infallible for well-formed parameters).
pub fn encrypt_credential(
    plaintext: &str,
    master_password: &MasterPassword,
) -> Result<String, AuthError> {
    // Fresh salt + nonce per encrypt from the OS entropy source.
    // `getrandom::fill` is the project's CSPRNG of record (CLAUDE.md
    // "CSPRNG only"); it's what `rand::OsRng` wraps internally. A
    // failure here would imply the OS RNG itself is unavailable, which
    // would also break Argon2id and the rest of the crypto path — we
    // surface it as a malformed container.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| AuthError::RstCred1Malformed {
        reason: format!("OS entropy source unavailable: {e}"),
    })?;
    getrandom::fill(&mut nonce_bytes).map_err(|e| AuthError::RstCred1Malformed {
        reason: format!("OS entropy source unavailable: {e}"),
    })?;

    let mut key = derive_key(master_password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: MAGIC,
            },
        )
        .map_err(|_| AuthError::RstCred1Malformed {
            reason: "ChaCha20-Poly1305 encrypt failed".to_string(),
        })?;

    // Zeroize the derived key as soon as we're done with it. The
    // `ChaCha20Poly1305` instance holds an internal copy that drops
    // when `cipher` goes out of scope.
    key.zeroize();

    // Assemble: MAGIC || salt || nonce || (ciphertext+tag).
    let mut container =
        Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext_with_tag.len());
    container.extend_from_slice(MAGIC);
    container.extend_from_slice(&salt);
    container.extend_from_slice(&nonce_bytes);
    container.extend_from_slice(&ciphertext_with_tag);

    Ok(STANDARD.encode(&container))
}

/// Decrypt a base64-encoded RST-CRED-1 container with the supplied master
/// password.
///
/// # Errors
///
/// - [`AuthError::RstCred1Malformed`] — bad base64, wrong magic bytes,
///   truncated container.
/// - [`AuthError::RstCred1Decryption`] — AEAD verification failed
///   (wrong password, tampered ciphertext, or tampered tag — the three
///   are deliberately indistinguishable).
///
/// # Panics
///
/// Never in practice. The `.expect`s below guard slice-conversion calls
/// that are statically validated by the preceding length check; a panic
/// would signal a bug in the bounds-check arithmetic, not bad input.
pub fn decrypt_credential(
    container_b64: &str,
    master_password: &MasterPassword,
) -> Result<SecretString, AuthError> {
    let container =
        STANDARD
            .decode(container_b64.trim())
            .map_err(|e| AuthError::RstCred1Malformed {
                reason: format!("base64 decode failed: {e}"),
            })?;

    let header_len = MAGIC.len() + SALT_LEN + NONCE_LEN;
    if container.len() < header_len + TAG_LEN {
        return Err(AuthError::RstCred1Malformed {
            reason: format!(
                "container too short ({} bytes; need at least {})",
                container.len(),
                header_len + TAG_LEN
            ),
        });
    }

    if &container[..MAGIC.len()] != MAGIC {
        return Err(AuthError::RstCred1Malformed {
            reason: "wrong magic bytes (expected `RC01`)".to_string(),
        });
    }

    let salt: &[u8; SALT_LEN] = container[MAGIC.len()..MAGIC.len() + SALT_LEN]
        .try_into()
        .expect("salt slice length verified by header_len check above");
    let nonce_bytes: &[u8; NONCE_LEN] = container[MAGIC.len() + SALT_LEN..header_len]
        .try_into()
        .expect("nonce slice length verified by header_len check above");
    let ciphertext_with_tag = &container[header_len..];

    let mut key = derive_key(master_password, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext_bytes = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext_with_tag,
                aad: MAGIC,
            },
        )
        .map_err(|_| AuthError::RstCred1Decryption)?;
    key.zeroize();

    let plaintext =
        String::from_utf8(plaintext_bytes).map_err(|_| AuthError::RstCred1Malformed {
            reason: "decrypted plaintext is not valid UTF-8".to_string(),
        })?;

    Ok(SecretString::from(plaintext))
}

/// Resolve a [`crate::auth::CredentialSource::RstCred1`] to
/// [`ResolvedCredentials`].
///
/// # Errors
///
/// Forwards [`decrypt_credential`]'s errors.
pub fn resolve_rstcred1(
    access_key_id: &str,
    secret_access_key_encrypted: &str,
    master_password: &MasterPassword,
) -> Result<ResolvedCredentials, AuthError> {
    let secret_access_key = decrypt_credential(secret_access_key_encrypted, master_password)?;
    Ok(ResolvedCredentials {
        access_key_id: access_key_id.to_string(),
        secret_access_key,
        // RST-CRED-1 is for STATIC credentials; STS-derived temporary
        // creds use IAM-instance-role or AWS-profile-with-session.
        session_token: None,
        expiry: None,
    })
}

/// Derive a 32-byte ChaCha20-Poly1305 key from the master password +
/// salt via Argon2id with the project's standard parameters.
fn derive_key(master_password: &MasterPassword, salt: &[u8]) -> Result<[u8; KEY_LEN], AuthError> {
    let params =
        Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN)).map_err(|e| {
            AuthError::RstCred1Malformed {
                reason: format!("invalid Argon2id params: {e}"),
            }
        })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .map_err(|e| AuthError::RstCred1Malformed {
            reason: format!("Argon2id key derivation failed: {e}"),
        })?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use falach_core::MasterPassword;
    use secrecy::ExposeSecret;

    fn master(s: &str) -> MasterPassword {
        MasterPassword::new(s.to_string())
    }

    // -- TC-AUTH-RC1 --------------------------------------------------------
    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let pw = master("correct horse battery staple");
        let plaintext = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let encrypted = encrypt_credential(plaintext, &pw).expect("encrypt ok");
        let decrypted = decrypt_credential(&encrypted, &pw).expect("decrypt ok");
        assert_eq!(decrypted.expose_secret(), plaintext);
    }

    // -- TC-AUTH-RC2 --------------------------------------------------------
    #[test]
    fn decrypt_with_wrong_master_password_fails() {
        let pw = master("correct password");
        let encrypted = encrypt_credential("secret", &pw).expect("encrypt");
        let wrong_pw = master("wrong password");
        let result = decrypt_credential(&encrypted, &wrong_pw);
        assert!(matches!(result, Err(AuthError::RstCred1Decryption)));
    }

    // -- TC-AUTH-RC2b -------------------------------------------------------
    // Two encrypts of the same plaintext with the same password produce
    // distinct ciphertexts (proves fresh salt + nonce per call). This is
    // the highest-value crypto test — a regression here means
    // ciphertexts are deterministic, which is catastrophic.
    #[test]
    fn repeat_encrypts_produce_distinct_ciphertexts() {
        let pw = master("pw");
        let a = encrypt_credential("secret", &pw).expect("a");
        let b = encrypt_credential("secret", &pw).expect("b");
        assert_ne!(
            a, b,
            "fresh salt+nonce per encrypt MUST make ciphertexts distinct"
        );
    }

    // -- TC-AUTH-RC2c -------------------------------------------------------
    #[test]
    fn decrypt_rejects_wrong_magic_bytes() {
        let pw = master("pw");
        let encrypted = encrypt_credential("secret", &pw).expect("encrypt");
        let mut bytes = STANDARD.decode(&encrypted).expect("decode");
        // Corrupt magic — flip the first byte.
        bytes[0] ^= 0xFF;
        let tampered = STANDARD.encode(&bytes);
        let result = decrypt_credential(&tampered, &pw);
        assert!(matches!(result, Err(AuthError::RstCred1Malformed { .. })));
    }

    // -- TC-AUTH-RC2d -------------------------------------------------------
    #[test]
    fn decrypt_rejects_truncated_container() {
        let pw = master("pw");
        let encrypted = encrypt_credential("secret", &pw).expect("encrypt");
        // Trim to a length below MAGIC + salt + nonce + tag.
        let truncated = &encrypted[..encrypted.len() / 2];
        let result = decrypt_credential(truncated, &pw);
        assert!(matches!(
            result,
            Err(AuthError::RstCred1Malformed { .. } | AuthError::RstCred1Decryption)
        ));
    }

    // -- TC-AUTH-RC2e -------------------------------------------------------
    #[test]
    fn decrypt_rejects_bad_base64() {
        let pw = master("pw");
        let result = decrypt_credential("not!valid$base64==", &pw);
        assert!(matches!(
            result,
            Err(AuthError::RstCred1Malformed { reason }) if reason.contains("base64")
        ));
    }

    // -- TC-AUTH-RC-resolve -------------------------------------------------
    #[test]
    fn resolve_rstcred1_returns_decrypted_credentials() {
        let pw = master("pw");
        let encrypted = encrypt_credential("the-secret-key", &pw).expect("encrypt");
        let resolved = resolve_rstcred1("AKIA-PUB", &encrypted, &pw).expect("resolve");
        assert_eq!(resolved.access_key_id, "AKIA-PUB");
        assert_eq!(resolved.secret_access_key.expose_secret(), "the-secret-key");
        assert!(resolved.session_token.is_none());
        assert!(resolved.expiry.is_none());
    }
}
