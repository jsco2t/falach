//! Sensitive-buffer helpers internal to `falach-security`.
//!
//! Currently houses [`ZeroizingString`], the wrapper the clipboard
//! timer thread uses to hold its comparison copy of the payload
//! without the bytes lingering in heap after the timer fires.
//!
//! Per design §2.2.6 / §3.7, the type is `pub(crate)`: callers of
//! [`crate::clipboard::Clipboard::copy_with_autoclear`] hand in a plain
//! `String` (which the function wraps in `zeroize::Zeroizing` for the
//! arming write), and only the clipboard module's timer thread holds a
//! `ZeroizingString`. There is no consumer outside the crate.

use std::fmt;
use std::ops::Deref;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A `String` that zeroes its bytes on drop and refuses to reveal its
/// contents through `Debug`.
///
/// Mirrors `falach_core::secret::MasterPassword`'s shape and rationale.
/// `Clone` is implemented (via derive) because the clipboard's
/// arming-write path needs both an in-flight buffer (moved into
/// `arboard::set_text`) and a comparison buffer (moved into the timer
/// thread); cloning the underlying `String` is the cheapest way to get
/// two independent zeroize-on-drop owners.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub(crate) struct ZeroizingString(String);

impl ZeroizingString {
    /// Wrap a caller-supplied string.
    pub(crate) fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Deref for ZeroizingString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ZeroizingString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ZeroizingString(***)")
    }
}

// Compile-time invariant: if a future refactor drops `ZeroizeOnDrop`
// from the derive list, this assertion fails to compile. Mirrors
// `falach_core::secret::MasterPassword`'s pattern. Intentionally
// outside `#[cfg(test)]` — the guarantee holds in every build.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<ZeroizingString>();
};

#[cfg(test)]
#[allow(unsafe_code)] // documented volatile-read zeroize verification
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_reveal_value() {
        let s = ZeroizingString::new("hunter2");
        let dbg = format!("{s:?}");
        assert!(
            !dbg.contains("hunter2"),
            "Debug output must not contain the inner value: {dbg}"
        );
        assert_eq!(dbg, "ZeroizingString(***)");
    }

    #[test]
    fn deref_returns_inner_str() {
        // The clipboard timer thread compares the live clipboard
        // contents to the `ZeroizingString` via the `Deref` impl. A
        // regression that returned an empty string from `Deref` would
        // make compare-and-clear vacuously match every value — every
        // clipboard would be stomped.
        let s = ZeroizingString::new("hunter2");
        let borrowed: &str = &s;
        assert_eq!(borrowed, "hunter2");
    }

    #[test]
    fn zeroize_clears_inner_bytes() {
        // Verifies that calling `.zeroize()` on a `ZeroizingString`
        // zeros the underlying byte buffer. The drop-zero guarantee
        // reduces to this property: `ZeroizeOnDrop`'s drop impl calls
        // `.zeroize()`, and the presence of that derive is enforced
        // separately by the compile-time `const _: fn() = ...`
        // assertion above this module.
        //
        // Pattern mirrors `falach_core::secret`'s evolved test
        // (`.zeroize()`-then-volatile-read rather than drop-then-read;
        // see that module for the macOS-allocator rationale).
        //
        // SAFETY (`read_volatile`): the buffer is still allocated; the
        // wrapper is mutably borrowed by `.zeroize()` and the read
        // happens before any drop. The pointer was obtained from the
        // live `String` and is valid for `len` bytes.
        let sentinel = "hunter2-zeroizing-string-sentinel".to_string();
        let len = sentinel.len();
        let mut s = ZeroizingString::new(sentinel);
        let ptr: *const u8 = s.as_bytes().as_ptr();

        Zeroize::zeroize(&mut s);

        for i in 0..len {
            // SAFETY: see block-level comment.
            let byte = unsafe { std::ptr::read_volatile(ptr.add(i)) };
            assert_eq!(
                byte, 0,
                "ZeroizingString byte at offset {i} should be zero after .zeroize()"
            );
        }
    }
}
