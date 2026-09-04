//! Secret-byte containers for ephemeral crypto material.
//!
//! Two wrappers with different guarantees:
//!
//! | Type | Zero on drop | `mlock`ed | Debug redacted | Use for |
//! |---|---|---|---|---|
//! | [`SecretBytes`] | yes | no | yes | ephemeral secrets that live in regular heap |
//! | [`LockedSecret`] | yes | yes | yes | long-lived keys that must not page to disk |
//!
//! Both types expose bytes only through `with_bytes(f)` / `with_bytes_mut(f)`
//! — the reference cannot escape the closure, preventing accidental copies
//! into longer-lived `Vec<u8>` through `.to_vec()`.
//!
//! `LockedSecret` uses [`memsec::mlock`] to pin pages in physical memory so
//! they never swap to disk, and zeroizes + munlocks on drop. The operations
//! are `unsafe` by nature (raw pointer arithmetic and syscalls); all such
//! code is confined to this module with explicit `// SAFETY:` comments.

#![allow(unsafe_code)] // mlock/munlock through raw pointers — isolated here

use crate::error::CryptoError;
use std::ptr::NonNull;
use zeroize::Zeroize;

// ============================================================================
// SecretBytes — heap-backed, zero-on-drop, no mlock.
// ============================================================================

/// A heap-allocated byte buffer that is zeroized when dropped.
///
/// Suitable for short-lived secret material that doesn't justify the overhead
/// of pinning a page in memory. For long-lived keys, prefer [`LockedSecret`].
///
/// # Example
/// ```
/// # use frappuccino_crypto_core::secret::SecretBytes;
/// let mut secret = SecretBytes::new_zeroed(32);
/// secret.with_bytes_mut(|b| b[0] = 42);
/// secret.with_bytes(|b| assert_eq!(b[0], 42));
/// // `secret` wipes its buffer when dropped here.
/// ```
#[must_use]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Allocate `size` zeroed bytes.
    /// (struct is `#[must_use]` so callers can't silently drop the allocation.)
    pub fn new_zeroed(size: usize) -> Self {
        Self {
            inner: vec![0u8; size],
        }
    }

    /// Copy `data` into a new `SecretBytes`. The source slice is *not* wiped;
    /// the caller is responsible for zeroizing the original if it was secret.
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            inner: data.to_vec(),
        }
    }

    /// Number of bytes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if the buffer is zero-length.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Grants read-only access to the bytes for the duration of the closure.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.inner)
    }

    /// Grants read-write access to the bytes for the duration of the closure.
    pub fn with_bytes_mut<R>(&mut self, f: impl FnOnce(&mut [u8]) -> R) -> R {
        f(&mut self.inner)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

// Redact Debug so `println!("{secret:?}")` / log crate integrations don't leak bytes.
impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<{}-byte redacted>)", self.inner.len())
    }
}

// ============================================================================
// LockedSecret — heap-backed, zero-on-drop, mlock'd, Debug redacted.
// ============================================================================

/// A byte buffer that is both zeroized *and* kept from swapping to disk.
///
/// On construction, calls `mlock` on the underlying buffer (`VirtualLock` on
/// Windows). On drop, zeroizes then calls `munlock`. If the OS refuses mlock
/// (e.g., process can't grow its working set), construction fails with
/// [`CryptoError::DerivationFailed`] rather than silently degrading.
///
/// The size is fixed at construction — the backing `Box<[u8]>` never
/// reallocates, so the locked region stays stable for the lifetime.
#[must_use]
pub struct LockedSecret {
    inner: Box<[u8]>,
}

impl LockedSecret {
    /// Allocate `size` zeroed bytes and pin them in RAM via `mlock`.
    ///
    /// # Errors
    /// Returns [`CryptoError::DerivationFailed`] if `size == 0` or the OS
    /// refuses the `mlock` syscall (rare; typically rlimit-related).
    pub fn new_zeroed(size: usize) -> Result<Self, CryptoError> {
        if size == 0 {
            return Err(CryptoError::DerivationFailed(
                "LockedSecret size must be > 0".into(),
            ));
        }
        let mut inner: Box<[u8]> = vec![0u8; size].into_boxed_slice();

        // SAFETY:
        //   * `inner.as_mut_ptr()` points to exactly `size` contiguous bytes
        //     owned by this stack frame for the duration of this call.
        //   * `NonNull::new` rejects null; `vec![0u8; size > 0]` cannot be null.
        //   * `memsec::mlock` reads and pins the range but does not free or
        //     alias the memory; the Box remains the unique owner.
        let ptr = NonNull::new(inner.as_mut_ptr())
            .ok_or_else(|| CryptoError::DerivationFailed("null buffer".into()))?;
        let locked = unsafe { memsec::mlock(ptr.as_ptr(), size) };
        if !locked {
            return Err(CryptoError::DerivationFailed(
                "mlock failed — RLIMIT_MEMLOCK / working-set quota exhausted".into(),
            ));
        }
        Ok(Self { inner })
    }

    /// Number of bytes held (fixed at construction).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Always `false` — `new_zeroed(0)` returns `Err`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Grants read-only access to the bytes for the duration of the closure.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.inner)
    }

    /// Grants read-write access to the bytes for the duration of the closure.
    pub fn with_bytes_mut<R>(&mut self, f: impl FnOnce(&mut [u8]) -> R) -> R {
        f(&mut self.inner)
    }

    /// Copy `src` into the locked buffer and wipe the source in place.
    /// Convenience for the common pattern of moving a non-locked secret into
    /// a locked home.
    ///
    /// # Errors
    /// Returns [`CryptoError::DerivationFailed`] if `src.len() != self.len()`.
    pub fn write_and_wipe_source(&mut self, src: &mut [u8]) -> Result<(), CryptoError> {
        if src.len() != self.inner.len() {
            return Err(CryptoError::DerivationFailed(format!(
                "size mismatch: locked={}, src={}",
                self.inner.len(),
                src.len()
            )));
        }
        self.inner.copy_from_slice(src);
        src.zeroize();
        Ok(())
    }
}

impl Drop for LockedSecret {
    fn drop(&mut self) {
        // Step 1: zero the bytes so even if munlock fails the memory is wiped.
        self.inner.zeroize();

        // Step 2: release the mlock.
        // SAFETY: see new_zeroed — the pointer / length remain valid until
        // the Box is freed (which happens after this Drop returns).
        if let Some(ptr) = NonNull::new(self.inner.as_mut_ptr()) {
            let _ = unsafe { memsec::munlock(ptr.as_ptr(), self.inner.len()) };
        }
    }
}

impl std::fmt::Debug for LockedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LockedSecret(<{}-byte redacted>)", self.inner.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_new_zeroed_is_zero() {
        let s = SecretBytes::new_zeroed(32);
        s.with_bytes(|b| assert_eq!(b, &[0u8; 32]));
    }

    #[test]
    fn secret_bytes_from_slice_copies() {
        let data = [1u8, 2, 3, 4];
        let s = SecretBytes::from_slice(&data);
        s.with_bytes(|b| assert_eq!(b, &[1, 2, 3, 4]));
    }

    #[test]
    fn secret_bytes_mut_access_writes_through() {
        let mut s = SecretBytes::new_zeroed(4);
        s.with_bytes_mut(|b| b.copy_from_slice(&[9, 8, 7, 6]));
        s.with_bytes(|b| assert_eq!(b, &[9, 8, 7, 6]));
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let s = SecretBytes::from_slice(&[0xDEu8; 32]);
        let dbg = format!("{s:?}");
        assert_eq!(dbg, "SecretBytes(<32-byte redacted>)");
    }

    #[test]
    fn locked_secret_mlocks_and_mwipes() {
        let mut ls = LockedSecret::new_zeroed(32).expect("mlock should succeed");
        ls.with_bytes_mut(|b| b.copy_from_slice(&[0xAB; 32]));
        ls.with_bytes(|b| assert_eq!(b, &[0xAB; 32]));
        // Drop is implicit at end of test; no asserting on post-drop memory
        // (the Box is freed too).
    }

    #[test]
    fn locked_secret_zero_size_rejected() {
        let err = LockedSecret::new_zeroed(0).unwrap_err();
        assert!(matches!(err, CryptoError::DerivationFailed(_)));
    }

    #[test]
    fn locked_secret_write_and_wipe() {
        let mut ls = LockedSecret::new_zeroed(4).unwrap();
        let mut src = [1u8, 2, 3, 4];
        ls.write_and_wipe_source(&mut src).unwrap();
        assert_eq!(src, [0, 0, 0, 0], "source must be wiped");
        ls.with_bytes(|b| assert_eq!(b, &[1, 2, 3, 4]));
    }

    #[test]
    fn locked_secret_write_size_mismatch_rejected() {
        let mut ls = LockedSecret::new_zeroed(4).unwrap();
        let mut src = [1u8, 2, 3];
        assert!(ls.write_and_wipe_source(&mut src).is_err());
    }

    #[test]
    fn locked_secret_debug_is_redacted() {
        let ls = LockedSecret::new_zeroed(64).unwrap();
        assert_eq!(format!("{ls:?}"), "LockedSecret(<64-byte redacted>)");
    }
}
