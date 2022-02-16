//!  The following algorithm is not secure and is provided as an
//! historical reference only.
//!
//!  The original affine cipher is a monoalphaberic substitution cipher where
//!  each octet is encrypted using a simple linear function performed modulo
//!  256.
//
//!  Encryption function: E(x) = (ax + b) = y
//!  Decryption function: D(y) = (y - b)*a^-1 = x
//
//!  Note that to be invertible the value 'a' should be chosen so that
//!  gcd(a,256)=1 and, since 256=2^8, this is true whenever the value
//!  of 'a' is odd.
//
//!  The provided implementation allows the usage of a list of 'a' values
//!  and 'b' values, thus it can be more appropriately classified as a
//!  polyalphabetic affine cipher.
//
//!  Given the two variable length 'keys' the implementation provides the
//!  following well known ciphers:
//!   - Caesar     : keylen = 1, keya = {1}, keyb = {3}
//!   - Rot-X      : keylen = 1, keya = {1}, keyb = {X}
//!   - Affine     : keylen = 1, keya = {a}, keyb = {0}
//!   - Vigenere   : keylen > 1, keya = {1,...,1},   keyb = {b1,...,bn}
//!   - Poly-Affine: keylen > 1, keya = {a1,...,an}, keyb = {b1,...,bn}

use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_affine_ctx, cry_affine_decrypt, cry_affine_encrypt, cry_affine_init, CRY_AFFINE_KEYMAX,
};

/// Affine cipher context.
pub struct AffineCipher {
    inner: cry_affine_ctx,
}

impl AffineCipher {
    /// Max key length.
    pub const KEYLEN_MAX: usize = CRY_AFFINE_KEYMAX as usize;

    /// Instance a new affine cipher context.
    pub fn new(keya: impl AsRef<[u8]>, keyb: impl AsRef<[u8]>) -> Result<Self, String> {
        let keya = keya.as_ref();
        let keyb = keyb.as_ref();
        if keya.len() > Self::KEYLEN_MAX
            || keyb.len() > Self::KEYLEN_MAX
            || keya.len() != keyb.len()
        {
            return Err(format!(
                "Key length shall be less than {}",
                Self::KEYLEN_MAX
            ));
        }
        let inner: cry_affine_ctx = unsafe {
            #[allow(clippy::uninit_assumed_init)]
            let mut inner = MaybeUninit::uninit().assume_init();
            let ctx = &mut inner as *mut _;
            let result = cry_affine_init(ctx, keya.as_ptr(), keyb.as_ptr(), keya.len() as u64);
            if result < 0 {
                return Err("Invalid key".into());
            }
            inner
        };
        Ok(AffineCipher { inner })
    }

    /// Encrypt the given plaintext.
    pub fn encrypt(&self, input: impl AsRef<[u8]>) -> Vec<u8> {
        let input = input.as_ref();
        let mut output = vec![0; input.len()];
        unsafe {
            let ctx = &self.inner as *const _ as *mut _;
            cry_affine_encrypt(ctx, output.as_mut_ptr(), input.as_ptr(), input.len() as u64)
        }
        output
    }

    /// Decrypt the given ciphertext.
    pub fn decrypt(&self, input: impl AsRef<[u8]>) -> Vec<u8> {
        let input = input.as_ref();
        let mut output = vec![0; input.len()];
        unsafe {
            let ctx = &self.inner as *const _ as *mut _;
            cry_affine_decrypt(ctx, output.as_mut_ptr(), input.as_ptr(), input.len() as u64)
        }
        output
    }
}

impl Drop for AffineCipher {
    fn drop(&mut self) {
        let ptr = &mut self.inner as *mut _ as *mut u8;
        let size = core::mem::size_of_val(self);
        unsafe {
            for off in 0..size {
                core::ptr::write_volatile(ptr.add(off), 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let keya = [1, 1, 1];
        let keyb = [19, 10, 201];
        let data = [0; 1024];

        let affine = AffineCipher::new(&keya, &keyb).unwrap();

        let enc = affine.encrypt(&data);
        let dec = affine.decrypt(&enc);

        assert_eq!(&data[..], &dec[..]);
    }
}
