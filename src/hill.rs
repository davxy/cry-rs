use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_hill_ctx, cry_hill_decrypt, cry_hill_encrypt, cry_hill_init, CRY_HILL_KEYLEN_MAX,
};

/// Hill cipher context.
pub struct HillCipher {
    inner: cry_hill_ctx,
}

impl HillCipher {
    /// Max key length.
    pub const KEYLEN_MAX: usize = CRY_HILL_KEYLEN_MAX as usize;

    /// Instance a new Hill cipher context.
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() > Self::KEYLEN_MAX {
            return Err(format!(
                "Key length shall be less than {}",
                Self::KEYLEN_MAX
            ));
        }
        let inner: cry_hill_ctx = unsafe {
            #[allow(clippy::uninit_assumed_init)]
            let mut inner = MaybeUninit::uninit().assume_init();
            let ctx = &mut inner as *mut _;
            let result = cry_hill_init(ctx, key.as_ptr(), core::ptr::null(), key.len() as u64);
            if result < 0 {
                return Err("Invalid key".into());
            }
            inner
        };
        Ok(HillCipher { inner })
    }

    /// Encrypt the given plaintext.
    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let mut output = vec![0; input.len()];
        unsafe {
            let ctx = &self.inner as *const _ as *mut _;
            cry_hill_encrypt(ctx, output.as_mut_ptr(), input.as_ptr(), input.len() as u64)
        }
        output
    }

    /// Decrypt the given ciphertext.
    pub fn decrypt(&self, input: &[u8]) -> Vec<u8> {
        let mut output = vec![0; input.len()];
        unsafe {
            let ctx = &self.inner as *const _ as *mut _;
            cry_hill_decrypt(ctx, output.as_mut_ptr(), input.as_ptr(), input.len() as u64)
        }
        output
    }
}

impl Drop for HillCipher {
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
    fn encrypt() {
        let key = hex::decode("66e94bd42089b6ac").unwrap();
        let hill = HillCipher::new(&key).unwrap();
        let plaintext = hex::decode("48656c6c6f576f726c64").unwrap();

        let ciphertext = hill.encrypt(&plaintext);

        assert_eq!(hex::encode(&ciphertext), "9dbc54146991fced0c74")
    }

    #[test]
    fn decrypt() {
        let key = hex::decode("66e94bd42089b6ac").unwrap();
        let hill = HillCipher::new(&key).unwrap();
        let ciphertext = hex::decode("9dbc54146991fced0c74").unwrap();

        let plaintext = hill.decrypt(&ciphertext);

        assert_eq!(hex::encode(&plaintext), "48656c6c6f576f726c64")
    }
}
