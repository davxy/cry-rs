use crate::cipher::Cipher;
use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_aes_clear, cry_aes_ctx, cry_aes_decrypt, cry_aes_encrypt, cry_aes_init, cry_aes_key_set,
    cry_ciph_itf,
};
use lazy_static::lazy_static;

struct Aes {
    inner: cry_aes_ctx,
}

impl Aes {
    pub fn new(key: &[u8]) -> Self {
        let inner = unsafe {
            let mut inner = MaybeUninit::uninit().assume_init();
            let ctx = &mut inner as *mut _;
            cry_aes_init(ctx);
            inner
        };
        let mut this = Aes { inner };
        this.reset(key);
        this
    }

    pub fn reset(&mut self, key: &[u8]) {
        let ctx = &mut self.inner as *mut _;
        let key = key.as_ref();
        let len = key.len();
        unsafe {
            cry_aes_key_set(ctx, key.as_ptr(), len as u64);
        }
    }

    pub fn encrypt(&mut self, src: &[u8]) -> Vec<u8> {
        let ctx = &mut self.inner as *mut _;
        let mut dst = vec![0u8; src.len()];
        unsafe {
            cry_aes_encrypt(ctx, dst.as_mut_ptr(), src.as_ptr(), src.len() as u64);
        }
        dst
    }

    pub fn encrypt_inplace(&mut self, data: &mut [u8]) {
        let ctx = &mut self.inner as *mut _;
        unsafe {
            cry_aes_encrypt(ctx, data.as_mut_ptr(), data.as_ptr(), data.len() as u64);
        }
    }

    pub fn decrypt(&mut self, src: &[u8]) -> Vec<u8> {
        let ctx = &mut self.inner as *mut _;
        let mut dst = vec![0u8; src.len()];
        unsafe {
            cry_aes_decrypt(ctx, dst.as_mut_ptr(), src.as_ptr(), src.len() as u64);
        }
        dst
    }

    pub fn decrypt_inplace(&mut self, data: &mut [u8]) {
        let ctx = &mut self.inner as *mut _;
        unsafe {
            cry_aes_decrypt(ctx, data.as_mut_ptr(), data.as_ptr(), data.len() as u64);
        }
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        let ctx = &mut self.inner as *mut _;
        unsafe { cry_aes_clear(ctx) }
    }
}

pub struct Aes128(Aes);

impl Aes128 {
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, ()> {
        let key = key.as_ref();
        if key.len() != 16 {
            return Err(());
        }
        Ok(Aes128(Aes::new(key)))
    }

    pub fn reset(&mut self, key: impl AsRef<[u8]>) {
        let key = key.as_ref();
        if key.len() != 16 {
            return;
        }
        self.0.reset(key.as_ref());
    }

    pub fn encrypt(&mut self, src: impl AsRef<[u8]>) -> Vec<u8> {
        self.0.encrypt(src.as_ref())
    }

    pub fn encrypt_inplace(&mut self, mut data: impl AsMut<[u8]>) {
        self.0.encrypt_inplace(data.as_mut());
    }

    pub fn decrypt(&mut self, src: impl AsRef<[u8]>) -> Vec<u8> {
        self.0.decrypt(src.as_ref())
    }

    pub fn decrypt_inplace(&mut self, mut data: impl AsMut<[u8]>) {
        self.0.decrypt_inplace(data.as_mut());
    }
}

pub struct Aes256(Aes);

impl Aes256 {
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, ()> {
        let key = key.as_ref();
        if key.len() != 32 {
            return Err(());
        }
        Ok(Aes256(Aes::new(key)))
    }

    pub fn reset(&mut self, key: impl AsRef<[u8]>) {
        let key = key.as_ref();
        if key.len() != 32 {
            return;
        }
        self.0.reset(key.as_ref());
    }

    pub fn encrypt(&mut self, src: impl AsRef<[u8]>) -> Vec<u8> {
        self.0.encrypt(src.as_ref())
    }

    pub fn encrypt_inplace(&mut self, mut data: impl AsMut<[u8]>) {
        self.0.encrypt_inplace(data.as_mut());
    }

    pub fn decrypt(&mut self, src: impl AsRef<[u8]>) -> Vec<u8> {
        self.0.decrypt(src.as_ref())
    }

    pub fn decrypt_inplace(&mut self, mut data: impl AsMut<[u8]>) {
        self.0.decrypt_inplace(data.as_mut());
    }
}

lazy_static! {
    static ref CIPH_ITF: cry_ciph_itf = unsafe {
        cry_ciph_itf {
            init: Some(core::mem::transmute(cry_aes_init as usize)),
            clear: Some(core::mem::transmute(cry_aes_clear as usize)),
            key_set: Some(core::mem::transmute(cry_aes_key_set as usize)),
            encrypt: Some(core::mem::transmute(cry_aes_encrypt as usize)),
            decrypt: Some(core::mem::transmute(cry_aes_decrypt as usize)),
        }
    };
}

impl Cipher for Aes128 {
    type Backend = cry_aes_ctx;

    fn interface() -> *const cry_ciph_itf {
        &*CIPH_ITF as *const cry_ciph_itf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_encrypt_decrypt() {
        let key = [0; 16];
        let mut ctx = Aes128::new(&key).unwrap();
        let data = [0; 1024];

        let enc = ctx.encrypt(&data);
        let dec = ctx.decrypt(&enc);

        assert_eq!(&data[..], &dec[..]);
    }

    #[test]
    fn aes128_encrypt_decrypt_inplace() {
        let key = [0; 16];
        let mut ctx = Aes128::new(&key).unwrap();
        let mut data = [0; 1024];

        ctx.encrypt_inplace(&mut data);
        ctx.decrypt_inplace(&mut data);

        assert_eq!(data, [0; 1024]);
    }
}
