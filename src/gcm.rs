use crate::{
    aes::{Aes128, Aes256},
    des::{Des, DesEde},
    traits::Cipher,
};
use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_gcm_clear, cry_gcm_ctx, cry_gcm_decrypt, cry_gcm_encrypt, cry_gcm_init, cry_gcm_key_set,
};

pub struct Gcm<C: Cipher> {
    inner: cry_gcm_ctx,
    cipher: Box<C::Backend>,
}

pub type AesGcm128 = Gcm<Aes128>;
pub type AesGcm256 = Gcm<Aes256>;
pub type DesGcm = Gcm<Des>;
pub type DesEdeGcm = Gcm<DesEde>;

impl<C: Cipher + Sized> Gcm<C> {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        let mut this = unsafe {
            let mut this = Gcm::<C> {
                inner: MaybeUninit::uninit().assume_init(),
                cipher: Box::new(MaybeUninit::uninit().assume_init()),
            };

            let ctx = &mut this.inner as *mut _;
            let ciph_ctx = this.cipher.as_mut() as *mut C::Backend as *mut _;
            cry_gcm_init(ctx, ciph_ctx, C::interface());
            this
        };
        this.reset(key);
        this
    }

    pub fn reset(&mut self, key: impl AsRef<[u8]>) {
        let ctx = &mut self.inner as *mut _;
        let key = key.as_ref();
        let len = key.len();
        unsafe {
            cry_gcm_key_set(ctx, key.as_ptr(), len as u64);
        }
    }

    pub fn encrypt(&mut self, src: impl AsRef<[u8]>) -> Vec<u8> {
        let src = src.as_ref();
        let ctx = &mut self.inner as *mut _;
        let mut dst = vec![0u8; src.len()];
        unsafe {
            cry_gcm_encrypt(ctx, dst.as_mut_ptr(), src.as_ptr(), src.len() as u64);
        }
        dst
    }

    pub fn encrypt_inplace(&mut self, mut data: impl AsMut<[u8]>) {
        let data = data.as_mut();
        let ctx = &mut self.inner as *mut _;
        unsafe {
            cry_gcm_encrypt(ctx, data.as_mut_ptr(), data.as_ptr(), data.len() as u64);
        }
    }

    pub fn decrypt(&mut self, src: impl AsRef<[u8]>) -> Vec<u8> {
        let src = src.as_ref();
        let ctx = &mut self.inner as *mut _;
        let mut dst = vec![0u8; src.len()];
        unsafe {
            cry_gcm_decrypt(ctx, dst.as_mut_ptr(), src.as_ptr(), src.len() as u64);
        }
        dst
    }

    pub fn decrypt_inplace(&mut self, mut data: impl AsMut<[u8]>) {
        let data = data.as_mut();
        let ctx = &mut self.inner as *mut _;
        unsafe {
            cry_gcm_decrypt(ctx, data.as_mut_ptr(), data.as_ptr(), data.len() as u64);
        }
    }
}

impl<C: Cipher> Drop for Gcm<C> {
    fn drop(&mut self) {
        let ctx = &mut self.inner as *mut _;
        unsafe { cry_gcm_clear(ctx) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_128_encrypt_decrypt() {
        let key = [0; 16];
        let mut ctx = AesGcm128::new(key);
        let data = [0; 1024];

        let enc = ctx.encrypt(data);

        ctx.reset(&key);

        let dec = ctx.decrypt(enc);

        assert_eq!(&data[..], &dec[..]);
    }

    #[test]
    fn aes_gcm_128_encrypt_decrypt_inplace() {
        let key = [0; 16];
        let mut ctx = AesGcm128::new(key);
        let mut data = [0; 1024];

        ctx.encrypt_inplace(&mut data);

        ctx.reset(&key);

        ctx.decrypt_inplace(&mut data);

        assert_eq!(data, [0; 1024]);
    }

    #[test]
    fn des_gcm_encrypt_decrypt() {
        let key = [0; 16];
        let mut ctx = DesGcm::new(key);
        let mut data = [0; 1024];

        let enc = ctx.encrypt(&mut data);

        ctx.reset(&key);

        let dec = ctx.decrypt(enc);

        assert_eq!(&data[..], &dec[..]);
    }
}
