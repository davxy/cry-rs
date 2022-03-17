use crate::{
    aes::{Aes128, Aes256},
    traits::Cipher,
};
use core::mem::MaybeUninit;

use cry_sys::bindings::{cry_cmac_ctx, cry_cmac_digest, cry_cmac_init, cry_cmac_update};

pub struct Cmac<C: Cipher> {
    backend: cry_cmac_ctx,
    cipher: Box<C::Backend>,
}

pub type Aes128Cmac = Cmac<Aes128>;
pub type Aes256Cmac = Cmac<Aes256>;

impl<C: Cipher> Cmac<C> {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        let key = key.as_ref();
        let this = unsafe {
            let mut this = Cmac::<C> {
                backend: MaybeUninit::uninit().assume_init(),
                cipher: Box::new(MaybeUninit::uninit().assume_init()),
            };

            let ctx = &mut this.backend as *mut _;
            let ciph_ctx = this.cipher.as_mut() as *mut C::Backend as *mut _;

            cry_cmac_init(
                ctx,
                ciph_ctx,
                C::interface(),
                key.as_ptr() as *mut u8,
                key.len() as u64,
            );
            this
        };
        this
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let ctx = &mut self.backend as *mut _;
        let data = data.as_ref();
        unsafe {
            cry_cmac_update(ctx, data.as_ptr(), data.len() as u64);
        }
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        let ctx = &mut self.backend as *mut _;
        // TODO: allow usage of arbitrary block size
        let mut digest = vec![0; 16];
        unsafe {
            cry_cmac_digest(ctx, digest.as_mut_ptr());
        }
        digest
    }
}

impl<C: Cipher> Drop for Cmac<C> {
    fn drop(&mut self) {
        // TODO: not yet implemented by the backend
        // let ctx = &mut self.backend as *mut _;
        // unsafe { cry_cmac_clear(ctx) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_cmac() {
        let key = [0; 16];
        let mut ctx = Aes128Cmac::new(key);

        ctx.update("Hello");
        ctx.update("World");

        let mac = ctx.finalize();

        assert_eq!(hex::encode(mac), "34801a662fd01690bdd6155d8dbdf2d7");
    }

    #[test]
    fn aes256_cmac() {
        let key = [0; 32];
        let mut ctx = Aes256Cmac::new(key);

        ctx.update("Hello");
        ctx.update("World");

        let mac = ctx.finalize();

        assert_eq!(hex::encode(mac), "68dadde42132fccea8faaa8a5fab53bb");
    }
}
