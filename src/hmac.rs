use crate::{cipher::Hasher, sha256::Sha256};
use core::mem::MaybeUninit;
use cry_sys::bindings::{cry_hmac_ctx, cry_hmac_digest, cry_hmac_init, cry_hmac_update};
use typenum::Unsigned;

pub struct Hmac<H: Hasher> {
    backend: cry_hmac_ctx,
    hasher: Box<H::Backend>,
}

pub type Sha256Hmac = Hmac<Sha256>;

impl<H: Hasher> Hmac<H> {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        let key = key.as_ref();
        let this = unsafe {
            let mut this = Hmac::<H> {
                backend: MaybeUninit::uninit().assume_init(),
                hasher: Box::new(MaybeUninit::uninit().assume_init()),
            };

            let ctx = &mut this.backend as *mut _;
            let hash_ctx = this.hasher.as_mut() as *mut H::Backend as *mut _;

            let digest_len = <H::DigestLen as Unsigned>::to_u64();
            cry_hmac_init(
                ctx,
                hash_ctx,
                H::interface(),
                digest_len,
                key.as_ptr(),
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
            cry_hmac_update(ctx, data.as_ptr(), data.len() as u64);
        }
    }

    // TODO: use typelen in the Digest trait
    pub fn finalize(&mut self) -> Vec<u8> {
        let ctx = &mut self.backend as *mut _;
        let mut digest = vec![0; <H::DigestLen as Unsigned>::USIZE];
        unsafe {
            cry_hmac_digest(ctx, digest.as_mut_ptr());
        }
        digest
    }
}

impl<H: Hasher> Drop for Hmac<H> {
    fn drop(&mut self) {
        // TODO: not yet implemented by the backend
        // let ctx = &mut self.backend as *mut _;
        // unsafe { cry_hmac_clear(ctx) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac() {
        let key = [0; 16];
        let mut ctx = Sha256Hmac::new(key);

        ctx.update("Hello");
        ctx.update("World");

        let mac = ctx.finalize();

        assert_eq!(
            hex::encode(mac),
            "a77d3694491c2109157bc896a06b5eb92eb1510b6d8c5ed8932da221c022aa0e"
        );
    }
}
