use crate::{
    md5::Md5,
    sha1::Sha1,
    sha256::Sha256,
    sha512::{Sha384, Sha512},
    traits::Hasher,
};
use core::mem::MaybeUninit;
use cry_sys::bindings::{cry_hmac_ctx, cry_hmac_digest, cry_hmac_init, cry_hmac_update};
use typenum::Unsigned;

pub struct Hmac<H: Hasher> {
    backend: cry_hmac_ctx,
    hasher: Box<H::Backend>,
}

pub type Sha256Hmac = Hmac<Sha256>;
pub type Sha384Hmac = Hmac<Sha384>;
pub type Sha512Hmac = Hmac<Sha512>;
pub type Md5Hmac = Hmac<Md5>;
pub type Sha1Hmac = Hmac<Sha1>;

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

            cry_hmac_init(
                ctx,
                hash_ctx,
                H::interface(),
                <H::DigestLen as Unsigned>::U64,
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
    fn sha256_hmac() {
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

    #[test]
    fn sha384_hmac() {
        let key = [0; 16];
        let mut ctx = Sha384Hmac::new(key);

        ctx.update("Hello");
        ctx.update("World");

        let mac = ctx.finalize();

        assert_eq!(
            hex::encode(mac),
            "8e18f1f196616b653f34c5d82bb3b529bba929e3e3904d098582741845376296eeac0eb646b39bbbe27171488894bcd6"
        );
    }

    #[test]
    fn sha512_hmac() {
        let key = [0; 16];
        let mut ctx = Sha512Hmac::new(key);

        ctx.update("Hello");
        ctx.update("World");

        let mac = ctx.finalize();

        assert_eq!(
            hex::encode(mac),
            "70718e02aba14daf933ef29b461c987de2ac900aae53d14ec348982b87514d371f1ce9f5b0dfa39887af7787423edf1f2a6404c365a8e7187d1287ecd99825f2"
        );
    }

    #[test]
    fn md5_hmac() {
        let key = [0; 16];
        let mut ctx = Md5Hmac::new(key);

        ctx.update("Hello");
        ctx.update("World");

        let mac = ctx.finalize();

        assert_eq!(hex::encode(mac), "dfa0ebcd46d978e041febdf4972aa274");
    }

    #[test]
    fn sha1_hmac() {
        let key = [0; 16];
        let mut ctx = Sha1Hmac::new(key);

        ctx.update("Hello");
        ctx.update("World");

        let mac = ctx.finalize();

        assert_eq!(hex::encode(mac), "23e531ab48f131c1e3c1c06b7a0d2ef20b0d2735");
    }
}
