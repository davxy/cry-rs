use crate::cipher::Hasher;
use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_hash_itf, cry_sha1_clear, cry_sha1_ctx, cry_sha1_digest, cry_sha1_init, cry_sha1_update,
};

const DIGEST_SIZE: usize = 20;

pub struct Sha1 {
    inner: cry_sha1_ctx,
}

impl Sha1 {
    pub fn new() -> Self {
        let inner = unsafe {
            let mut inner = MaybeUninit::uninit().assume_init();
            let ctx = &mut inner as *mut _;
            cry_sha1_init(ctx);
            inner
        };
        Sha1 { inner }
    }

    pub fn clear(&mut self) {
        let ctx = &mut self.inner as *mut _;
        unsafe {
            cry_sha1_clear(ctx);
        }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let ctx = &mut self.inner as *mut _;
        let data = data.as_ref();
        unsafe {
            cry_sha1_update(ctx, data.as_ptr(), data.len() as u64);
        }
    }

    pub fn digest(&mut self) -> [u8; DIGEST_SIZE] {
        let ctx = &mut self.inner as *mut _;
        let mut output = [0; DIGEST_SIZE];
        unsafe {
            cry_sha1_digest(ctx, output.as_mut_ptr());
        }
        output
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Sha1::new()
    }
}

lazy_static::lazy_static! {
    static ref HASH_ITF: cry_hash_itf = unsafe {
        cry_hash_itf {
            init: Some(core::mem::transmute(cry_sha1_init as usize)),
            clear: Some(core::mem::transmute(cry_sha1_clear as usize)),
            update: Some(core::mem::transmute(cry_sha1_update as usize)),
            digest: Some(core::mem::transmute(cry_sha1_digest as usize)),
        }
    };
}

impl Hasher for Sha1 {
    type Backend = cry_sha1_ctx;
    type DigestLen = typenum::U20;

    fn interface() -> *const cry_hash_itf {
        &*HASH_ITF as *const cry_hash_itf
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn digest() {
        let mut sha = Sha1::new();

        sha.update("Hello");
        sha.update("World");

        let digest = sha.digest().to_vec();

        assert_eq!(
            hex::encode(digest),
            "db8ac1c259eb89d4a131b253bacfca5f319d54f2"
        );
    }
}
