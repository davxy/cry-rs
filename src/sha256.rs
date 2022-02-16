use crate::traits::Hasher;
use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_hash_itf, cry_sha256_clear, cry_sha256_ctx, cry_sha256_digest, cry_sha256_init,
    cry_sha256_update,
};

pub struct Sha256 {
    inner: cry_sha256_ctx,
}

impl Sha256 {
    pub fn new() -> Self {
        let inner = unsafe {
            let mut inner = MaybeUninit::uninit().assume_init();
            let ctx = &mut inner as *mut _;
            cry_sha256_init(ctx);
            inner
        };
        Sha256 { inner }
    }

    pub fn clear(&mut self) {
        let ctx = &mut self.inner as *mut _;
        unsafe {
            cry_sha256_clear(ctx);
        }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let ctx = &mut self.inner as *mut _;
        let data = data.as_ref();
        unsafe {
            cry_sha256_update(ctx, data.as_ptr(), data.len() as u64);
        }
    }

    pub fn digest(&mut self) -> [u8; 32] {
        let ctx = &mut self.inner as *mut _;
        let mut output = [0; 32];
        unsafe {
            cry_sha256_digest(ctx, output.as_mut_ptr());
        }
        output
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

lazy_static::lazy_static! {
    static ref HASH_ITF: cry_hash_itf = unsafe {
        cry_hash_itf {
            init: Some(core::mem::transmute(cry_sha256_init as usize)),
            clear: Some(core::mem::transmute(cry_sha256_clear as usize)),
            update: Some(core::mem::transmute(cry_sha256_update as usize)),
            digest: Some(core::mem::transmute(cry_sha256_digest as usize)),
        }
    };
}

impl Hasher for Sha256 {
    type Backend = cry_sha256_ctx;
    type DigestLen = typenum::U32;

    fn interface() -> *const cry_hash_itf {
        &*HASH_ITF as *const cry_hash_itf
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn digest() {
        let mut ctx = Sha256::new();

        ctx.update("Hello");
        ctx.update("World");

        let digest = ctx.digest().to_vec();

        assert_eq!(
            hex::encode(digest),
            "872e4e50ce9990d8b041330c47c9ddd11bec6b503ae9386a99da8584e9bb12c4"
        );
    }
}
