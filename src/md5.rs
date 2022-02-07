use crate::cipher::Hasher;
use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_hash_itf, cry_md5_clear, cry_md5_ctx, cry_md5_digest, cry_md5_init, cry_md5_update,
};

const DIGEST_SIZE: usize = 16;

pub struct Md5 {
    inner: cry_md5_ctx,
}

impl Md5 {
    pub fn new() -> Self {
        let inner = unsafe {
            let mut inner = MaybeUninit::uninit().assume_init();
            let ctx = &mut inner as *mut _;
            cry_md5_init(ctx);
            inner
        };
        Md5 { inner }
    }

    pub fn clear(&mut self) {
        let ctx = &mut self.inner as *mut _;
        unsafe {
            cry_md5_clear(ctx);
        }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let ctx = &mut self.inner as *mut _;
        let data = data.as_ref();
        unsafe {
            cry_md5_update(ctx, data.as_ptr(), data.len() as u64);
        }
    }

    pub fn digest(&mut self) -> [u8; DIGEST_SIZE] {
        let ctx = &mut self.inner as *mut _;
        let mut output = [0; DIGEST_SIZE];
        unsafe {
            cry_md5_digest(ctx, output.as_mut_ptr());
        }
        output
    }
}

impl Default for Md5 {
    fn default() -> Self {
        Md5::new()
    }
}

lazy_static::lazy_static! {
    static ref HASH_ITF: cry_hash_itf = unsafe {
        cry_hash_itf {
            init: Some(core::mem::transmute(cry_md5_init as usize)),
            clear: Some(core::mem::transmute(cry_md5_clear as usize)),
            update: Some(core::mem::transmute(cry_md5_update as usize)),
            digest: Some(core::mem::transmute(cry_md5_digest as usize)),
        }
    };
}

impl Hasher for Md5 {
    type Backend = cry_md5_ctx;
    type DigestLen = typenum::U16;

    fn interface() -> *const cry_hash_itf {
        &*HASH_ITF as *const cry_hash_itf
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn digest() {
        let mut ctx = Md5::new();

        ctx.update("Hello");
        ctx.update("World");

        let digest = ctx.digest().to_vec();

        assert_eq!(hex::encode(digest), "68e109f0f40ca72a15e05cc22786f8e6");
    }
}
