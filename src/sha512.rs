use crate::traits::Hasher;
use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_hash_itf, cry_sha512_clear, cry_sha512_ctx, cry_sha512_digest, cry_sha512_init,
    cry_sha512_update,
};

pub struct Sha512 {
    inner: cry_sha512_ctx,
}

impl Sha512 {
    pub fn new() -> Self {
        Self::new_inner(false)
    }

    fn new_inner(is_384: bool) -> Self {
        let inner = unsafe {
            let mut inner = MaybeUninit::uninit().assume_init();
            let ctx = &mut inner as *mut _;
            cry_sha512_init(ctx, is_384 as i8);
            inner
        };
        Sha512 { inner }
    }

    pub fn clear(&mut self) {
        let ctx = &mut self.inner as *mut _;
        unsafe {
            cry_sha512_clear(ctx);
        }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let ctx = &mut self.inner as *mut _;
        let data = data.as_ref();
        unsafe {
            cry_sha512_update(ctx, data.as_ptr(), data.len() as u64);
        }
    }

    pub fn digest(&mut self) -> [u8; 64] {
        let ctx = &mut self.inner as *mut _;
        let mut output = [0; 64];
        unsafe {
            cry_sha512_digest(ctx, output.as_mut_ptr());
        }
        output
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Sha512::new()
    }
}

#[no_mangle]
extern "C" fn sha512_init(ctx: *mut cry_sha512_ctx) {
    unsafe {
        cry_sha512_init(ctx, 0);
    }
}

lazy_static::lazy_static! {
    static ref SHA512_ITF: cry_hash_itf = unsafe {
        cry_hash_itf {
            init: Some(core::mem::transmute(sha512_init as usize)),
            clear: Some(core::mem::transmute(cry_sha512_clear as usize)),
            update: Some(core::mem::transmute(cry_sha512_update as usize)),
            digest: Some(core::mem::transmute(cry_sha512_digest as usize)),
        }
    };
}

impl Hasher for Sha512 {
    type Backend = cry_sha512_ctx;
    type DigestLen = typenum::U64;

    fn interface() -> *const cry_hash_itf {
        &*SHA512_ITF as *const cry_hash_itf
    }
}

pub struct Sha384(Sha512);

impl Sha384 {
    pub fn new() -> Self {
        Self(Sha512::new_inner(true))
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data);
    }

    pub fn digest(&mut self) -> [u8; 48] {
        let dig = self.0.digest();
        let mut res = [0; 48];
        res.copy_from_slice(&dig[..48]);
        res
    }
}

#[no_mangle]
extern "C" fn sha384_init(ctx: *mut cry_sha512_ctx) {
    unsafe {
        cry_sha512_init(ctx, 1);
    }
}

lazy_static::lazy_static! {
    static ref SHA384_ITF: cry_hash_itf = unsafe {
        cry_hash_itf {
            init: Some(core::mem::transmute(sha384_init as usize)),
            clear: Some(core::mem::transmute(cry_sha512_clear as usize)),
            update: Some(core::mem::transmute(cry_sha512_update as usize)),
            digest: Some(core::mem::transmute(cry_sha512_digest as usize)),
        }
    };
}

impl Hasher for Sha384 {
    type Backend = cry_sha512_ctx;
    type DigestLen = typenum::U48;

    fn interface() -> *const cry_hash_itf {
        &*SHA384_ITF as *const cry_hash_itf
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sha512_digest() {
        let mut sha = Sha512::new();

        sha.update("Hello");
        sha.update("World");

        let digest = sha.digest();

        assert_eq!(
            hex::encode(digest),
            "8ae6ae71a75d3fb2e0225deeb004faf95d816a0a58093eb4cb5a3aa0f197050d7a4dc0a2d5c6fbae5fb5b0d536a0a9e6b686369fa57a027687c3630321547596",
        );
    }

    #[test]
    fn sha384_digest() {
        let mut ctx = Sha384::new();

        ctx.update("Hello");
        ctx.update("World");

        let digest = ctx.digest();

        assert_eq!(
            hex::encode(digest),
            "293cd96eb25228a6fb09bfa86b9148ab69940e68903cbc0527a4fb150eec1ebe0f1ffce0bc5e3df312377e0a68f1950a"
        );
    }
}
