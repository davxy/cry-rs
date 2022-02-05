use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_sha512_clear, cry_sha512_ctx, cry_sha512_digest, cry_sha512_init, cry_sha512_update,
};

pub struct Sha512 {
    inner: cry_sha512_ctx,
}

impl Sha512 {
    pub fn new() -> Self {
        let inner = unsafe {
            let mut inner = MaybeUninit::uninit().assume_init();
            let ctx = &mut inner as *mut _;
            cry_sha512_init(ctx, 0);
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn digest() {
        let mut sha = Sha512::new();

        sha.update("Hello");
        sha.update("World");

        let digest = sha.digest();

        assert_eq!(
            hex::encode(digest),
            "8ae6ae71a75d3fb2e0225deeb004faf95d816a0a58093eb4cb5a3aa0f197050d7a4dc0a2d5c6fbae5fb5b0d536a0a9e6b686369fa57a027687c3630321547596",
        );
    }
}
