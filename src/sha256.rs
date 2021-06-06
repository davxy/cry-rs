use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_sha256_clear, cry_sha256_ctx, cry_sha256_digest, cry_sha256_init, cry_sha256_update,
};
use digest::{Digest, Output};
use generic_array::GenericArray;

pub struct Sha256 {
    inner: cry_sha256_ctx,
}

impl Sha256 {
    pub fn new() -> Self {
        let inner = unsafe {
            #[allow(clippy::uninit_assumed_init)]
            let mut inner = MaybeUninit::uninit().assume_init();
            let ctx = &mut inner as *mut _;
            cry_sha256_init(ctx);
            inner
        };
        Sha256 { inner }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

impl Digest for Sha256 {
    type OutputSize = typenum::U32;

    fn new() -> Self {
        Sha256::new()
    }

    fn output_size() -> usize {
        64
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        let ctx = &mut self.inner as *mut _;
        let data = data.as_ref();
        unsafe {
            cry_sha256_update(ctx, data.as_ptr(), data.len() as u64);
        }
    }

    fn chain(mut self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        self.update(data);
        self
    }

    fn finalize(mut self) -> Output<Self> {
        self.finalize_reset()
    }

    fn reset(&mut self) {
        let ctx = &mut self.inner as *mut _;
        unsafe {
            cry_sha256_clear(ctx);
        }
    }

    fn finalize_reset(&mut self) -> Output<Self> {
        let ctx = &self.inner as *const _ as *mut _;
        let mut output = vec![0; 32];
        unsafe {
            cry_sha256_digest(ctx, output.as_mut_ptr());
        }
        let output = GenericArray::clone_from_slice(output.as_slice());
        *self = Self::new();
        output
    }

    fn digest(data: &[u8]) -> Output<Self> {
        let mut sha = Sha256::new();
        sha.update(data);
        sha.finalize_reset()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn digest() {
        let mut sha = Sha256::new();

        sha.update("Hello");
        sha.update("World");

        let digest = sha.finalize_reset().to_owned();

        assert_eq!(hex::encode(digest), "872e4e50ce9990d8b041330c47c9ddd11bec6b503ae9386a99da8584e9bb12c4");
    }
}
