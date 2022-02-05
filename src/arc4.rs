use core::mem::MaybeUninit;
use cry_sys::bindings::{
    cry_arc4_clear, cry_arc4_crypt, cry_arc4_ctx, cry_arc4_init, cry_arc4_key_set,
};

pub struct Arc4 {
    inner: cry_arc4_ctx,
}

impl Arc4 {
    pub fn new(key: &[u8]) -> Self {
        let inner = unsafe {
            let mut inner = MaybeUninit::uninit().assume_init();
            let ctx = &mut inner as *mut _;
            cry_arc4_init(ctx);
            inner
        };
        let mut this = Arc4 { inner };
        this.reset(key);
        this
    }

    pub fn reset(&mut self, key: &[u8]) {
        let ctx = &mut self.inner as *mut _;
        let key = key.as_ref();
        let len = key.len();
        unsafe {
            cry_arc4_key_set(ctx, key.as_ptr(), len as u64);
        }
    }

    pub fn crypt(&mut self, src: impl AsRef<[u8]>) -> Vec<u8> {
        let ctx = &mut self.inner as *mut _;
        let src = src.as_ref();
        let mut dst = vec![0u8; src.len()];
        unsafe {
            cry_arc4_crypt(ctx, dst.as_mut_ptr(), src.as_ptr(), src.len() as u64);
        }
        dst
    }

    pub fn crypt_inplace(&mut self, mut data: impl AsMut<[u8]>) {
        let ctx = &mut self.inner as *mut _;
        let data = data.as_mut();
        unsafe {
            cry_arc4_crypt(ctx, data.as_mut_ptr(), data.as_ptr(), data.len() as u64);
        }
    }
}

impl Drop for Arc4 {
    fn drop(&mut self) {
        let ctx = &mut self.inner as *mut _;
        unsafe { cry_arc4_clear(ctx) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc4128_encrypt_decrypt() {
        let key = [0; 16];
        let mut ctx = Arc4::new(&key);
        let data = [0; 1024];

        let enc = ctx.crypt(&data);

        ctx.reset(&key);

        let dec = ctx.crypt(&enc);

        assert_eq!(&data[..], &dec[..]);
    }

    #[test]
    fn arc4128_encrypt_decrypt_inplace() {
        let key = [0; 16];
        let mut ctx = Arc4::new(&key);
        let mut data = [0; 1024];

        ctx.crypt_inplace(&mut data);

        ctx.reset(&key);

        ctx.crypt_inplace(&mut data);

        assert_eq!(data, [0; 1024]);
    }
}
