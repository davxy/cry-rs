use core::mem::{self, MaybeUninit};
use cry_sys::bindings::{
    cry_aes_clear, cry_aes_ctx, cry_aes_encrypt, cry_aes_key_set, cry_ciph_itf, cry_gcm_clear,
    cry_gcm_ctx, cry_gcm_decrypt, cry_gcm_encrypt, cry_gcm_init, cry_gcm_key_set,
};

pub struct AesGcm {
    gcm_ctx: cry_gcm_ctx,
    aes_ctx: cry_aes_ctx,
    aes_itf: cry_ciph_itf,
}

impl AesGcm {
    pub fn new(key: &[u8]) -> Self {
        let key = key.as_ref();
        let len = key.len();
        unsafe {
            let mut this: Self = MaybeUninit::uninit().assume_init();

            let aes_ctx = &mut this.aes_ctx as *mut _ as *mut core::ffi::c_void;
            let aes_itf = &mut this.aes_itf as *mut _;
            let gcm_ctx = &mut this.gcm_ctx as *mut _;

            this.aes_itf.key_set = Some(mem::transmute(cry_aes_key_set as usize));
            this.aes_itf.encrypt = Some(mem::transmute(cry_aes_encrypt as usize));
            this.aes_itf.clear = Some(mem::transmute(cry_aes_clear as usize));

            cry_gcm_init(gcm_ctx, aes_ctx, aes_itf);
            cry_gcm_key_set(gcm_ctx, key.as_ptr(), len as u64);

            this
        }
    }

    pub fn reset(&mut self, key: &[u8]) {
        let ctx = &mut self.gcm_ctx as *mut _;
        let key = key.as_ref();
        let len = key.len();
        unsafe {
            cry_gcm_key_set(ctx, key.as_ptr(), len as u64);
        }
    }

    pub fn encrypt(&mut self, src: impl AsRef<[u8]>) -> Vec<u8> {
        let src = src.as_ref();
        let ctx = &mut self.gcm_ctx as *mut _;
        let mut dst = vec![0u8; src.len()];
        unsafe {
            cry_gcm_encrypt(ctx, dst.as_mut_ptr(), src.as_ptr(), src.len() as u64);
        }
        dst
    }

    pub fn encrypt_inplace(&mut self, mut data: impl AsMut<[u8]>) {
        let data = data.as_mut();
        let ctx = &mut self.gcm_ctx as *mut _;
        unsafe {
            cry_gcm_encrypt(ctx, data.as_mut_ptr(), data.as_ptr(), data.len() as u64);
        }
    }

    pub fn decrypt(&mut self, src: impl AsRef<[u8]>) -> Vec<u8> {
        let src = src.as_ref();
        let ctx = &mut self.gcm_ctx as *mut _;
        let mut dst = vec![0u8; src.len()];
        unsafe {
            cry_gcm_decrypt(ctx, dst.as_mut_ptr(), src.as_ptr(), src.len() as u64);
        }
        dst
    }

    pub fn decrypt_inplace(&mut self, mut data: impl AsMut<[u8]>) {
        let data = data.as_mut();
        let ctx = &mut self.gcm_ctx as *mut _;
        unsafe {
            cry_gcm_decrypt(ctx, data.as_mut_ptr(), data.as_ptr(), data.len() as u64);
        }
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        let ctx = &mut self.gcm_ctx as *mut _;
        unsafe { cry_gcm_clear(ctx) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_128_encrypt_decrypt() {
        let key = [0; 16];
        let mut ctx = AesGcm::new(&key);
        let data = [0; 1024];

        let enc = ctx.encrypt(&data);

        ctx.reset(&key);

        let dec = ctx.decrypt(&enc);

        assert_eq!(&data[..], &dec[..]);
    }

    #[test]
    fn aes_gcm_128_encrypt_decrypt_inplace() {
        let key = [0; 16];
        let mut ctx = AesGcm::new(&key);
        let mut data = [0; 1024];

        ctx.encrypt_inplace(&mut data);

        ctx.reset(&key);

        ctx.decrypt_inplace(&mut data);

        assert_eq!(data, [0; 1024]);
    }
}
