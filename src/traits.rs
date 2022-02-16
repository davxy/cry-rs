use cry_sys::bindings::{cry_ciph_itf, cry_hash_itf};
use typenum::Unsigned;

pub trait Cipher {
    type Backend;

    fn interface() -> *const cry_ciph_itf;
}

pub trait Hasher {
    type Backend;
    type DigestLen: Unsigned;

    fn interface() -> *const cry_hash_itf;
}
