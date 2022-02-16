// Utilities
pub mod base64;

// Modern strong primitives
pub mod aes;
pub mod arc4;
pub mod des;
pub mod gcm;
pub mod hmac;
pub mod sha1;
pub mod sha256;
pub mod sha512;

// Modern weak primitives
#[cfg(feature = "weak")]
pub mod md5;

// Historical ciphers (just for fun)
#[cfg(feature = "historical")]
pub mod affine;
#[cfg(feature = "historical")]
pub mod hill;

mod traits;
