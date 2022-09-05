use core::{
    fmt::Display,
    mem::MaybeUninit,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Rem, RemAssign, Sub, SubAssign},
};
use cry_sys::bindings::{
    cry_mpi, cry_mpi_add, cry_mpi_clear, cry_mpi_copy, cry_mpi_count_bits, cry_mpi_div,
    cry_mpi_init, cry_mpi_init_str, cry_mpi_mod_exp, cry_mpi_mul, cry_mpi_store_str, cry_mpi_sub,
};

#[derive(Debug)]
pub struct Mpi {
    backend: cry_mpi,
}

// We're not supposed to recover from this type of errors here.
macro_rules! checked {
    ($op:expr) => {
        if unsafe { $op } != 0 {
            panic!("Out of memory error");
        }
    };
}

impl Mpi {
    pub fn new() -> Self {
        let mut backend = unsafe { MaybeUninit::uninit().assume_init() };
        checked!(cry_mpi_init(&mut backend));
        Mpi { backend }
    }

    pub fn from_hex(x: &str) -> Result<Self, String> {
        let mut v = Vec::with_capacity(x.len() + 1);
        v.extend_from_slice(x.as_bytes());
        v.push(0);
        let backend = unsafe {
            let mut backend = MaybeUninit::uninit().assume_init();
            if cry_mpi_init_str(&mut backend, 16, v.as_ptr() as *const i8) != 0 {
                return Err("Invalid hex string".into());
            }
            backend
        };
        Ok(Mpi { backend })
    }

    pub fn bits_count(&self) -> usize {
        unsafe { cry_mpi_count_bits(&self.backend) as usize }
    }

    pub fn bytes_count(&self) -> usize {
        (self.bits_count() + 7) / 8
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut res = Mpi::new();
        checked!(cry_mpi_add(&mut res.backend, &self.backend, &other.backend));
        res
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut res = Mpi::new();
        checked!(cry_mpi_sub(&mut res.backend, &self.backend, &other.backend));
        res
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut res = Mpi::new();
        checked!(cry_mpi_mul(&mut res.backend, &self.backend, &other.backend));
        res
    }

    // Returns quotiend and reminder tuple.
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let mut q = Mpi::new();
        let mut r = Mpi::new();
        checked!(cry_mpi_div(
            &mut q.backend,
            &mut r.backend,
            &self.backend,
            &other.backend
        ));
        (q, r)
    }

    pub fn div(&self, other: &Self) -> Self {
        self.div_rem(other).0
    }

    pub fn rem(&self, other: &Self) -> Self {
        self.div_rem(other).1
    }

    pub fn mod_exp(&self, exp: &Self, modulus: &Self) -> Self {
        let mut res = Mpi::new();
        checked!(cry_mpi_mod_exp(
            &mut res.backend,
            &self.backend,
            &exp.backend,
            &modulus.backend
        ));
        res
    }

    pub fn add_assign(&mut self, other: &Self) {
        checked!(cry_mpi_add(
            &mut self.backend,
            &self.backend,
            &other.backend
        ));
    }

    pub fn sub_assign(&mut self, other: &Self) {
        checked!(cry_mpi_sub(
            &mut self.backend,
            &self.backend,
            &other.backend
        ));
    }

    pub fn mul_assign(&mut self, other: &Self) {
        checked!(cry_mpi_mul(
            &mut self.backend,
            &self.backend,
            &other.backend
        ));
    }

    pub fn div_assign(&mut self, other: &Self) {
        checked!(cry_mpi_div(
            &mut self.backend,
            core::ptr::null_mut(),
            &self.backend,
            &other.backend
        ));
    }

    pub fn rem_assign(&mut self, other: &Self) {
        checked!(cry_mpi_div(
            core::ptr::null_mut(),
            &mut self.backend,
            &self.backend,
            &other.backend
        ));
    }
}

impl Drop for Mpi {
    fn drop(&mut self) {
        unsafe {
            cry_mpi_clear(&mut self.backend);
        }
    }
}

impl Clone for Mpi {
    fn clone(&self) -> Self {
        let mut res = Mpi::new();
        checked!(cry_mpi_copy(&mut res.backend, &self.backend));
        res
    }
}

impl Add for Mpi {
    type Output = Mpi;

    fn add(self, rhs: Self) -> Self::Output {
        Self::add(&self, &rhs)
    }
}

impl Sub for Mpi {
    type Output = Mpi;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::sub(&self, &rhs)
    }
}

impl Mul for Mpi {
    type Output = Mpi;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::mul(&self, &rhs)
    }
}

impl Div for Mpi {
    type Output = Mpi;

    fn div(self, rhs: Self) -> Self::Output {
        Self::div(&self, &rhs)
    }
}

impl Rem for Mpi {
    type Output = Mpi;

    fn rem(self, rhs: Self) -> Self::Output {
        Self::rem(&self, &rhs)
    }
}

impl AddAssign for Mpi {
    fn add_assign(&mut self, rhs: Self) {
        Self::add_assign(self, &rhs);
    }
}

impl SubAssign for Mpi {
    fn sub_assign(&mut self, rhs: Self) {
        Self::sub_assign(self, &rhs);
    }
}

impl MulAssign for Mpi {
    fn mul_assign(&mut self, rhs: Self) {
        Self::mul_assign(self, &rhs);
    }
}

impl DivAssign for Mpi {
    fn div_assign(&mut self, rhs: Self) {
        Self::div_assign(self, &rhs);
    }
}

impl RemAssign for Mpi {
    fn rem_assign(&mut self, rhs: Self) {
        Self::rem_assign(self, &rhs);
    }
}

impl Display for Mpi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes: Vec<u8> = vec![0; 2 * (10 + self.bytes_count())];
        checked!(cry_mpi_store_str(
            &self.backend,
            16,
            bytes.as_mut_ptr() as *mut i8
        ));
        let off = bytes.iter().rposition(|&c| c != 0).unwrap_or_default();
        write!(f, "{}", String::from_utf8_lossy(&bytes[0..=off]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A_HEX: &str = "e832fcffa681dec7a22795ba8e528dd5e9af5d197f50fce4340707efec68e1f9";
    const B_HEX: &str = "6ba218432ef91f921a3dfe1b19725e61274cf66f76b5297c6ccd95c0d3d20ac1";
    const C_HEX: &str = "4ca6087f5d5f081fbe7a305def082458ae2c5020b2b6116253dc62a8beab09ac";

    const ADD_RES: &str = "153d51542d57afe59bc6593d5a7c4ec3710fc5388f6062660a0d49db0c03aecba";
    const SUB_RES: &str = "7c90e4bc7788bf3587e9979f74e02f74c26266aa089bd367c739722f1896d738";
    const MUL_RES: &str = "61a05604ac0af481e2141fb88a9a3958d46bf7925dd4273091e10b1be8d4e6b41805b66838d5759f1cdb7289b546945da92482d639d088db1cdb2326ed2816b9";
    const DIV_RES: &str = "2";
    const REM_RES: &str = "10eecc79488f9fa36dab99845b6dd1139b15703a91e6a9eb5a6bdc6e44c4cc77";
    const MOD_EXP_RES: &str = "3c544e8ea7a083b08e08975f28e2a4673d421c6956f93a1aa65a204e03eb87e1";

    fn from_hex(s: &str) -> Mpi {
        Mpi::from_hex(s).unwrap()
    }

    #[test]
    fn add() {
        let a = from_hex(A_HEX);
        let b = from_hex(B_HEX);

        let c = a + b;

        assert_eq!(c.to_string(), ADD_RES);
    }

    #[test]
    fn sub() {
        let a = from_hex(A_HEX);
        let b = from_hex(B_HEX);

        let c = a - b;

        assert_eq!(c.to_string(), SUB_RES);
    }

    #[test]
    fn mul() {
        let a = from_hex(A_HEX);
        let b = from_hex(B_HEX);

        let c = a * b;

        assert_eq!(c.to_string(), MUL_RES);
    }

    #[test]
    fn div() {
        let a = from_hex(A_HEX);
        let b = from_hex(B_HEX);

        let c = a / b;

        assert_eq!(c.to_string(), DIV_RES);
    }

    #[test]
    fn rem() {
        let a = from_hex(A_HEX);
        let b = from_hex(B_HEX);

        let c = a % b;

        assert_eq!(c.to_string(), REM_RES);
    }

    #[test]
    fn add_assign() {
        let a = from_hex(A_HEX);
        let mut b = from_hex(B_HEX);

        b += a;

        assert_eq!(b.to_string(), ADD_RES);
    }

    #[test]
    fn sub_assign() {
        let mut a = from_hex(A_HEX);
        let b = from_hex(B_HEX);

        a -= b;

        assert_eq!(a.to_string(), SUB_RES);
    }

    #[test]
    fn mul_assign() {
        let a = from_hex(A_HEX);
        let mut b = from_hex(B_HEX);

        b *= a;

        assert_eq!(b.to_string(), MUL_RES);
    }

    #[test]
    fn div_assign() {
        let mut a = from_hex(A_HEX);
        let b = from_hex(B_HEX);

        a /= b;

        assert_eq!(a.to_string(), DIV_RES);
    }

    #[test]
    fn rem_assign() {
        let mut a = from_hex(A_HEX);
        let b = from_hex(B_HEX);

        a %= b;

        assert_eq!(a.to_string(), REM_RES);
    }

    #[test]
    fn mod_exp() {
        let a = from_hex(A_HEX);
        let b = from_hex(B_HEX);
        let c = from_hex(C_HEX);

        let c = a.mod_exp(&b, &c);

        assert_eq!(c.to_string(), MOD_EXP_RES);
    }
}
