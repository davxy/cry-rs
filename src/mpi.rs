use core::{
    fmt::Display,
    mem::MaybeUninit,
    ops::{Add, AddAssign},
};
use cry_sys::bindings::{
    cry_mpi, cry_mpi_add, cry_mpi_clear, cry_mpi_count_bits, cry_mpi_init, cry_mpi_init_str,
    cry_mpi_store_str,
};

#[derive(Debug)]
pub struct Mpi {
    backend: cry_mpi,
}

// We're not supposed to recover from this type of errors here.
macro_rules! checked {
    ($op:expr) => {
        if $op != 0 {
            panic!("Out of memory error");
        }
    };
}

impl Mpi {
    pub fn new() -> Self {
        let backend = unsafe {
            let mut backend = MaybeUninit::uninit().assume_init();
            let ctx = &mut backend as *mut _;
            checked!(cry_mpi_init(ctx));
            backend
        };
        Mpi { backend }
    }

    pub fn from_hex(x: &str) -> Result<Self, String> {
        let mut v = Vec::with_capacity(x.len() + 1);
        v.extend_from_slice(x.as_bytes());
        v.push(0);
        let backend = unsafe {
            let mut backend = MaybeUninit::uninit().assume_init();
            let ctx = &mut backend as *mut _;
            if cry_mpi_init_str(ctx, 16, v.as_ptr() as *const i8) != 0 {
                return Err("Invalid hex string".into());
            }
            backend
        };
        Ok(Mpi { backend })
    }

    pub fn bits_count(&self) -> usize {
        unsafe { cry_mpi_count_bits(&self.backend as *const _) as usize }
    }

    pub fn bytes_count(&self) -> usize {
        (self.bits_count() + 7) / 8
    }
}

impl Drop for Mpi {
    fn drop(&mut self) {
        let backend = &mut self.backend as *mut _;
        unsafe {
            cry_mpi_clear(backend);
        }
    }
}

impl Add for Mpi {
    type Output = Mpi;

    fn add(self, rhs: Self) -> Self::Output {
        let mut res = Mpi::new();
        unsafe {
            checked!(cry_mpi_add(
                &mut res.backend as *mut _,
                &self.backend,
                &rhs.backend
            ))
        }
        res
    }
}

impl AddAssign for Mpi {
    fn add_assign(&mut self, rhs: Self) {
        unsafe {
            cry_mpi_add(&mut self.backend, &self.backend, &rhs.backend);
        }
    }
}

impl Display for Mpi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes: Vec<u8> = vec![0; 2 * (10 + self.bytes_count())];
        let s = unsafe {
            cry_mpi_store_str(&self.backend as *const _, 16, bytes.as_mut_ptr() as *mut i8);
            let off = bytes.iter().rposition(|&c| c != 0).unwrap_or_default();
            String::from_utf8_unchecked(bytes[0..=off].to_owned())
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add() {
        let a = Mpi::from_hex("123456").unwrap();
        let b = Mpi::from_hex("7890").unwrap();

        let mut c = a + b;
        assert_eq!("12ace6", c.to_string());

        let a = Mpi::from_hex("12").unwrap();
        c += a;
        assert_eq!("12acf8", c.to_string());
    }
}
