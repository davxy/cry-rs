use cry_sys::bindings::{cry_base64_decode, cry_base64_encode};

pub fn encode(input: &[u8]) -> String {
    let mut output: Vec<u8> = vec![0; 2 * input.len()];
    let len = unsafe {
        cry_base64_encode(
            output.as_mut_ptr() as *mut i8,
            input.as_ptr() as *const i8,
            input.len() as u64,
        )
    };
    output.resize(len as usize, 0);
    String::from_utf8(output).unwrap_or_default()
}

pub fn decode(input: &str) -> Vec<u8> {
    let mut output = vec![0; input.len()];
    let len = unsafe {
        cry_base64_decode(
            output.as_mut_ptr() as *mut i8,
            input.as_ptr() as *const i8,
            input.len() as u64,
        )
    };
    output.resize(len as usize, 0);
    output
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_data() {
        let input = "HelloWorld";

        let output = encode(input.as_bytes());

        assert_eq!("SGVsbG9Xb3JsZA==", output);
    }

    #[test]
    fn decode_data() {
        let input = "SGVsbG9Xb3JsZA==";

        let output = decode(input);

        assert_eq!("HelloWorld", String::from_utf8_lossy(&output));
    }
}
