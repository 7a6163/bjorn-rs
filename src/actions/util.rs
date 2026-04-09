/// Simple base64 encoding without pulling in the base64 crate.
pub fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_empty() {
        assert_eq\!(base64_encode(""), "");
    }

    #[test]
    fn base64_encode_single_char() {
        assert_eq\!(base64_encode("A"), "QQ==");
    }

    #[test]
    fn base64_encode_two_chars() {
        assert_eq\!(base64_encode("AB"), "QUI=");
    }

    #[test]
    fn base64_encode_three_chars() {
        assert_eq\!(base64_encode("ABC"), "QUJD");
    }

    #[test]
    fn base64_encode_credentials() {
        assert_eq\!(base64_encode("user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn base64_encode_admin_credentials() {
        assert_eq\!(base64_encode("admin:admin"), "YWRtaW46YWRtaW4=");
    }
}
