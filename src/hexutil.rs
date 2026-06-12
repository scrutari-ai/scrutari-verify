//! Minimal lower-hex decode, no external crate — so the verifier's dependency
//! surface (the thing an auditor reviews) stays small. Encoding lives in
//! [`crate::crypto::hex_lower`]; this is only the inverse.

/// Decode a lower/upper-hex string into bytes. Errors (never panics) on an odd
/// length or a non-hex character.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length {}", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    // `bytes.len()` is even (checked above) and `i` steps by 2, so `i + 1` is
    // always in range when `i < len` — no panic path.
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// Decode a hex string that must be exactly 32 bytes (a SHA-256 digest / Merkle
/// node). Errors on any other length.
pub fn decode32(s: &str) -> Result<[u8; 32], String> {
    let v = decode(s)?;
    let arr: [u8; 32] = v
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

fn hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!("invalid hex digit '{}'", other as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_errors() {
        assert_eq!(decode("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert_eq!(decode("ABcd").unwrap(), vec![0xab, 0xcd]);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert!(decode("abc").is_err(), "odd length rejected");
        assert!(decode("zz").is_err(), "non-hex rejected");
        assert!(decode32("00").is_err(), "wrong length for 32-byte decode");
        assert_eq!(decode32(&"ab".repeat(32)).unwrap()[0], 0xab);
    }
}
