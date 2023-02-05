#[cfg(test)]
pub fn hex_to_vec(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|chunk| u8::from_str_radix(chunk, 16).unwrap())
        .collect()
}