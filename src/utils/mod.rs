pub fn str_to_usize(s: &str) -> Result<usize, &str> {
    if s.starts_with("0x") {
        let real = &s[2..];
        return usize::from_str_radix(real, 16).map_err(|_e| real);
    } else {
        return s.parse::<usize>().map_err(|_e| s);
    }
}

pub fn i64_to_u8s(value: i64) -> [u8; 8] {
    unsafe { std::mem::transmute(value) }
}
