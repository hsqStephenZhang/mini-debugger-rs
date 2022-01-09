use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn str_to_usize(s: &str) -> Result<usize, &str> {
    if s.starts_with("0x") {
        let real = &s[2..];
        return usize::from_str_radix(real, 16).map_err(|_e| real);
    } else {
        return s.parse::<usize>().map_err(|_e| s);
    }
}

pub fn str_to_u64(s: &str) -> Result<u64, &str> {
    if s.starts_with("0x") {
        let real = &s[2..];
        return u64::from_str_radix(real, 16).map_err(|_e| real);
    } else {
        return s.parse::<u64>().map_err(|_e| s);
    }
}

pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
