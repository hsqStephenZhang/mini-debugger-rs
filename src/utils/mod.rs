use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
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

#[allow(dead_code)]
pub(crate) fn disassemble(bytes: &[u8], code_bitness: u32, rip: u64, column_byte_length: usize) {
    let mut decoder = Decoder::with_ip(code_bitness, bytes, rip, DecoderOptions::NONE);

    let mut formatter = NasmFormatter::new();

    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);

    let mut output = String::new();

    let mut instruction = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        output.clear();
        formatter.format(&instruction, &mut output);

        print!("0x{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - rip) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }
        if instr_bytes.len() < column_byte_length {
            for _ in 0..column_byte_length - instr_bytes.len() {
                print!("  ");
            }
        }
        println!(" {}", output);
    }
}

#[cfg(test)]
mod tests {
    use iced_x86::{Decoder, DecoderOptions};

    #[test]
    fn t1() {
        let bytes = [0xcc, 0, 0, 0, 0];
        let mut decoder = Decoder::with_ip(64, &bytes[..], 0x1234_5678, DecoderOptions::NONE);
        let r = decoder.decode();
        dbg!(r);
    }
}
