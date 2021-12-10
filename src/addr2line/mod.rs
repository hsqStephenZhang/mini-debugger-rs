use goblin::{
    elf::{Elf, SectionHeader, Sym},
    elf64::sym::STT_FUNC,
    Object,
};

trait ElfExt {
    fn section_by_name<'a>(&'a self, section_name: &str) -> Option<&'a SectionHeader>;
    fn load_function(&self, func_name: &str) -> Option<Sym>;
    fn dump_file(&self, endian: gimli::RunTimeEndian) -> Result<(), gimli::Error>;
}

impl<'a> ElfExt for Elf<'a> {
    fn section_by_name<'b>(&'b self, section_name: &str) -> Option<&'b SectionHeader> {
        for header in self.section_headers.iter() {
            match self.shdr_strtab.get_at(header.sh_name) {
                Some(r) => {
                    if r == section_name {
                        return Some(header);
                    }
                }
                None => {}
            }
        }
        None
    }

    fn load_function(&self, func_name: &str) -> Option<Sym> {
        for s in self.syms.iter() {
            if s.st_type() != STT_FUNC {
                continue;
            }
            match self.strtab.get_at(s.st_name) {
                Some(r) => {
                    if r == func_name {
                        return Some(s);
                    }
                }
                None => {}
            }
        }
        None
    }

    fn dump_file(&self, _endian: gimli::RunTimeEndian) -> Result<(), gimli::Error> {
        // let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, gimli::Error> {
        //     match self.section_by_name(id.name()) {
        //         Some(section) => Ok(section
        //             .uncompressed_data()
        //             .unwrap_or(borrow::Cow::Borrowed(&[][..]))),
        //         None => Ok(borrow::Cow::Borrowed(&[][..])),
        //     }
        // };
        todo!()
    }
}

pub fn load<'a>(buffer: &'a [u8]) -> Result<Elf<'a>, goblin::error::Error> {
    match Object::parse(&buffer)? {
        Object::Elf(elf) => return Ok(elf),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test1() {
        let content = include_bytes!("../../data/test");
        let elf = load(content).unwrap();
        dbg!(elf);
    }
}
