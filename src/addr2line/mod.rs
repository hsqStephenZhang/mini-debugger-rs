#[cfg(test)]
#[allow(unused_must_use)]
pub fn dump_file(object: &object::File, endian: gimli::RunTimeEndian) -> Result<(), gimli::Error> {
    use object::{Object, ObjectSection};
    use std::borrow;

    // Load a section and return as `Cow<[u8]>`.
    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, gimli::Error> {
        match object.section_by_name(id.name()) {
            Some(ref section) => Ok(section
                .uncompressed_data()
                .unwrap_or(borrow::Cow::Borrowed(&[][..]))),
            None => Ok(borrow::Cow::Borrowed(&[][..])),
        }
    };

    // Load all of the sections.
    let dwarf_cow = gimli::Dwarf::load(&load_section)?;

    // Borrow a `Cow<[u8]>` to create an `EndianSlice`.
    let borrow_section: &dyn for<'a> Fn(
        &'a borrow::Cow<[u8]>,
    ) -> gimli::EndianSlice<'a, gimli::RunTimeEndian> =
        &|section| gimli::EndianSlice::new(&*section, endian);

    // Create `EndianSlice`s for all of the sections.
    let dwarf = dwarf_cow.borrow(&borrow_section);

    dbg!(dump_entries(&dwarf));
    // dbg!(dump_line_infos(&dwarf));
    
    Ok(())
}

pub fn dump_entries(
    dwarf: &gimli::Dwarf<gimli::EndianSlice<gimli::RunTimeEndian>>,
) -> Result<(), gimli::Error> {
    use gimli::{read::EntriesCursor, AttributeValue};

    let mut iter = dwarf.units();
    // Iterate over the Debugging Information Entries (DIEs) in the unit.
    while let Some(header) = iter.next()? {
        println!(
            "Unit at <.debug_info+0x{:x}>",
            header.offset().as_debug_info_offset().unwrap().0
        );
        let unit = dwarf.unit(header)?;

        let mut depth = 0;
        let mut entries: EntriesCursor<_> = unit.entries();
        while let Some((delta_depth, entry)) = entries.next_dfs()? {
            let entry = entry;
            depth += delta_depth;
            println!("<{}><{:x}> {}", depth, entry.offset().0, entry.tag());

            // Iterate over the attributes in the DIE.
            let mut attrs = entry.attrs();
            while let Some(attr) = attrs.next()? {
                // } else {
                //     println!("   {}: {:?}", attr.name(), attr.value());
                // }
                let name = attr.name();
                println!("   {}: {:?}", attr.name(), attr.value());
                if name == gimli::constants::DW_AT_name {
                    match attr.value() {
                        AttributeValue::Addr(_) => todo!(),
                        AttributeValue::Block(_) => todo!(),
                        AttributeValue::Data1(_) => todo!(),
                        AttributeValue::Data2(_) => todo!(),
                        AttributeValue::Data4(_) => todo!(),
                        AttributeValue::Data8(_) => todo!(),
                        AttributeValue::Sdata(_) => todo!(),
                        AttributeValue::Udata(_) => todo!(),
                        AttributeValue::Exprloc(_) => todo!(),
                        AttributeValue::Flag(_) => todo!(),
                        AttributeValue::SecOffset(_) => todo!(),
                        AttributeValue::DebugAddrBase(_) => todo!(),
                        AttributeValue::DebugAddrIndex(_) => todo!(),
                        AttributeValue::UnitRef(_) => todo!(),
                        AttributeValue::DebugInfoRef(_) => todo!(),
                        AttributeValue::DebugInfoRefSup(_) => todo!(),
                        AttributeValue::DebugLineRef(_) => todo!(),
                        AttributeValue::LocationListsRef(_) => todo!(),
                        AttributeValue::DebugLocListsBase(_) => todo!(),
                        AttributeValue::DebugLocListsIndex(_) => todo!(),
                        AttributeValue::DebugMacinfoRef(_) => todo!(),
                        AttributeValue::DebugMacroRef(_) => todo!(),
                        AttributeValue::RangeListsRef(_) => todo!(),
                        AttributeValue::DebugRngListsBase(_) => todo!(),
                        AttributeValue::DebugRngListsIndex(_) => todo!(),
                        AttributeValue::DebugTypesRef(_) => todo!(),
                        AttributeValue::DebugStrRef(r) => {
                            let s = dwarf.debug_str.get_str(r).unwrap();
                            println!("---Get DebugStrRef: {:?}", s.to_string());
                        }
                        AttributeValue::DebugStrRefSup(_) => todo!(),
                        AttributeValue::DebugStrOffsetsBase(_) => todo!(),
                        AttributeValue::DebugStrOffsetsIndex(_) => todo!(),
                        AttributeValue::DebugLineStrRef(r) => {
                            let s = dwarf.debug_line_str.get_str(r).unwrap();
                            println!("---Get DebugLineStrRef: {:?}", s.to_string());
                        }
                        AttributeValue::String(s) => {
                            println!("---Get String: {:?}", s.to_string());
                        }
                        AttributeValue::Encoding(_) => todo!(),
                        AttributeValue::DecimalSign(_) => todo!(),
                        AttributeValue::Endianity(_) => todo!(),
                        AttributeValue::Accessibility(_) => todo!(),
                        AttributeValue::Visibility(_) => todo!(),
                        AttributeValue::Virtuality(_) => todo!(),
                        AttributeValue::Language(_) => todo!(),
                        AttributeValue::AddressClass(_) => todo!(),
                        AttributeValue::IdentifierCase(_) => todo!(),
                        AttributeValue::CallingConvention(_) => todo!(),
                        AttributeValue::Inline(_) => todo!(),
                        AttributeValue::Ordering(_) => todo!(),
                        AttributeValue::FileIndex(_) => todo!(),
                        AttributeValue::DwoId(_) => todo!(),
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn dump_line_infos(
    dwarf: &gimli::Dwarf<gimli::EndianSlice<gimli::RunTimeEndian>>,
) -> Result<(), gimli::Error> {
    // Iterate over the compilation units.
    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        println!(
            "Line number info for unit at <.debug_info+0x{:x}>",
            header.offset().as_debug_info_offset().unwrap().0
        );
        let unit = dwarf.unit(header)?;

        if let Some(prog) = unit.line_program.clone() {
            let compile_dir = if let Some(dir) = unit.comp_dir {
                std::path::PathBuf::from(dir.to_string_lossy().into_owned())
            } else {
                std::path::PathBuf::new()
            };

            let mut rows = prog.rows();

            while let Some((header, row)) = rows.next_row()? {
                if row.end_sequence() {
                    println!("{:x} end-sequence", row.address());
                } else {
                    let mut path = std::path::PathBuf::new();
                    if let Some(file) = row.file(header) {
                        path = compile_dir.clone();

                        // The directory index 0 is defined to correspond to the compilation unit directory.
                        if file.directory_index() != 0 {
                            if let Some(dir) = file.directory(header) {
                                path.push(
                                    dwarf.attr_string(&unit, dir)?.to_string_lossy().as_ref(),
                                );
                            }
                        }

                        path.push(
                            dwarf
                                .attr_string(&unit, file.path_name())?
                                .to_string_lossy()
                                .as_ref(),
                        );
                    }

                    // Determine line/column. DWARF line/column is never 0, so we use that
                    // but other applications may want to display this differently.
                    let line = match row.line() {
                        Some(line) => line.get(),
                        None => 0,
                    };
                    let column = match row.column() {
                        gimli::ColumnType::LeftEdge => 0,
                        gimli::ColumnType::Column(column) => column.get(),
                    };

                    println!("{:x} {}:{}:{}", row.address(), path.display(), line, column);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::dump_file;

    #[test]
    fn t1() {
        let content = include_bytes!("../../data/test");
        let file = object::File::parse(&content[..]).unwrap();
        dump_file(&file, gimli::RunTimeEndian::Little).unwrap();
    }
}
