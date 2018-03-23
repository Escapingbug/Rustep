use std::mem;
use nom::{IResult, IResult::*, Needed::{Size, Unknown}, *};
use failure::Error;
use error::RustepErrorKind;
use format::{
    executable::Executable,
    elf::*,
};
use num::FromPrimitive;
use enumflags::BitFlags;

pub fn parse_elf(input: &[u8]) -> Result<Executable, Error> {
    let elf_class = nom_try!(parse_elf_class(input)) as u32;
    match elf_class {
        ELFCLASS32 => parse_elf32(input),
        ELFCLASS64 => parse_elf64(input),
        val => Err(RustepErrorKind::UnsupportedElfClass(val as u8))?,
    }
}

macro_rules! define_elf_parser {
    {
        $func_name: ident,
        $header_parser: ident,
        $section_parser: ident,
        $segment_parser: ident,
        $section: ident,
        $segment: ident,
        $result: ident
    } => {
            pub fn $func_name(input: &[u8]) -> Result<Executable, Error> {
                let hdr = nom_try!($header_parser(input));
                let mut segments = Vec::new();
                let mut sections = Vec::new();
                let program_headers = nom_try!(preceded!(
                    input,
                    take!(hdr.e_phoff),
                    count!(call!($segment_parser), hdr.e_phnum as usize)
                ));
                for p in program_headers.iter() {
                    let data = &input[(p.p_offset as usize)..(p.p_offset + p.p_filesz) as usize];
                    let segment_type = FromPrimitive::from_u32(p.p_type)
                        .ok_or(RustepErrorKind::SegmentType(p.p_type as u64))?;
                    let flags = BitFlags::from_bits(p.p_flags as u64)
                        .ok_or(RustepErrorKind::SegmentFlag(p.p_flags as u64))?;
                    let segment = $segment {
                        phdr: *p,
                        segment_type: segment_type,
                        flags: flags,
                        data: data
                    };
            
                    segments.push(segment);
                }
                let section_headers = nom_try!(preceded!(
                    input,
                    take!(hdr.e_shoff),
                    count!(call!($section_parser), hdr.e_shnum as usize)
                ));
                for s in section_headers.iter() {
                    let data = &input[(s.sh_offset as usize) .. (s.sh_offset + s.sh_size) as usize];
                    let section_type = FromPrimitive::from_u32(s.sh_type)
                        .ok_or(RustepErrorKind::SectionType(s.sh_type as u64))?;
                    let flags = BitFlags::from_bits(s.sh_flags as u64)
                        .ok_or(RustepErrorKind::SectionFlag(s.sh_flags as u64))?;
                    let name = String::new();
            
                    let section = $section {
                        name: name,
                        shdr: *s,
                        section_type: section_type,
                        flags: flags,
                        data: data
                    };
            
                    sections.push(section);
                }
            
                let strtab_data = sections
                    .get(hdr.e_shstrndx as usize)
                    .map(|s| s.data);
                if let Some(data) = strtab_data {
                    for s in sections.iter_mut() {
                        let name_bytes = nom_try!(take_until!(&data[s.shdr.sh_name as usize..], b"\x00" as &[u8]));
                        let mut new_name = String::from_utf8(name_bytes.to_vec())?;
                        mem::replace(&mut s.name, new_name);
                    }
                }
            
                let struct_ins = $result {
                    header: hdr,
                    elf_type: FromPrimitive::from_u16(hdr.e_type)
                        .ok_or(RustepErrorKind::ElfType(hdr.e_type as u64))?,
                    sections: sections,
                    segments: segments,
                };
                Ok(Executable::$result(struct_ins))
            }
        }
}

// TODO Refactor this when `Rust`'s contant generic is done.
// I really don't want to write duplicate code, macro is my final option to avoid that.
define_elf_parser!{
    parse_elf32,
    parse_elf_header32,
    parse_elf_section_header32,
    parse_elf_prog_header32,
    ElfSection32,
    ElfSegment32,
    Elf32
}
define_elf_parser!{
    parse_elf64,
    parse_elf_header64,
    parse_elf_section_header64,
    parse_elf_prog_header64,
    ElfSection64,
    ElfSegment64,
    Elf64
}

#[test]
fn test_parse_elf32() {
    use std::{fs::File, io::prelude::*};

    let mut file = File::open("test/test32").unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    
    let result = parse_elf32(&buf).unwrap();
    match result {
        Executable::Elf32(res) => {
            let section = res.sections[1].shdr;
            assert_eq!(section.sh_name, 0x1b);
            assert_eq!(section.sh_type, 1);
            assert_eq!(section.sh_flags, 2);
            assert_eq!(section.sh_addr, 0x154);
            assert_eq!(section.sh_offset, 0x154);
            assert_eq!(section.sh_size, 19);
            assert_eq!(section.sh_link, 0);
            assert_eq!(section.sh_info, 0);
            assert_eq!(section.sh_addralign, 1);
            assert_eq!(section.sh_entsize, 0);

            let segment = res.segments[0].phdr;
            assert_eq!(segment.p_type, 6);
            assert_eq!(segment.p_offset, 0x34);
            assert_eq!(segment.p_vaddr, 0x34);
            assert_eq!(segment.p_paddr, 0x34);
            assert_eq!(segment.p_filesz, 288);
            assert_eq!(segment.p_memsz, 288);
            assert_eq!(segment.p_flags, 5);
            assert_eq!(segment.p_align, 4);
        },
        _ => panic!("Wrong file format detection"),
    };
}

#[test]
fn test_parse_elf() {
    use std::{fs::File, io::prelude::*};

    let mut file = File::open("test/test").unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    
    let result = parse_elf(&buf).unwrap();
    match result {
        Executable::Elf64(res) => {
            let section = res.sections[1].shdr;
            assert_eq!(section.sh_name, 0x1b);
            assert_eq!(section.sh_type, 1);
            assert_eq!(section.sh_flags, 2);
            assert_eq!(section.sh_addr, 0x238);
            assert_eq!(section.sh_offset, 0x238);
            assert_eq!(section.sh_size, 28);
            assert_eq!(section.sh_link, 0);
            assert_eq!(section.sh_info, 0);
            assert_eq!(section.sh_addralign, 1);
            assert_eq!(section.sh_entsize, 0);

            let segment = res.segments[0].phdr;
            assert_eq!(segment.p_type, 6);
            assert_eq!(segment.p_offset, 0x40);
            assert_eq!(segment.p_vaddr, 0x40);
            assert_eq!(segment.p_paddr, 0x40);
            assert_eq!(segment.p_filesz, 504);
            assert_eq!(segment.p_memsz, 504);
            assert_eq!(segment.p_flags, 5);
            assert_eq!(segment.p_align, 8);

            assert_eq!(res.elf_type, ElfType::ET_DYN);
        },
        _ => panic!("Wrong file format detection"),
    };

    let mut file = File::open("test/test32").unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    
    let result = parse_elf(&buf).unwrap();
    match result {
        Executable::Elf32(res) => {
            let section = res.sections[1].shdr;
            assert_eq!(section.sh_name, 0x1b);
            assert_eq!(section.sh_type, 1);
            assert_eq!(section.sh_flags, 2);
            assert_eq!(section.sh_addr, 0x154);
            assert_eq!(section.sh_offset, 0x154);
            assert_eq!(section.sh_size, 19);
            assert_eq!(section.sh_link, 0);
            assert_eq!(section.sh_info, 0);
            assert_eq!(section.sh_addralign, 1);
            assert_eq!(section.sh_entsize, 0);

            let segment = res.segments[0].phdr;
            assert_eq!(segment.p_type, 6);
            assert_eq!(segment.p_offset, 0x34);
            assert_eq!(segment.p_vaddr, 0x34);
            assert_eq!(segment.p_paddr, 0x34);
            assert_eq!(segment.p_filesz, 288);
            assert_eq!(segment.p_memsz, 288);
            assert_eq!(segment.p_flags, 5);
            assert_eq!(segment.p_align, 4);

            assert_eq!(res.elf_type, ElfType::ET_DYN);
        },
        _ => panic!("Wrong file format detection"),
    };
}

#[test]
fn test_parse_elf64() {
    use std::{fs::File, io::prelude::*};

    let mut file = File::open("test/test").unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    
    let result = parse_elf64(&buf).unwrap();
    match result {
        Executable::Elf64(res) => {
            let section = res.sections[1].shdr;
            assert_eq!(section.sh_name, 0x1b);
            assert_eq!(section.sh_type, 1);
            assert_eq!(section.sh_flags, 2);
            assert_eq!(section.sh_addr, 0x238);
            assert_eq!(section.sh_offset, 0x238);
            assert_eq!(section.sh_size, 28);
            assert_eq!(section.sh_link, 0);
            assert_eq!(section.sh_info, 0);
            assert_eq!(section.sh_addralign, 1);
            assert_eq!(section.sh_entsize, 0);

            let segment = res.segments[0].phdr;
            assert_eq!(segment.p_type, 6);
            assert_eq!(segment.p_offset, 0x40);
            assert_eq!(segment.p_vaddr, 0x40);
            assert_eq!(segment.p_paddr, 0x40);
            assert_eq!(segment.p_filesz, 504);
            assert_eq!(segment.p_memsz, 504);
            assert_eq!(segment.p_flags, 5);
            assert_eq!(segment.p_align, 8);
        },
        _ => panic!("Wrong file format detection"),
    }

}

// parse elf tests
#[test]
fn test_parse_elf_wrong_class() {
    match parse_elf(b"\x7fELF\x05") {
        Err(e) => assert_eq!(
            *e.downcast_ref::<RustepErrorKind>().unwrap(),
            RustepErrorKind::UnsupportedElfClass(5)
        ),
        _ => panic!("parse elf with class 5 succeed, which cannot happen"),
    }
}

// ############### Elf Class ####################

/// Elf class means to differ in arch, we must get that ahead to determine which type to be used.
named!(parse_elf_class<&[u8], u8>,
    do_parse!(
        tag!("\x7fELF") >> // Elf ident
        data: le_u8 >>
        (data)
    )
);

#[test]
fn test_parse_elf_class() {
    // 32 class
    assert_eq!(parse_elf_class(b"\x7fELF\x01"), Done(b"" as &[u8], 1));

    // 64 class
    assert_eq!(parse_elf_class(b"\x7fELF\x02"), Done(b"" as &[u8], 2));

    use nom::ErrorKind;
    // error
    assert_eq!(
        parse_elf_class(b"FLE\x01"),
        Error(error_position!(ErrorKind::Tag, b"FLE\x01" as &[u8]))
    );
}

// ############### Elf Header 32 ################

fn parse_e_ident(input: &[u8]) -> IResult<&[u8], [u8; 16]> {
    let res = take!(input, 16);
    let mut v = [0; 16];
    if let Done(_i, val) = res {
        v.clone_from_slice(val);
        Done(_i, v)
    } else if let Error(e) = res {
        Error(e)
    } else if let Incomplete(need) = res {
        Incomplete(need)
    } else {
        unreachable!()
    }
}

named!(parse_elf_header32<&[u8], Elf32_Ehdr>,
    do_parse!(
        e_ident: parse_e_ident >>
        e_type: le_u16 >>
        e_machine: le_u16 >>
        e_version: le_u32 >>
        e_entry: le_u32 >>
        e_phoff: le_u32 >>
        e_shoff: le_u32 >>
        e_flags: le_u32 >>
        e_ehsize: le_u16 >>
        e_phentsize: le_u16 >>
        e_phnum: le_u16 >>
        e_shentsize: le_u16 >>
        e_shnum: le_u16 >>
        e_shstrndx: le_u16 >>
        (Elf32_Ehdr {
            e_ident: e_ident,
            e_type: e_type,
            e_machine: e_machine,
            e_version: e_version,
            e_entry: e_entry,
            e_phoff: e_phoff,
            e_shoff: e_shoff,
            e_flags: e_flags,
            e_ehsize: e_ehsize,
            e_phentsize: e_phentsize,
            e_phnum: e_phnum,
            e_shentsize: e_shentsize,
            e_shnum: e_shnum,
            e_shstrndx: e_shstrndx
        })
    )
);

#[test]
fn test_parse_elf_header32() {
    use std::{fs::File, io::prelude::*};

    let file = File::open("test/test32").unwrap();
    let mut buf = [0; 0x34];
    let mut handle = file.take(0x34);
    handle.read(&mut buf).unwrap();
    let res = parse_elf_header32(&buf);

    if let Done(_, hdr) = res {
        // These test values are parsed by 010 editor, and regarded trustable

        // \x7fELF id test
        assert_eq!(hdr.e_ident[0], 0x7fu8);
        assert_eq!(hdr.e_ident[1], 0x45u8);
        assert_eq!(hdr.e_ident[2], 0x4cu8);
        assert_eq!(hdr.e_ident[3], 0x46u8);

        // ET_DYN = 3
        assert_eq!(hdr.e_type, 3);

        // EM_386 = 3
        assert_eq!(hdr.e_machine, 3);

        // EV_CURRENT = 1
        assert_eq!(hdr.e_version, 1);

        assert_eq!(hdr.e_entry, 0x3e0);
        assert_eq!(hdr.e_phoff, 52);
        assert_eq!(hdr.e_shoff, 7372);
        assert_eq!(hdr.e_flags, 0);
        assert_eq!(hdr.e_ehsize, 52);
        assert_eq!(hdr.e_phentsize, 32);
        assert_eq!(hdr.e_phnum, 9);
        assert_eq!(hdr.e_shentsize, 40);
        assert_eq!(hdr.e_shnum, 31);
        assert_eq!(hdr.e_shstrndx, 30);
    } else if let Error(err) = res {
        panic!(err.to_string());
    } else if let Incomplete(need) = res {
        match need {
            Size(size) => panic!("Incomplete, needs size {}", size),
            Unknown => panic!("Incomplete, needs size unknown"),
        }
    } else {
        unreachable!();
    }
}

// ############### Elf Header 64 ################

named!(parse_elf_header64<&[u8], Elf64_Ehdr>,
    do_parse!(
        e_ident: parse_e_ident >>
        e_type: le_u16 >>
        e_machine: le_u16 >>
        e_version: le_u32 >>
        e_entry: le_u64 >>
        e_phoff: le_u64 >>
        e_shoff: le_u64 >>
        e_flags: le_u32 >>
        e_ehsize: le_u16 >>
        e_phentsize: le_u16 >>
        e_phnum: le_u16 >>
        e_shentsize: le_u16 >>
        e_shnum: le_u16 >>
        e_shstrndx: le_u16 >>
        (Elf64_Ehdr {
            e_ident: e_ident,
            e_type: e_type,
            e_machine: e_machine,
            e_version: e_version,
            e_entry: e_entry,
            e_phoff: e_phoff,
            e_shoff: e_shoff,
            e_flags: e_flags,
            e_ehsize: e_ehsize,
            e_phentsize: e_phentsize,
            e_phnum: e_phnum,
            e_shentsize: e_shentsize,
            e_shnum: e_shnum,
            e_shstrndx: e_shstrndx
        })
    )
);

#[test]
fn test_parse_elf_header64() {
    use std::{fs::File, io::prelude::*};

    let file = File::open("test/test").unwrap();
    let mut buf = [0; 0x40];
    let mut handle = file.take(0x40);
    handle.read(&mut buf).unwrap();
    let res = parse_elf_header64(&buf);

    if let Done(_i, hdr) = res {
        assert_eq!(hdr.e_ident[0], 0x7f);
        assert_eq!(hdr.e_ident[1], 0x45);
        assert_eq!(hdr.e_ident[2], 0x4c);
        assert_eq!(hdr.e_ident[3], 0x46);

        // ET_DYN = 3
        assert_eq!(hdr.e_type, 3);

        // EM_X86_64 = 62
        assert_eq!(hdr.e_machine, 62);

        // EV_CURRENT = 1
        assert_eq!(hdr.e_version, 1);

        assert_eq!(hdr.e_entry, 0x540);
        assert_eq!(hdr.e_phoff, 64);
        assert_eq!(hdr.e_shoff, 7744);
        assert_eq!(hdr.e_flags, 0);
        assert_eq!(hdr.e_ehsize, 64);
        assert_eq!(hdr.e_phentsize, 56);
        assert_eq!(hdr.e_phnum, 9);
        assert_eq!(hdr.e_shentsize, 64);
        assert_eq!(hdr.e_shnum, 30);
        assert_eq!(hdr.e_shstrndx, 29);
    } else if let Error(err) = res {
        panic!(err.to_string());
    } else if let Incomplete(need) = res {
        match need {
            Size(size) => {
                panic!("incomplete, needs size {}", size);
            }
            Unknown => {
                panic!("incomplete file, needs size unknown");
            }
        }
    } else {
        unreachable!();
    }
}

// ############### Elf Program Header 32 ################

/// Parses a single elf program table, 32-bit version
named!(parse_elf_prog_header32<&[u8], Elf32_Phdr>,
    do_parse!(
        p_type: le_u32 >>
        p_offset: le_u32 >>
        p_vaddr: le_u32 >>
        p_paddr: le_u32 >>
        p_filesz: le_u32 >>
        p_memsz: le_u32 >>
        p_flags: le_u32 >>
        p_align: le_u32 >>
        (Elf32_Phdr {
            p_type: p_type,
            p_offset: p_offset,
            p_vaddr: p_vaddr,
            p_paddr: p_paddr,
            p_filesz: p_filesz,
            p_memsz: p_memsz,
            p_flags: p_flags,
            p_align: p_align
        })
    )
);

// ############### Elf Program Header 64 ################
named!(parse_elf_prog_header64<&[u8], Elf64_Phdr>,
    do_parse!(
        p_type: le_u32 >>
        p_flags: le_u32 >>
        p_offset: le_u64 >>
        p_vaddr: le_u64 >>
        p_paddr: le_u64 >>
        p_filesz: le_u64 >>
        p_memsz: le_u64 >>
        p_align: le_u64 >>
        (Elf64_Phdr {
            p_type: p_type,
            p_flags: p_flags,
            p_offset: p_offset,
            p_vaddr: p_vaddr,
            p_paddr: p_paddr,
            p_filesz: p_filesz,
            p_memsz: p_memsz,
            p_align: p_align,
        })
    )
);

// ############### Elf Section Header 32 ################
named!(parse_elf_section_header32<&[u8], Elf32_Shdr>,
    do_parse!(
        sh_name: le_u32 >>
        sh_type: le_u32 >>
        sh_flags: le_u32 >>
        sh_addr: le_u32 >>
        sh_offset: le_u32 >>
        sh_size: le_u32 >>
        sh_link: le_u32 >>
        sh_info: le_u32 >>
        sh_addralign: le_u32 >>
        sh_entsize: le_u32 >>
        (Elf32_Shdr {
            sh_name: sh_name,
            sh_type: sh_type,
            sh_flags: sh_flags,
            sh_addr: sh_addr,
            sh_offset: sh_offset,
            sh_size: sh_size,
            sh_link: sh_link,
            sh_info: sh_info,
            sh_addralign: sh_addralign,
            sh_entsize: sh_entsize
        })
    )
);

// ############### Elf Section Header 64 ################
named!(parse_elf_section_header64<&[u8], Elf64_Shdr>,
    do_parse!(
        sh_name: le_u32 >>
        sh_type: le_u32 >>
        sh_flags: le_u64 >>
        sh_addr: le_u64 >>
        sh_offset: le_u64 >>
        sh_size: le_u64 >>
        sh_link: le_u32 >>
        sh_info: le_u32 >>
        sh_addralign: le_u64 >>
        sh_entsize: le_u64 >>
        (Elf64_Shdr {
            sh_name: sh_name,
            sh_type: sh_type,
            sh_flags: sh_flags,
            sh_addr: sh_addr,
            sh_offset: sh_offset,
            sh_size: sh_size,
            sh_link: sh_link,
            sh_info: sh_info,
            sh_addralign: sh_addralign,
            sh_entsize: sh_entsize
        })
    )
);
