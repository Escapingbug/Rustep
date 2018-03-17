//! `ELF` is a file format used by linux.

use std::mem;
use structure::elf::{
    elf32_hdr,
    elf64_hdr,
    ElfStruct,
};
use parser::elf_parser::parse_elf;
use failure::Error;
use enumflags::{
    BitFlags,
};
use num::FromPrimitive;
use error::RustepErrorKind;

#[derive(FromPrimitive, ToPrimitive, Eq, PartialEq)]
pub enum ProgramTableType {
    PT_NULL = 0,
    PT_LOAD,
    PT_DYNAMIC,
    PT_INTERP,
    PT_NOTE,
    PT_SHLIB,
    PT_PHDR,
    PT_TLS,
    PT_LOOS = 0x3c3cba00,
    PT_HIOS = 0x6fffffff,
    PT_LOPROC = 0x70000000,
    PT_HIPROC = 0x7fffffff,
    PT_GNU_EH_FRAME = 0x6474e550,
    PT_GNU_STACK = 0x6464e551,
}

#[derive(EnumFlags, Copy, Clone, Debug)]
#[repr(u64)]
pub enum ProgramFlag {
    PF_X = 1,
    PF_W = 2,
    PF_R = 4,
}

#[derive(FromPrimitive, ToPrimitive, Eq, PartialEq)]
pub enum SectionTableType {
     SHT_NULL = 0,
     SHT_PROGBITS = 1,
     SHT_SYMTAB = 2,
     SHT_STRTAB = 3,
     SHT_RELA = 4,
     SHT_HASH = 5,
     SHT_DYNAMIC = 6,
     SHT_NOTE = 7,
     SHT_NOBITS = 8,
     SHT_REL = 9,
     SHT_SHLIB = 10,
     SHT_DYNSYM = 11,
     SHT_NUM = 12,
     SHT_LOPROC = 1879048192,
     SHT_HIPROC = 2147483647,
     SHT_LOUSER = 2147483648,
     SHT_HIUSER = 4294967295,
}

#[derive(EnumFlags, Copy, Clone, Debug)]
#[repr(u64)]
pub enum SectionFlag {
     SHF_WRITE = 1,
     SHF_ALLOC = 2,
     SHF_EXECINSTR = 4,
     SHF_RELA_LIVEPATCH = 1048576,
     SHF_RO_AFTER_INIT = 2097152,
     SHF_MASKPROC = 4026531840,
}

pub struct ElfSection32<'a> {
    pub name: String,
    pub sec_type: SectionTableType,
    pub flags: BitFlags<SectionFlag>,
    pub addr: u32,
    pub offset: u32,
    pub size: u32,
    pub link: u32,
    pub info: u32,
    pub addralign: u32,
    pub entry_size: u32,
    pub data: &'a [u8]
}

pub struct ElfSection64<'a> {
    pub name: String,
    pub sec_type: SectionTableType,
    pub flags: BitFlags<SectionFlag>,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entry_size: u64,
    pub data: &'a [u8]
}

/// 32 bit representation of Elf Segment. The original representation doesn't contain the data part
/// and is exported in the `bindings` which is hard to document.
pub struct ElfSegment32<'a> {
    pub seg_type: ProgramTableType,
    pub flags: BitFlags<ProgramFlag>,
    pub offset: u32,
    pub vaddr: u32,
    pub paddr: u32,
    pub file_size: u32,
    pub mem_size: u32,
    pub align: u32,
    pub data: &'a [u8],
}

/// 64 bit representation of Elf Segment. The original representation doesn't contain the data part
///    and is exported in the `bindings` which is hard to document.
pub struct ElfSegment64<'a> {
    pub seg_type: ProgramTableType,
    pub flags: BitFlags<ProgramFlag>,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub align: u64,
    pub data: &'a [u8]
}

pub struct Elf32<'a> {
    pub header: elf32_hdr,
    pub segments: Vec<ElfSegment32<'a>>,
    pub sections: Vec<ElfSection32<'a>>,
}

pub struct Elf64<'a> {
    pub header: elf64_hdr,
    pub segments: Vec<ElfSegment64<'a>>,
    pub sections: Vec<ElfSection64<'a>>,
}

pub enum Elf<'a> {
    Arch32(Elf32<'a>),
    Arch64(Elf64<'a>),
}

// TODO `Rust` currently has not supported constant generics, beautify it when that work is done.
pub fn from_u8_array(arr: &[u8]) -> Result<Elf, Error> {
    let elf_struct = parse_elf(arr)?;
    match elf_struct {
        ElfStruct::Struct32(s) => {
            let header = s.header;
            let mut progs = Vec::new();
            let mut secs = Vec::new();

            // Reconstructs raw segments and sections representation to higher represention
            for p in s.program_headers.iter() {
                let seg_type = FromPrimitive::from_u32(p.p_type)
                    .ok_or(RustepErrorKind::SegmentType(p.p_type as usize))?;
                let flags = BitFlags::from_bits(p.p_flags as u64)
                    .ok_or(RustepErrorKind::SegmentFlag(p.p_flags as usize))?;
                let offset = p.p_offset;
                let vaddr = p.p_vaddr;
                let paddr = p.p_paddr;
                let file_size = p.p_filesz;
                let mem_size = p.p_memsz;
                let align = p.p_align;
                let data = &arr[offset as usize..(offset+file_size) as usize];

                let new_seg = ElfSegment32 {
                    seg_type: seg_type,
                    flags: flags,
                    offset: offset,
                    vaddr: vaddr,
                    paddr: paddr,
                    file_size: file_size,
                    mem_size: mem_size,
                    align: align,
                    data: data,
                };
                progs.push(new_seg);
            }

            // possible string table data
            let mut strtab = None;
            for s in s.section_headers.iter() {
                // Sections need to resolve names as well, this cannot be done by first loop
                // we need another to determine each names. Names of sections for now are just
                // a empty string to be changed later.
                let name = String::new();
                let sec_type = FromPrimitive::from_u32(s.sh_type)
                    .ok_or(RustepErrorKind::SectionType(s.sh_type as usize))?;
                let flags = BitFlags::from_bits(s.sh_flags as u64)
                    .ok_or(RustepErrorKind::SectionFlag(s.sh_flags as usize))?;
                let addr = s.sh_addr;
                let offset = s.sh_offset;
                let size = s.sh_size;
                let link = s.sh_link;
                let info = s.sh_info;
                let addralign = s.sh_addralign;
                let entry_size = s.sh_entsize;
                let data = &arr[offset as usize..(offset+size) as usize];
                if sec_type == SectionTableType::SHT_STRTAB {
                    strtab = Some(data);
                }

                let new_sec = ElfSection32 {
                    name: name,
                    sec_type: sec_type,
                    flags: flags,
                    addr: addr,
                    offset: offset,
                    size: size,
                    link: link,
                    info: info,
                    addralign: addralign,
                    entry_size: entry_size,
                    data: data,
                };

                secs.push(new_sec);
            }

            // Second loop to find the correct name of each sections
            match strtab {
                Some(data) => {
                    let mut idx = 0;
                    for s in s.section_headers.iter() {
                        let name_idx = s.sh_name as usize;
                        let mut end_idx = 0usize;
                        while data[name_idx] != b'\x00' {
                            end_idx += 1;
                        }
                        let real_name = String::from_utf8(data[name_idx..end_idx].to_vec()).unwrap();
                        mem::replace(&mut secs[idx].name, real_name);
                    }
                },
                // No string table, leaving all names to be empty
                None => {}
            }

            let new_elf = Elf32 {
                header: header,
                sections: secs,
                segments: progs,
            };
            Ok(Elf::Arch32(new_elf))
        },
        ElfStruct::Struct64(s) => {
            let header = s.header;
            let mut progs = Vec::new();
            let mut secs = Vec::new();

            // Reconstructs raw segments and sections representation to higher represention
            for p in s.program_headers.iter() {
                let seg_type = FromPrimitive::from_u32(p.p_type)
                    .ok_or(RustepErrorKind::SegmentType(p.p_type as usize))?;
                let flags = BitFlags::from_bits(p.p_flags as u64)
                    .ok_or(RustepErrorKind::SegmentFlag(p.p_flags as usize))?;
                let offset = p.p_offset;
                let vaddr = p.p_vaddr;
                let paddr = p.p_paddr;
                let file_size = p.p_filesz;
                let mem_size = p.p_memsz;
                let align = p.p_align;
                let data = &arr[offset as usize..(offset+file_size) as usize];

                let new_seg = ElfSegment64 {
                    seg_type: seg_type,
                    flags: flags,
                    offset: offset,
                    vaddr: vaddr,
                    paddr: paddr,
                    file_size: file_size,
                    mem_size: mem_size,
                    align: align,
                    data: data,
                };
                progs.push(new_seg);
            }

            // possible string table data
            let mut strtab = None;
            for s in s.section_headers.iter() {
                // Sections need to resolve names as well, this cannot be done by first loop
                // we need another to determine each names. Names of sections for now are just
                // a empty string to be changed later.
                let name = String::new();
                let sec_type = FromPrimitive::from_u32(s.sh_type)
                    .ok_or(RustepErrorKind::SectionType(s.sh_type as usize))?;
                let flags = BitFlags::from_bits(s.sh_flags as u64)
                    .ok_or(RustepErrorKind::SectionFlag(s.sh_flags as usize))?;
                let addr = s.sh_addr;
                let offset = s.sh_offset;
                let size = s.sh_size;
                let link = s.sh_link;
                let info = s.sh_info;
                let addralign = s.sh_addralign;
                let entry_size = s.sh_entsize;
                let data = &arr[offset as usize..(offset+size) as usize];
                if sec_type == SectionTableType::SHT_STRTAB {
                    strtab = Some(data);
                }

                let new_sec = ElfSection64 {
                    name: name,
                    sec_type: sec_type,
                    flags: flags,
                    addr: addr,
                    offset: offset,
                    size: size,
                    link: link,
                    info: info,
                    addralign: addralign,
                    entry_size: entry_size,
                    data: data,
                };

                secs.push(new_sec);
            }

            // Second loop to find the correct name of each sections
            match strtab {
                Some(data) => {
                    let mut idx = 0;
                    for s in s.section_headers.iter() {
                        let name_idx = s.sh_name as usize;
                        let mut end_idx = 0usize;
                        while data[name_idx] != b'\x00' {
                            end_idx += 1;
                        }
                        let real_name = String::from_utf8(data[name_idx..end_idx].to_vec()).unwrap();
                        mem::replace(&mut secs[idx].name, real_name);
                    }
                },
                // No string table, leaving all names to be empty
                None => {}
            }

            let new_elf = Elf64 {
                header: header,
                sections: secs,
                segments: progs,
            };
            Ok(Elf::Arch64(new_elf))

        }
    }
}
