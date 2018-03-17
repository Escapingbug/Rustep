//! Definition of overall elf file format and Reexports bindings as low level implementation 
//! of elf file format for it has a complete header already described the file format 
//! structure overall.

pub use format::bindings::*;
use enumflags::BitFlags;

#[derive(FromPrimitive, ToPrimitive, Eq, PartialEq)]
pub enum SegmentType {
    PT_NULL = 0,
    PT_LOAD = 1,
    PT_DYNAMIC = 2,
    PT_INTERP = 3,
    PT_NOTE = 4,
    PT_SHLIB = 5,
    PT_PHDR = 6,
    PT_TLS = 7,
    PT_NUM = 8,
    PT_LOOS = 1610612736,
    PT_GNU_EH_FRAME = 1685382480,
    PT_GNU_STACK = 1685382481,
    PT_GNU_RELRO = 1685382482,
    PT_LOSUNW = 1879048186,
    //PT_SUNWBSS = 1879048186,
    PT_SUNWSTACK = 1879048187,
    PT_HISUNW = 1879048191,
    //PT_HIOS = 1879048191,
    PT_LOPROC = 1879048192,
    PT_HIPROC = 2147483647,
}

#[derive(EnumFlags, Copy, Clone, Debug)]
#[repr(u64)]
pub enum SegmentFlag {
    PF_X = 1,
    PF_W = 2,
    PF_R = 4,
    PF_MASKOS = 267386880,
    PF_MASKPROC = 4026531840,
}

#[derive(FromPrimitive, ToPrimitive, Eq, PartialEq)]
pub enum SectionType {
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
     SHT_INIT_ARRAY = 14,
     SHT_FINI_ARRAY = 15,
     SHT_PREINIT_ARRAY = 16,
     SHT_GROUP = 17,
     SHT_SYMTAB_SHNDX = 18,
     SHT_NUM = 19,
     SHT_LOOS = 1610612736,
     SHT_GNU_ATTRIBUTES = 1879048181,
     SHT_GNU_HASH = 1879048182,
     SHT_GNU_LIBLIST = 1879048183,
     SHT_CHECKSUM = 1879048184,
     SHT_LOSUNW = 1879048186,
     //SHT_SUNW_move = 1879048186,
     SHT_SUNW_COMDAT = 1879048187,
     SHT_SUNW_syminfo = 1879048188,
     SHT_GNU_verdef = 1879048189,
     SHT_GNU_verneed = 1879048190,
     SHT_GNU_versym = 1879048191,
     //SHT_HISUNW = 1879048191,
     //SHT_HIOS = 1879048191,
     SHT_LOPROC = 1879048192,
     SHT_HIPROC = 2147483647,
     SHT_LOUSER = 2147483648,
     SHT_HIUSER = 2415919103,
}

#[derive(EnumFlags, Copy, Clone, Debug)]
#[repr(u64)]
pub enum SectionFlag {
     SHF_WRITE = 1,
     SHF_ALLOC = 2,
     SHF_EXECINSTR = 4,
     SHF_MERGE = 16,
     SHF_STRINGS = 32,
     SHF_INFO_LINK = 64,
     SHF_LINK_ORDER = 128,
     SHF_OS_NONCONFORMING = 256,
     SHF_GROUP = 512,
     SHF_TLS = 1024,
     SHF_COMPRESSED = 2048,
     SHF_MASKOS = 267386880,
     //SHF_MASKPROC = 4026531840,
     //SHF_ORDERED = 1073741824,
     //SHF_EXCLUDE = 2147483648,
}

pub struct ElfSection32<'a> {
    pub shdr: Elf32_Shdr,
    pub section_type: SectionType,
    pub flags: BitFlags<SectionFlag>,
    pub name: String,
    pub data: &'a [u8]
}

pub struct ElfSection64<'a> {
    pub shdr: Elf64_Shdr,
    pub section_type: SectionType,
    pub flags: BitFlags<SectionFlag>,
    pub name: String,
    pub data: &'a [u8],
}

pub struct ElfSegment32<'a> {
    pub phdr: Elf32_Phdr,
    pub segment_type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub data: &'a [u8],
}

pub struct ElfSegment64<'a> {
    pub phdr: Elf64_Phdr,
    pub segment_type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub data: &'a [u8],
}

/// Elf file format 32-bit version
pub struct Elf32<'a> {
    pub header: Elf32_Ehdr,
    pub segments: Vec<ElfSegment32<'a>>,
    pub sections: Vec<ElfSection32<'a>>,
}


/// Elf file format 64-bit version
pub struct Elf64<'a> {
    pub header: Elf64_Ehdr,
    pub segments: Vec<ElfSegment64<'a>>,
    pub sections: Vec<ElfSection64<'a>>,
}
