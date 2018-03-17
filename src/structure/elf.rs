//! Definition of overall elf file format and Reexports bindings as low level implementation 
//! of elf file format for it has a complete header already described the file format 
//! structure overall.

pub use structure::bindings::*;

/// Elf struct representation, 32-bit version. Currently `Rust` has not supported constant generics.
/// This would be better use that feature. But for now, we can only split this in 
/// two versions, one for 64-bit, and one for 32-bit.
pub struct ElfStruct32 {
    pub header: elf32_hdr,
    pub program_headers: Vec<elf32_phdr>,
    pub section_headers: Vec<elf32_shdr>,
}


/// Elf struct representation, 64-bit version. Currently `Rust` has not supported constant generics.
/// This would be better use that feature. But for now, we can only split this in 
/// two versions, one for 64-bit, and one for 32-bit.
pub struct ElfStruct64 {
    pub header: elf64_hdr,
    pub program_headers: Vec<elf64_phdr>,
    pub section_headers: Vec<elf64_shdr>,
}

/// Two types allowed to represent ELF format. Wrap them around using an enum to pass the type
/// system which may prevent us from returning two possible types.
pub enum ElfStruct {
    Struct32(ElfStruct32),
    Struct64(ElfStruct64),
}
