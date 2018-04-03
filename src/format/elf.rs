//! Definition of overall elf file format and Reexports bindings as low level implementation 
//! of elf file format for it has a complete header already described the file format 
//! structure overall.
use format::bindings::*;
use std::{
    mem,
    convert::{
        TryFrom,
        TryInto,
    },
};
use nom::{IResult, IResult::*, Needed::{Size, Unknown}, *};
use failure::Error;
use error::RustepErrorKind;
use format::executable::Executable;
use num::FromPrimitive;
use enumflags::BitFlags;

/// Elf types, refer to `ELF`'s `e_type`
#[derive(FromPrimitive, ToPrimitive, Eq, PartialEq, Clone, Copy, Debug)]
pub enum ElfType {
     ET_REL = 1,
     ET_EXEC = 2,
     ET_DYN = 3,
     ET_CORE = 4,
     ET_NUM = 5,
     ET_LOOS = 65024,
     ET_HIOS = 65279,
     ET_LOPROC = 65280,
     ET_HIPROC = 65535,
}

/// Elf segment type, refer to `segment`'s `p_type`
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

/// Elf segment's flag. Refer to `segment`'s `p_flags`
#[derive(EnumFlags, Copy, Clone, Debug)]
#[repr(u64)]
pub enum SegmentFlag {
    PF_X = 1,
    PF_W = 2,
    PF_R = 4,
    PF_MASKOS = 267386880,
    PF_MASKPROC = 4026531840,
}

/// Elf section's type referring to `section`'s `sh_type`
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

/// Elf section's type referring to `section`'s `sh_flags`
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

/// A trait representing the supported methods for a extracted section header.
/// This is used as universal interface for ElfXX_Shdr, since those are generated from C header,
/// some methods are useful when using those ignoring the 32 or 64 part.
pub trait ElfSectionHeader {
    fn address(&self) -> u64;
    fn offset(&self) -> u64;
    fn size(&self) -> u64;
    fn entry_size(&self) -> u64;
}

impl ElfSectionHeader for Elf32_Shdr {
    fn address(&self) -> u64 {
        self.sh_addr as u64
    }

    fn offset(&self) -> u64 {
        self.sh_offset as u64
    }

    fn size(&self) -> u64 {
        self.sh_size as u64
    }
    
    fn entry_size(&self) -> u64 {
        self.sh_entsize as u64
    }
}

impl ElfSectionHeader for Elf64_Shdr {
    fn address(&self) -> u64 {
        self.sh_addr
    }

    fn offset(&self) -> u64 {
        self.sh_offset
    }

    fn size(&self) -> u64 {
        self.sh_size
    }

    fn entry_size(&self) -> u64 {
        self.sh_entsize
    }
}

/// A trait to provide all functions supported by ElfSectionXX structure representation.
/// Dynamic dispatch is used to provide only function usages, thus 32-bit and 64-bit can be used
/// alike.
pub trait ElfSection {
    /// Internal shdr representation of this section. Note that since dynamic dispatch is used,
    /// this method mostly just provide the functionalities, not the full struct.
    fn shdr(&self) -> &ElfSectionHeader;
    /// Name of this section.
    fn name(&self) -> &str;
    /// Type of this section
    fn section_type(&self) -> &SectionType;
    /// Flags of this section
    fn flags(&self) -> BitFlags<SectionFlag>;
    /// Data of this section
    fn data(&self) -> &[u8];
}

/// 32-bit Elf Section representation
pub struct ElfSection32<'a> {
    /// Internal Shdr. If you only need the functionality provided, just use the getter.
    shdr: Elf32_Shdr,
    section_type: SectionType,
    flags: BitFlags<SectionFlag>,
    name: String,
    data: &'a [u8],
}

/// 64-bit ElfSection representation
pub struct ElfSection64<'a> {
    /// Internal Shdr. If you only need the functionality provided, just use the getter.
    shdr: Elf64_Shdr,
    section_type: SectionType,
    flags: BitFlags<SectionFlag>,
    name: String,
    data: &'a [u8],
}

impl<'a> ElfSection for ElfSection32<'a> {
    fn shdr(&self) -> &ElfSectionHeader {
        &self.shdr
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn section_type(&self) -> &SectionType {
        &self.section_type
    }

    fn flags(&self) -> BitFlags<SectionFlag> {
        self.flags
    }

    fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> ElfSection for ElfSection64<'a> {
    fn shdr(&self) -> &ElfSectionHeader {
        &self.shdr
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn section_type(&self) -> &SectionType {
        &self.section_type
    }

    fn flags(&self) -> BitFlags<SectionFlag> {
        self.flags
    }

    fn data(&self) -> &[u8] {
        self.data
    }
}

/// A trait representing the supported methods for a extracted program header.
/// This is used as universal interface for ElfXX_Phdr, since those are generated from C header,
/// some methods are useful when using those ignoring the 32 or 64 part.
pub trait ElfSegmentHeader {
    fn offset(&self) -> u64;
    fn vaddr(&self) -> u64;
    fn paddr(&self) -> u64;
    fn file_size(&self) -> u64;
    fn mem_size(&self) -> u64;
}

impl ElfSegmentHeader for Elf32_Phdr {
    fn offset(&self) -> u64 {
        self.p_offset as u64
    }

    fn vaddr(&self) -> u64 {
        self.p_vaddr as u64
    }

    fn paddr(&self) -> u64 {
        self.p_paddr as u64
    }

    fn file_size(&self) -> u64 {
        self.p_filesz as u64
    }

    fn mem_size(&self) -> u64 {
        self.p_memsz as u64
    }
}

impl ElfSegmentHeader for Elf64_Phdr {
    fn offset(&self) -> u64 {
        self.p_offset
    }

    fn vaddr(&self) -> u64 {
        self.p_vaddr
    }

    fn paddr(&self) -> u64 {
        self.p_paddr
    }

    fn file_size(&self) -> u64 {
        self.p_filesz
    }

    fn mem_size(&self) -> u64 {
        self.p_memsz
    }
}

/// providing universal functionality of `Elf` segment
pub trait ElfSegment {
    /// internal phdr access, note that this method only provide functionalities, since it
    /// uses dynamic dispatch.
    fn phdr(&self) -> &ElfSegmentHeader;
    /// Type of this segment.
    fn segment_type(&self) -> &SegmentType;
    /// Flags of this segment
    fn flags(&self) -> BitFlags<SegmentFlag>;
    /// Data of this segment
    fn data(&self) -> &[u8];
}

/// 32-bit version Elf Segment representation.
pub struct ElfSegment32<'a> {
    /// Internal phdr of the segment, full struct
    phdr: Elf32_Phdr,
    segment_type: SegmentType,
    flags: BitFlags<SegmentFlag>,
    data: &'a [u8],
}

/// 64-bit version Elf Segment representation
pub struct ElfSegment64<'a> {
    /// Internal phdr of the segment, full struct
    phdr: Elf64_Phdr,
    segment_type: SegmentType,
    flags: BitFlags<SegmentFlag>,
    data: &'a [u8],
}

impl<'a> ElfSegment for ElfSegment32<'a> {
    fn phdr(&self) -> &ElfSegmentHeader {
        &self.phdr
    }

    fn segment_type(&self) -> &SegmentType {
        &self.segment_type
    }

    fn flags(&self) -> BitFlags<SegmentFlag> {
        self.flags
    }

    fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> ElfSegment for ElfSegment64<'a> {
    fn phdr(&self) -> &ElfSegmentHeader {
        &self.phdr
    }

    fn segment_type(&self) -> &SegmentType {
        &self.segment_type
    }

    fn flags(&self) -> BitFlags<SegmentFlag> {
        self.flags
    }

    fn data(&self) -> &[u8] {
        self.data
    }
}

/// Elf machine type, referring to `e_machine` in `ELF` header
#[derive(FromPrimitive, ToPrimitive, Eq, PartialEq)]
#[repr(u64)]
pub enum ElfMachine {
    /// Nomachine
    NONE = 0,
    /// AT&T WE32100
    M32 = 1,
    /// SPARC
    SPARC = 2,
    /// Intel80386
    I386 = 3,
    /// Motorola68000
    M68K = 4,
    /// Motorola88000
    M88K = 5,
    /// Intel80860
    I860 = 7,
    /// MIPS IArchitecture
    MIPS = 8,
    /// IBM System/370Processor
    S370 = 9,
    /// MIPS RS3000Little-endian
    MIPS_RS3_LE = 10,
    /// Hewlett-PackardPA-RISC
    PARISC = 15,
    /// FujitsuVPP500
    VPP500 = 17,
    /// Enhanced instruction setSPARC
    SPARC32PLUS = 18,
    /// Intel80960
    I960 = 19,
    /// PowerPC
    PPC = 20,
    /// 64-bitPowerPC
    PPC64 = 21,
    /// IBM System/390Processor
    S390 = 22,
    /// NECV800
    V800 = 36,
    /// FujitsuFR20
    FR20 = 37,
    /// TRWRH-32
    RH32 = 38,
    /// MotorolaRCE
    RCE = 39,
    /// Advanced RISC MachinesARM
    ARM = 40,
    /// DigitalAlpha
    ALPHA = 41,
    /// HitachiSH
    SH = 42,
    /// SPARC Version9
    SPARCV9 = 43,
    /// Siemens TriCore embeddedprocessor
    TRICORE = 44,
    /// Argonaut RISC Core, Argonaut TechnologiesInc.
    ARC = 45,
    /// HitachiH8/300
    H8_300 = 46,
    /// HitachiH8/300H
    H8_300H = 47,
    /// HitachiH8S
    H8S = 48,
    /// HitachiH8/500
    H8_500 = 49,
    /// Intel IA-64 processorarchitecture
    IA_64 = 50,
    /// StanfordMIPS-X
    MIPS_X = 51,
    /// MotorolaColdFire
    COLDFIRE = 52,
    /// MotorolaM68HC12
    M68HC12 = 53,
    /// Fujitsu MMA MultimediaAccelerator
    MMA = 54,
    /// SiemensPCP
    PCP = 55,
    /// Sony nCPU embedded RISCprocessor
    NCPU = 56,
    /// Denso NDR1microprocessor
    NDR1 = 57,
    /// Motorola Star*Coreprocessor
    STARCORE = 58,
    /// Toyota ME16processor
    ME16 = 59,
    /// STMicroelectronics ST100processor
    ST100 = 60,
    /// Advanced Logic Corp. TinyJ embedded processorfamily
    TINYJ = 61,
    /// AMD x86-64architecture
    X86_64 = 62,
    /// Sony DSPProcessor
    PDSP = 63,
    /// Digital Equipment Corp.PDP-10
    PDP10 = 64,
    /// Digital Equipment Corp.PDP-11
    PDP11 = 65,
    /// Siemens FX66microcontroller
    FX66 = 66,
    /// STMicroelectronics ST9+ 8/16 bitmicrocontroller
    ST9PLUS = 67,
    /// STMicroelectronics ST7 8-bitmicrocontroller
    ST7 = 68,
    /// Motorola MC68HC16Microcontroller
    M68HC16 = 69,
    /// Motorola MC68HC11Microcontroller
    M68HC11 = 70,
    /// Motorola MC68HC08Microcontroller
    M68HC08 = 71,
    /// Motorola MC68HC05Microcontroller
    M68HC05 = 72,
    /// Silicon GraphicsSVx
    SVX = 73,
    /// STMicroelectronics ST19 8-bitmicrocontroller
    ST19 = 74,
    /// DigitalVAX
    VAX = 75,
    /// Axis Communications 32-bit embeddedprocessor
    CRIS = 76,
    /// Infineon Technologies 32-bit embeddedprocessor
    JAVELIN = 77,
    /// Element 14 64-bit DSPProcessor
    FIREPATH = 78,
    /// LSI Logic 16-bit DSPProcessor
    ZSP = 79,
    /// Donald Knuth's educational 64-bitprocessor
    MMIX = 80,
    /// Harvard University machine-independent objectfiles
    HUANY = 81,
    /// SiTeraPrism
    PRISM = 82,
    /// Atmel AVR 8-bitmicrocontroller
    AVR = 83,
    /// FujitsuFR30
    FR30 = 84,
    /// MitsubishiD10V
    D10V = 85,
    /// MitsubishiD30V
    D30V = 86,
    /// NECv850
    V850 = 87,
    /// MitsubishiM32R
    M32R = 88,
    /// MatsushitaMN10300
    MN10300 = 89,
    /// MatsushitaMN10200
    MN10200 = 90,
    /// picoJava
    PJ = 91,
    /// OpenRISC 32-bit embeddedprocessor
    OPENRISC = 92,
    /// ARC CoresTangent-A5
    ARC_A5 = 93,
    /// Tensilica XtensaArchitecture
    XTENSA = 94,
    /// Alphamosaic VideoCoreprocessor
    VIDEOCORE = 95,
    /// Thompson Multimedia General PurposeProcessor
    TMM_GPP = 96,
    /// National Semiconductor 32000series
    NS32K = 97,
    /// Tenor Network TPCprocessor
    TPC = 98,
    /// Trebia SNP 1000processor
    SNP1K = 99,
    /// STMicroelectronics (www.st.com) ST200microcontroller
    ST200 = 100,
    /// Ubicom IP2xxx microcontrollerfamily
    IP2K = 101,
    /// MAXProcessor
    MAX = 102,
    /// National Semiconductor CompactRISCmicroprocessor
    CR = 103,
    /// FujitsuF2MC16
    F2MC16 = 104,
    /// Texas Instruments embedded microcontrollermsp430
    MSP430 = 105,
    /// Analog Devices Blackfin (DSP)processor
    BLACKFIN = 106,
    /// S1C33 Family of Seiko Epsonprocessors
    SE_C33 = 107,
    /// Sharp embeddedmicroprocessor
    SEP = 108,
    /// Arca RISCMicroprocessor
    ARCA = 109,
    /// Microprocessor series from PKU-Unity Ltd. and MPRC of PekingUniversity
    UNICORE = 110,
}

/// Information provided by Elf header is provided by functions of this trait.
pub trait ElfHeader {
    /// Elf File type
    fn elf_type(&self) -> Result<ElfType, Error>;
    /// Elf machine
    fn machine(&self) -> Result<ElfMachine, Error>;
    /// Entry point
    fn entry(&self) -> u64;
    /// Program header offset
    fn phoff(&self) -> u64;
    /// Section header offset
    fn shoff(&self) -> u64;
    fn ehsize(&self) -> u64;
    /// program header entry size
    fn phentsize(&self) -> u64;
    /// program header number
    fn phnum(&self) -> u64;
    /// section header entry size
    fn shentsize(&self) -> u64;
    /// section header number
    fn shnum(&self) -> u64;
    /// section header of string table index
    fn shstrndx(&self) -> u64;
}

impl ElfHeader for Elf32_Ehdr {
    fn elf_type(&self) -> Result<ElfType, Error> {
        Ok(FromPrimitive::from_u16(self.e_type)
            .ok_or(RustepErrorKind::ElfType(self.e_type as u64))?)
    }

    fn machine(&self) -> Result<ElfMachine, Error> {
        Ok(FromPrimitive::from_u16(self.e_machine)
            .ok_or(RustepErrorKind::ElfMachine(self.e_machine as u64))?)
    }

    fn entry(&self) -> u64 {
        self.e_entry as u64
    }

    fn phoff(&self) -> u64 {
        self.e_phoff as u64
    }

    fn shoff(&self) -> u64 {
        self.e_shoff as u64
    }

    fn ehsize(&self) -> u64 {
        self.e_ehsize as u64
    }

    fn phentsize(&self) -> u64 {
        self.e_phentsize as u64
    }

    fn phnum(&self) -> u64 {
        self.e_phnum as u64
    }

    fn shentsize(&self) -> u64 {
        self.e_shentsize as u64
    }

    fn shnum(&self) -> u64 {
        self.e_shnum as u64
    }

    fn shstrndx(&self) -> u64 {
        self.e_shstrndx as u64
    }
}

impl ElfHeader for Elf64_Ehdr {
    fn elf_type(&self) -> Result<ElfType, Error> {
        Ok(FromPrimitive::from_u16(self.e_type)
            .ok_or(RustepErrorKind::ElfType(self.e_type as u64))?)
    }

    fn machine(&self) -> Result<ElfMachine, Error> {
        Ok(FromPrimitive::from_u16(self.e_machine)
            .ok_or(RustepErrorKind::ElfMachine(self.e_machine as u64))?)
    }

    fn entry(&self) -> u64 {
        self.e_entry as u64
    }

    fn phoff(&self) -> u64 {
        self.e_phoff as u64
    }

   fn shoff(&self) -> u64 {
       self.e_shoff as u64
    }

   fn ehsize(&self) -> u64 {
       self.e_ehsize as u64
   }

   fn phentsize(&self) -> u64 {
       self.e_phentsize as u64
   }

   fn phnum(&self) -> u64 {
       self.e_phnum as u64
   }

   fn shentsize(&self) -> u64 {
       self.e_shentsize as u64
   }

   fn shnum(&self) -> u64 {
       self.e_shnum as u64
   }

   fn shstrndx(&self) -> u64 {
       self.e_shstrndx as u64
   }
}

/// A trait representing the supported methods for a parsed ELF format.
/// This is used as universal interface for Elf file format, some methods are useful when using
/// those ignoring the 32 or 64 part. The information provided by `ELF` header can be extracted 
/// from the `ElfHeader` trait object which can be gained from `header()` method. 
///
pub trait ElfFormat {
    /// Get trait object of header
    fn header(&self) -> &ElfHeader;
    /// all segments trait objects
    fn segments(&self) -> Vec<&ElfSegment>;
    /// all sections trait objects
    fn sections(&self) -> Vec<&ElfSection>;
    /// get some specific section with a given name
    fn section(&self, name: &str) -> Option<&ElfSection> {
        for sec in self.sections().iter() {
            if sec.name() == name {
                return Some(*sec)
            }
        }

        None
    }
}

/// Elf file format 32-bit version
pub struct Elf32<'a> {
    header: Elf32_Ehdr,
    elf_type: ElfType,
    segments: Vec<ElfSegment32<'a>>,
    sections: Vec<ElfSection32<'a>>,
}


/// Elf file format 64-bit version
pub struct Elf64<'a> {
    header: Elf64_Ehdr,
    elf_type: ElfType,
    segments: Vec<ElfSegment64<'a>>,
    sections: Vec<ElfSection64<'a>>,
}

impl<'a> ElfFormat for Elf32<'a> {
    fn header(&self) -> &ElfHeader {
        &self.header
    }

    fn segments(&self) -> Vec<&ElfSegment> {
        let mut v = Vec::new();
        for elem in self.segments.iter() {
            v.push(elem as &ElfSegment);
        }

        v
    }

    fn sections(&self) -> Vec<&ElfSection> {
        let mut v = Vec::new();
        for elem in self.sections.iter() {
            v.push(elem as &ElfSection);
        }

        v
    }
}

impl<'a> ElfFormat for Elf64<'a> {
    fn header(&self) -> &ElfHeader {
        &self.header
    }

    fn segments(&self) -> Vec<&ElfSegment> {
        let mut v = Vec::new();
        for elem in self.segments.iter() {
            v.push(elem as &ElfSegment);
        }

        v
    }

    fn sections(&self) -> Vec<&ElfSection> {
        let mut v = Vec::new();
        for elem in self.sections.iter() {
            v.push(elem as &ElfSection);
        }

        v
    }
}

impl<'a> TryFrom<&'a Executable<'a>> for &'a ElfFormat {
    type Error=Error;

    /// Tries to convert an [`Executable`](../executable/enum.Executable.html) reference to an
    /// [`ElfFormat` trait object](../elf/trait.ElfFormat.html)
    fn try_from(value: &'a Executable) -> Result<&'a ElfFormat, Error> {
        match *value {
            Executable::Elf32(ref elf) => Ok(elf as &ElfFormat),
            Executable::Elf64(ref elf) => Ok(elf as &ElfFormat),
            _ => Err(RustepErrorKind::NotElf)?,
        }
    } 
}

/// parses input byes to executable
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
    {
        let res: &ElfFormat = (&result).try_into().expect("unable to convert");
        assert_eq!(res.header().elf_type().unwrap(), ElfType::ET_DYN);
    }
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
    {
        let res: &ElfFormat = (&result).try_into().expect("unable to convert");
        assert_eq!(res.header().elf_type().unwrap(), ElfType::ET_DYN);
    }
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
    {
        let res: &ElfFormat = (&result).try_into().expect("unable to convert");
        assert_eq!(res.header().elf_type().unwrap(), ElfType::ET_DYN);
    }
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
