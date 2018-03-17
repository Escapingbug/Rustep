use format::elf::{
    Elf32,
    Elf64,
};

pub enum Executable<'a> {
    Elf32(Elf32<'a>),
    Elf64(Elf64<'a>),
}
