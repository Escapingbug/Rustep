//! Rustep stands for Rust Execution Parser, it is what we need to parse the executable file
//! format such as linux's `ELF` file format, Windows's `PE` file format or OSX's `Macho` format.
//!
//! Current only `ELF` file format is supported.
//! This crate constructs a higher level representation of file format for you, all the information
//! needed is in the corresponding struct.
//!
//! # Examples
//! ```
//! #![feature(try_from)]
//! use std::fs::File;
//! use std::io::prelude::*;
//! use std::convert::TryInto;
//! use std::convert::TryFrom;
//! use rustep::format::executable::Executable;
//! use rustep::format::elf::ElfType;
//! use rustep::format::elf::ElfFormat;
//!
//! let mut file = File::open("test/test").unwrap();
//! let mut buf = Vec::new();
//! file.read_to_end(&mut buf).unwrap();
//!
//! let res = Executable::from_u8_array(&buf).unwrap(); // This should be a Executable::Elf64
//! // You can match it to get the internal structure
//! match res {
//!     Executable::Elf64(elf) => { println!("This is elf64"); }, // Do something with the elf
//!     _ => { panic!("Wrong file format detected"); },
//! }
//!
//! // You can also use the trait object methods to get the universal interface among parsed
//! // formats.
//! let res = Executable::from_u8_array(&buf).unwrap();
//! // Now we actually do not know what type is the executable, how ever we can guess that it
//! // is an `ELF`
//! let res: &ElfFormat = (&res).try_into().expect("Not elf"); // The `Result` type can tell 
//! // us if it is really an `ELF`
//! assert_eq!(res.header().elf_type().unwrap(), ElfType::ET_DYN);
//! ```
//!
//! When use pattern match, after matching you will get a `elf`, which is the `Elf64` struct.
//! All higher level information can be extracted from that struct. 32 bit version is almost
//! the same. Please refer to [`Elf64`](format/elf/struct.Elf64.html) or 
//! [`Elf32`](format/elf/struct.Elf32.html) documentation for what information you can get 
//! from the `ELF` file.
//!
//! When use `try_from` or `try_into` method, you can get a 
//! [`ElfFormat`](format/elf/trait.ElfFormat.html) trait object. Please refer to that doc
//! for more information.
#![feature(try_from)]
#[macro_use]
extern crate nom;

#[macro_use]
extern crate failure;

extern crate enumflags;
#[macro_use]
extern crate enumflags_derive;

extern crate num;
#[macro_use]
extern crate num_derive;

#[macro_use]
pub mod error;
//pub mod parser;
pub mod format;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
