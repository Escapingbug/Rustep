//! Rustep stands for Rust Execution Parser, it is what we need to parse the executable file
//! format such as linux's `ELF` file format, Windows's `PE` file format or OSX's `Macho` format.
//!
//! Current only `ELF` file format is supported.
//! This crate constructs a higher level representation of file format for you, all the information
//! needed is in the corresponding struct.
//!
//! # Examples
//! ```
//! use std::fs::File;
//! use std::io::prelude::*;
//! use rustep::format::executable::Executable;
//!
//! let mut file = File::open("test/test").unwrap();
//! let mut buf = Vec::new();
//! file.read_to_end(&mut buf).unwrap();
//!
//! let res = Executable::from_u8_array(&buf).unwrap(); // This should be a Executable::Elf64
//! // You can match it to get the internal structure
//! match res {
//!     Executable::Elf64(elf) => {}, // Do something with the elf
//!     _ => { panic!("Wrong file format detected") },
//! }
//! ```
//!
//! After that, you got a `elf`, which is the `Elf64` struct. All higher level information can be
//! extracted from that struct. 32 bit version is almost the same. Please refer to `Elf64` or
//! `Elf32` struct documentation for what information you can get from the `ELF` file.

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
