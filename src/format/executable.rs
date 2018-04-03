//! The overall entry point of the crate. Defines the
//! [`Executable`](executable/enum.Executable.html) enum to provide functionalities of
//! parsing various file format.

use failure::Error;
use format::elf::{
    Elf32,
    Elf64,
    parse_elf,
};
use nom::{
    *,
    Needed::*,
    IResult::*,
};
use error::RustepErrorKind;
use num::FromPrimitive;

/// A list of all supported file formats, and the parsed structure within. This is the main
/// interface of `rustep`.
pub enum Executable<'a> {
    Elf32(Elf32<'a>),
    Elf64(Elf64<'a>),
}

#[derive(FromPrimitive, ToPrimitive, Eq, PartialEq)]
enum ExecutableFormat {
    Elf = 0x464c457f,
    Pe = 0x4550,
    Mach32 = 0xfeedface,
    Mach64 = 0xfeedfacf,
}

impl<'a> Executable<'a> {
    /// Parse a executable file using a u8 array. This is the main interface of `rustep`.
    /// # Examples
    /// ```
    /// #![feature(try_from)]
    /// use std::fs::File;
    /// use std::io::prelude::*;
    /// use std::convert::TryInto;
    /// use std::convert::TryFrom;
    /// use rustep::format::executable::Executable;
    /// use rustep::format::elf::ElfType;
    /// use rustep::format::elf::ElfFormat;
    ///
    /// let mut file = File::open("test/test").unwrap();
    /// let mut buf = Vec::new();
    /// file.read_to_end(&mut buf).unwrap();
    ///
    /// let res = Executable::from_u8_array(&buf).unwrap(); // This should be a Executable::Elf64
    /// // You can match it to get the internal structure
    /// match res {
    ///     Executable::Elf64(elf) => { println!("This is elf64"); }, // Do something with the elf
    ///     _ => { panic!("Wrong file format detected"); },
    /// }
    ///
    /// // You can also use the trait object methods to get the universal interface among parsed
    /// // formats.
    /// let res = Executable::from_u8_array(&buf).unwrap();
    /// // Now we actually do not know what type is the executable, how ever we can guess that it
    /// // is an `ELF`
    /// let res: &ElfFormat = (&res).try_into().expect("Not elf"); // The `Result` type can tell 
    /// // us if it is really an `ELF`
    /// assert_eq!(res.header().elf_type().unwrap(), ElfType::ET_DYN);
    ///
    /// ```
    pub fn from_u8_array(input: &'a [u8]) -> Result<Executable<'a>, Error> {
        println!("{:?}", nom_try!(
            alt!(input, tag!("\x7fELF") | tag!("PE\x00\x00")))
        );
        // File format detection
        let res = nom_try!(
            call!(input, le_u32)
        ); 
        // It is safe to use `unwrap()` here, as this should panic when the conversion is wrong.
        // This denotes the internal bug instead of user fault usage since the signature file
        // should always be possible to be converted, and the not enough situation is covered
        // in nom parse part.
        let format: ExecutableFormat = FromPrimitive::from_u32(res).unwrap();

        match format {
            ExecutableFormat::Elf => parse_elf(input),
            _ => panic!("File format other than ELF is not yet supported"),
        }
    }

}

#[test]
fn test_executable() {
    use std::{
        fs::File,
        io::prelude::*,
    };

    let mut file = File::open("test/test").unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    match Executable::from_u8_array(&buf).unwrap() {
        Executable::Elf64(_elf) => {},
        _ => { panic!("Wrong file format detection") }
    }
}
