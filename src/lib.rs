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
pub mod parser;
pub mod format;
pub mod structure;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
