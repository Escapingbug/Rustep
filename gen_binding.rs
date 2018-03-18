//! Since we already have some reuseable code(which is from linux source tree), we'd like to 
//! use those to get a overall representation instead of use a hand written one which may be
//! error prone. This uses [rust-bindgen][1] to make the binding from C header file we can 
//! find that describes the overall structure of some format.
//!
//! [1]: https://github.com/rust-lang-nursery/rust-bindgen

extern crate bindgen;

use std::path::{
    PathBuf,
    Path,
};

fn main() {

    println!("cargo:rerun-if-changed=elf.h");
    
    if Path::new("src/format/bindings.rs").exists() == false {
        let bindings = bindgen::Builder::default()
            // This `wrapper.h` is used as input. Since multiple file may be used, we use a wrapper
            // to solve this problem.
            .header("elf.h")
            .generate()
            .expect("Unable to generate bindings");
    
        let out_path = PathBuf::from("src/format/");
        bindings.write_to_file(out_path.join("bindings.rs"))
            .expect("Unable to write generated bindings to bindings.rs");
    }
}
