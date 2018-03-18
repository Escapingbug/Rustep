use std::{
    fmt,
    fmt::Display,
};

use failure::{
    Context,
    Fail,
    Backtrace,
};

#[derive(Debug)]
pub struct RustepError {
    inner: Context<RustepErrorKind>
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum RustepErrorKind {
    #[fail(display = "Unsupported ELF class value {}", _0)]
    UnsupportedElfClass(u8),
    #[fail(display = "Parsing error")]
    Parse,
    #[fail(display = "Not enough byte, {} bytes needed", _0)]
    Incomplete(usize),
    #[fail(display = "Not enough byte, unknown bytes needed")]
    IncompleteUnknown,
    #[fail(display = "Segment type {} not resolved", _0)]
    SegmentType(u64),
    #[fail(display = "Section type {} not resolved", _0)]
    SectionType(u64),
    #[fail(display = "Segment flag {} invalid", _0)]
    SegmentFlag(u64),
    #[fail(display = "Section flag {} invalid", _0)]
    SectionFlag(u64),
}

impl Fail for RustepError {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for RustepError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl RustepError {
    pub fn kind(&self) -> RustepErrorKind {
        *self.inner.get_context()
    }
}

impl From<RustepErrorKind> for RustepError {
    fn from(kind: RustepErrorKind) -> RustepError {
        RustepError { inner: Context::new(kind) }
    }
}

impl From<Context<RustepErrorKind>> for RustepError {
    fn from(inner: Context<RustepErrorKind>) -> RustepError {
        RustepError { inner: inner }
    }
}

/// Crate `Failure` has not supported `nom`, or `nom` not supported `Failure`.
/// To avoid to do error handling manually, this macro is used to emulate the try method to be
/// better to use along with `Failure`.
///
/// # Examples
/// ```
/// use nom::*;
/// 
/// let res = tag!(b"abc", "bcd"); // Here will be an IResult returned from nom.
/// let res_err = nom_try!(res); // This is almost like `res?`, it will return early
/// let res = tag!(b"abc", "abc"); // This will be accepted
/// let res_noerr = nom_try!(res); // The Done part of nom will be extracted
/// ```
macro_rules! nom_try {

    ($arg:expr) => {
        match $arg {
            Done(_i, res) => {
                res
            },
            Error(e) => {
                Err(format_err!("Parse Error {}", e.to_string()).context(RustepErrorKind::Parse))?
            },
            Incomplete(needed) => {
                match needed {
                    Size(s) => Err(RustepErrorKind::Incomplete(s))?,
                    Unknown => Err(RustepErrorKind::IncompleteUnknown)?,
                }
            }
        }
    }
}
