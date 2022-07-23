#![feature(int_log)]
#![feature(int_roundings)]
#![feature(assert_matches)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::upper_case_acronyms)]

pub mod loader;
pub mod protocol;
pub mod scheme;
pub mod util;

#[derive(Clone, Debug)]
pub enum Error {
    InvalidInstances,
    MissingQuery(util::Query),
    MissingChallenge(usize),
    Transcript(std::io::ErrorKind, String),
}
