#![feature(strict_provenance)]
#![no_std]

#[doc(hidden)]
pub extern crate core as _core;

pub mod abi;
pub mod api;
pub mod encoder;
pub mod error;
pub mod ptr;
pub mod table;
