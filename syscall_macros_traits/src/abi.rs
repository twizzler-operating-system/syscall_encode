use core::alloc::Layout;
use std::{default, ptr::null_mut};

use crate::{encoder::SyscallEncoder, error::SyscallError};

pub mod registers_and_stack;

pub enum AllocationError {
    OutOfMemory,
}

pub trait SyscallAbi: Sized {
    type SyscallArgType: Copy;
    type SyscallRetType: Copy;
    type SyscallNumType: Copy;
    type ArgEncoder<'a>: SyscallEncoder<'a, Self, Self::SyscallArgType>
    where
        Self: 'a;
    type RetEncoder<'a>: SyscallEncoder<'a, Self, Self::SyscallRetType>
    where
        Self: 'a;

    fn with_alloc<F, R, E: Copy>(&self, layout: Layout, f: F) -> Result<R, SyscallError<E>>
    where
        F: FnOnce(Allocation) -> Result<R, SyscallError<E>>;

    fn kernel_alloc(&self, layout: Layout) -> Allocation;

    fn arg_encoder<'a>(&'a self, alloc: Allocation) -> Self::ArgEncoder<'a> {
        Self::ArgEncoder::new_encode(self, alloc)
    }

    fn arg_decoder<'a>(&'a self, data: Self::SyscallArgType) -> Self::ArgEncoder<'a> {
        Self::ArgEncoder::new_decode(self, data)
    }

    fn ret_encoder<'a>(&'a self, alloc: Allocation) -> Self::RetEncoder<'a> {
        Self::RetEncoder::new_encode(self, alloc)
    }

    fn ret_decoder<'a>(&'a self, data: Self::SyscallRetType) -> Self::RetEncoder<'a> {
        Self::RetEncoder::new_decode(self, data)
    }

    fn syscall_impl(
        &self,
        num: Self::SyscallNumType,
        args: Self::SyscallArgType,
    ) -> Self::SyscallRetType;
}

pub trait AbiRegister: Copy {}

impl AbiRegister for u64 {}

pub struct Allocation {
    data: *mut u8,
    size: usize,
}

impl Allocation {
    pub fn null() -> Self {
        Self {
            data: null_mut(),
            size: 0,
        }
    }
}

impl From<&mut [u8]> for Allocation {
    fn from(value: &mut [u8]) -> Self {
        Self {
            data: value.as_mut_ptr(),
            size: value.len(),
        }
    }
}
