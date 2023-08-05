use core::alloc::Layout;

use crate::{decoder::SyscallDecoder, encoder::SyscallEncoder, error::SyscallError};

pub mod registers_and_stack;

pub enum AllocationError {
    OutOfMemory,
}

pub trait SyscallAbi: Sized {
    type SyscallArgType: Copy;
    type SyscallRetType: Copy;
    type SyscallNumType: Copy;
    type Primitive: Copy + Default;
    type ArgEncoder<'a>: SyscallEncoder<'a, Self, Self::SyscallArgType>
    where
        Self: 'a;
    type ArgDecoder<'a>: SyscallDecoder<'a, Self, Self::SyscallArgType>
    where
        Self: 'a;
    type RetEncoder<'a>: SyscallEncoder<'a, Self, Self::SyscallRetType>
    where
        Self: 'a;
    type RetDecoder<'a>: SyscallDecoder<'a, Self, Self::SyscallRetType>
    where
        Self: 'a;

    fn with_alloc<F, R, E: Copy>(&self, layout: Layout, f: F) -> Result<R, SyscallError<E>>
    where
        F: FnOnce(&Self, Allocation) -> Result<R, SyscallError<E>>;

    fn create_sender_encoder<'a>(&'a self) -> Self::ArgEncoder<'a> {
        Self::ArgEncoder::new(self)
    }

    fn create_sender_decoder<'a>(&'a self, ret: Self::SyscallRetType) -> Self::RetDecoder<'a> {
        Self::RetDecoder::new(self, ret)
    }

    fn create_receiver_pair<'a>(
        &'a self,
        args: Self::SyscallArgType,
    ) -> (Self::ArgDecoder<'a>, Self::RetEncoder<'a>) {
        (
            Self::ArgDecoder::new(self, args),
            Self::RetEncoder::new(self),
        )
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

impl From<&mut [u8]> for Allocation {
    fn from(value: &mut [u8]) -> Self {
        Self {
            data: value.as_mut_ptr(),
            size: value.len(),
        }
    }
}
