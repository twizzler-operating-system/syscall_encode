use core::alloc::Layout;
use core::ptr::null_mut;

use crate::{encoder::SyscallEncoder, error::SyscallError};

pub mod registers_and_stack;

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

    unsafe fn syscall_impl(
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
    taken: usize,
}

impl Allocation {
    pub fn null() -> Self {
        Self {
            data: null_mut(),
            size: 0,
            taken: 0,
        }
    }

    pub fn reserve<T>(&mut self) -> Option<&mut T> {
        if self.is_null() {
            return None;
        }
        let layout = core::alloc::Layout::new::<T>();
        let a_off = unsafe { self.data.add(self.taken) }.align_offset(layout.align());
        if a_off == usize::MAX {
            return None;
        }
        self.taken += a_off;
        if self.taken + layout.size() > self.size {
            return None;
        }
        unsafe { (self.data.add(self.taken) as *mut T).as_mut() }
    }

    pub fn is_null(&self) -> bool {
        self.data.is_null()
    }
}

impl From<&mut [u8]> for Allocation {
    fn from(value: &mut [u8]) -> Self {
        Self {
            data: value.as_mut_ptr(),
            size: value.len(),
            taken: 0,
        }
    }
}
