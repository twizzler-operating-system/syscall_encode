use core::alloc::Layout;
use core::ptr::null_mut;

use crate::{encoder::SyscallEncoder, error::SyscallError};

pub mod registers_and_stack;

/// Basic ABI information for a syscall system.
pub trait SyscallAbi: Sized {
    /// The type that will be passed to the syscall implementation function as the arguments.
    type SyscallArgType: Copy;
    /// The type that will be returned by the syscall implementation.
    type SyscallRetType: Copy;
    /// The type that will be passed to the syscall implementation function as the number.
    type SyscallNumType: Copy;

    // The type of the argument encoder for this ABI.
    type ArgEncoder<'a>: SyscallEncoder<'a, Self, Self::SyscallArgType>
    where
        Self: 'a;
    // The type of the return value encoder for this ABI.
    type RetEncoder<'a>: SyscallEncoder<'a, Self, Self::SyscallRetType>
    where
        Self: 'a;

    /// Allocate some memory with the supplied layout. The allocation mechanism should issue no syscalls.
    /// The allocated memory is passed to the supplied closure.
    fn with_alloc<F, R, E: Copy>(&self, layout: Layout, f: F) -> Result<R, SyscallError<E>>
    where
        F: FnOnce(Allocation) -> Result<R, SyscallError<E>>;

    /// Allocate some memory as the kernel, for passing back to the application. This can just
    /// return a null Allocation.
    ///
    /// # Safety
    /// The allocation must point to memory that will be valid until the application fully reads and decodes the value.
    unsafe fn kernel_alloc(&self, layout: Layout) -> Allocation;

    /// Create a new encoder for arguments.
    fn arg_encoder(&self, alloc: Allocation) -> Self::ArgEncoder<'_> {
        Self::ArgEncoder::new_encode(self, alloc)
    }

    /// Create a new decoder for arguments.
    fn arg_decoder(&self, data: Self::SyscallArgType) -> Self::ArgEncoder<'_> {
        Self::ArgEncoder::new_decode(self, data)
    }

    /// Create a new encoder for return values.
    fn ret_encoder(&self, alloc: Allocation) -> Self::RetEncoder<'_> {
        Self::RetEncoder::new_encode(self, alloc)
    }

    /// Create a new decoder for return values.
    fn ret_decoder(&self, data: Self::SyscallRetType) -> Self::RetEncoder<'_> {
        Self::RetEncoder::new_decode(self, data)
    }

    /// The raw syscall implementation. This should do little more than just assign the appropriate
    /// registers and issue the appropriate instruction to initiate the trap.
    ///
    /// # Safety
    /// 1. The values of num and args must remain unmodified as they are transferred to the kernel.
    /// 2. The syscall instruction must correctly take the number and arguments, and return the return value.
    unsafe fn syscall_impl(
        &self,
        num: Self::SyscallNumType,
        args: Self::SyscallArgType,
    ) -> Self::SyscallRetType;
}

/// An allocation that was performed for storing encoded values.
pub struct Allocation {
    data: *mut u8,
    size: usize,
    taken: usize,
}

impl Allocation {
    /// Create a new null allocation.
    pub fn null() -> Self {
        Self {
            data: null_mut(),
            size: 0,
            taken: 0,
        }
    }

    /// Allocate some memory.
    pub fn reserve<T: Copy>(&mut self) -> Option<&mut T> {
        if self.is_null() {
            return None;
        }
        let layout = core::alloc::Layout::new::<T>();
        // Safety: we meet the stated requirements of add(), since taken will never exceed size.
        let a_off = unsafe { self.data.add(self.taken) }.align_offset(layout.align());
        if a_off == usize::MAX {
            return None;
        }
        self.taken += a_off;
        if self.taken + layout.size() > self.size {
            return None;
        }
        // Safety: again, taken will never exceed size, nor will taken + layout.size() ever exceed size.
        // The cast is safe as well, since we manually aligned above.
        let res = unsafe { (self.data.add(self.taken) as *mut T).as_mut() };
        self.taken += layout.size();
        res
    }

    /// Is this a null allocation?
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
