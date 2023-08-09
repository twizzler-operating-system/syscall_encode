use core::marker::PhantomData;

use crate::{abi::SyscallAbi, api::SyscallEncodable, encoder::SyscallEncoder};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A type representing a user pointer.
pub struct UserPointer<'abi, T> {
    raw: usize,
    _pd: PhantomData<&'abi T>,
}

impl<'abi, T> UserPointer<'abi, T> {
    /// Construct a new user pointer.
    pub fn new(ptr: &'abi T) -> Self {
        Self {
            raw: (ptr as *const T).expose_addr(),
            _pd: PhantomData,
        }
    }

    /// Construct a new null user pointer.
    pub fn new_null() -> Self {
        Self {
            raw: 0,
            _pd: PhantomData,
        }
    }

    /// Is this a null user pointer?
    pub fn is_null(&self) -> bool {
        self.raw == 0
    }
}

impl<'abi, T: Sync> UserPointer<'abi, T> {
    /// Verify a user pointer, and return it as a reference.
    /// Should be called by the kernel before using the pointer. The
    /// supplied closure should implement the kernel's security and address space verification for
    /// this pointer. The closure should return true if the contiguous memory region delimited by
    /// the arguments is okay for the kernel to read.
    /// Note that this means the following:
    /// 1. The userspace code has perms to read the memory.
    /// 2. The kernel has perms to read the memory.
    /// 3. The region is in a valid part of the address space.
    /// 4. T is Sync.
    pub fn as_ref(&self, f: impl FnOnce(*const T, usize) -> bool) -> Option<&'abi T> {
        if self.is_null() {
            return None;
        }
        let ptr: *const T = core::ptr::from_exposed_addr(self.raw);
        if f(ptr, core::mem::size_of::<T>()) {
            unsafe { ptr.as_ref() }
        } else {
            None
        }
    }

    /// See [Self::as_ref].
    pub fn as_mut(&mut self, f: impl FnOnce(*mut T, usize) -> bool) -> Option<&'abi mut T> {
        if self.is_null() {
            return None;
        }
        let ptr: *mut T = core::ptr::from_exposed_addr_mut(self.raw);
        if f(ptr, core::mem::size_of::<T>()) {
            unsafe { ptr.as_mut() }
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A type representing a slice of user memory.
pub struct UserSlice<'abi, T> {
    ptr: UserPointer<'abi, T>,
    len: usize,
}

impl<'abi, T> UserSlice<'abi, T> {
    /// Construct a new user slice from a user pointer and length.
    pub fn from_parts(ptr: UserPointer<'abi, T>, len: usize) -> Self {
        Self { ptr, len }
    }

    /// Construct a new user slice.
    pub fn new(slice: &'abi [T]) -> Self {
        let ptr = slice.as_ptr();
        Self {
            ptr: unsafe { ptr.as_ref().unwrap() }.into(),
            len: slice.len(),
        }
    }

    /// Get the length of the slice
    pub fn len(&self) -> usize {
        self.len
    }

    /// Is this slice empty?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<'abi, T: Sync> UserSlice<'abi, T> {
    /// See [UserPointer::as_ref].
    pub fn as_ref(&self, f: impl FnOnce(*const T, usize) -> bool) -> Option<&'abi [T]> {
        let ptr: *const T = core::ptr::from_exposed_addr(self.ptr.raw);
        if ptr.is_null() {
            return None;
        }
        if f(ptr, core::mem::size_of::<T>() * self.len) {
            Some(unsafe { core::slice::from_raw_parts(ptr, self.len) })
        } else {
            None
        }
    }

    /// See [UserPointer::as_ref].
    pub fn as_mut(&mut self, f: impl FnOnce(*mut T, usize) -> bool) -> Option<&'abi mut [T]> {
        let ptr: *mut T = core::ptr::from_exposed_addr_mut(self.ptr.raw);
        if ptr.is_null() {
            return None;
        }
        if f(ptr, core::mem::size_of::<T>() * self.len) {
            Some(unsafe { core::slice::from_raw_parts_mut(ptr, self.len) })
        } else {
            None
        }
    }
}

impl<'abi, T> From<&'abi T> for UserPointer<'abi, T> {
    fn from(value: &'abi T) -> Self {
        Self::new(value)
    }
}

impl<'abi, T> From<&'abi mut T> for UserPointer<'abi, T> {
    fn from(value: &'abi mut T) -> Self {
        Self::new(value)
    }
}

impl<'abi, T> From<&'abi [T]> for UserSlice<'abi, T> {
    fn from(value: &'abi [T]) -> Self {
        Self::new(value)
    }
}

impl<'abi, T> From<&'abi mut [T]> for UserSlice<'abi, T> {
    fn from(value: &'abi mut [T]) -> Self {
        Self::new(value)
    }
}

impl<
        'a,
        Abi: SyscallAbi,
        EncodedType: Copy,
        Encoder: SyscallEncoder<'a, Abi, EncodedType>,
        T: Copy,
    > SyscallEncodable<'a, Abi, EncodedType, Encoder> for UserPointer<'a, T>
{
    fn encode(&self, encoder: &mut Encoder) -> Result<(), crate::encoder::EncodeError> {
        self.raw.encode(encoder)
    }

    fn decode(decoder: &mut Encoder) -> Result<Self, crate::encoder::DecodeError>
    where
        Self: Sized,
    {
        Ok(Self {
            raw: usize::decode(decoder)?,
            _pd: PhantomData,
        })
    }
}

impl<
        'a,
        Abi: SyscallAbi,
        EncodedType: Copy,
        Encoder: SyscallEncoder<'a, Abi, EncodedType>,
        T: Copy,
    > SyscallEncodable<'a, Abi, EncodedType, Encoder> for UserSlice<'a, T>
{
    fn encode(&self, encoder: &mut Encoder) -> Result<(), crate::encoder::EncodeError> {
        self.ptr.encode(encoder)?;
        self.len.encode(encoder)
    }

    fn decode(decoder: &mut Encoder) -> Result<Self, crate::encoder::DecodeError>
    where
        Self: Sized,
    {
        Ok(Self {
            ptr: UserPointer::<'a, T>::decode(decoder)?,
            len: usize::decode(decoder)?,
        })
    }
}
