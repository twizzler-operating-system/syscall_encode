use std::{marker::PhantomData, mem::MaybeUninit};

pub mod abi;
pub mod api;
pub mod table;
#[derive(Debug)]
pub struct SyscallArgs<T: SyscallRegister, const NR_REGS: usize> {
    pub registers: [T; NR_REGS],
    pub extra_data: Option<*mut u8>,
}

pub trait SyscallRegister: Copy {
    const BITS: usize;
    type Ty;
    fn zero() -> Self;
    fn fill(&self, mem: &mut [u8]);
    fn from_stack_bytes(mem: &[u8]) -> Self;
}

impl SyscallRegister for u64 {
    const BITS: usize = 64;
    type Ty = Self;
    fn zero() -> Self {
        0
    }

    fn fill(&self, mem: &mut [u8]) {
        let bytes = self.to_ne_bytes();
        mem.split_at_mut(8).0.copy_from_slice(&bytes)
    }

    fn from_stack_bytes(mem: &[u8]) -> Self {
        let bytes = [
            mem[0], mem[1], mem[2], mem[3], mem[4], mem[5], mem[6], mem[7],
        ];
        Self::from_ne_bytes(bytes)
    }
}

pub trait SyscallArguments<const BITS: usize, const NR_REGS: usize> {
    type RegisterType: SyscallRegister + Default + Copy;
    fn encode(&self, encoder: &mut SyscallEncoder<Self::RegisterType, BITS, NR_REGS>);
    fn decode(
        decoder: &mut SyscallDecoder<Self::RegisterType, BITS, NR_REGS>,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized;
    unsafe fn with<R, F: FnOnce(Self::RegisterType, Self) -> R>(
        num: Self::RegisterType,
        args: SyscallArgs<Self::RegisterType, NR_REGS>,
        call: F,
    ) -> Result<R, DecodeError>
    where
        Self: Sized,
    {
        let mut decoder = SyscallDecoder::new(args);
        let me = Self::decode(&mut decoder)?;
        Ok((call)(num, me))
    }
}

#[derive(Debug)]
pub enum DecodeError {
    InvalidData,
    InvalidNum,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
#[repr(transparent)]
pub struct UserPointer<'a, T>(*mut u8, PhantomData<&'a T>);

impl<'a, T> From<&'a T> for UserPointer<'a, T> {
    fn from(value: &'a T) -> Self {
        Self(value as *const _ as *const u8 as *mut u8, PhantomData)
    }
}

impl<T: SyscallRegister + Copy, const BITS: usize, const NR_REGS: usize> Default
    for SyscallEncoder<T, BITS, NR_REGS>
{
    fn default() -> Self {
        Self {
            idx: Default::default(),
            _pd: Default::default(),
            max: 0,
            used: 0,
            args: SyscallArgs {
                registers: [T::zero(); NR_REGS],
                extra_data: None,
            },
        }
    }
}

pub struct SyscallEncoder<T: SyscallRegister, const BITS: usize, const NR_REGS: usize> {
    idx: usize,
    args: SyscallArgs<T, NR_REGS>,
    max: usize,
    used: usize,
    _pd: core::marker::PhantomData<T>,
}

impl<T: SyscallRegister + Copy, const BITS: usize, const NR_REGS: usize>
    SyscallEncoder<T, BITS, NR_REGS>
{
    fn push_primitive(&mut self, item: impl Into<T>) {
        if self.idx == NR_REGS - 1 {
            // Out of registers, push to stack
            let stack = self
                .args
                .extra_data
                .expect("tried to push register to stack, but no stack space was allocated");
            let s = unsafe {
                // TODO: bounds checking
                core::slice::from_raw_parts_mut(stack.add(self.used), self.max - self.used)
            };
            let reg: T = item.into();
            reg.fill(s);
            self.used += core::mem::size_of::<T>();
        } else {
            self.args.registers[self.idx] = item.into();
            self.idx += 1;
        }
    }

    fn new(alloc: &mut [MaybeUninit<u8>]) -> Self {
        Self {
            args: SyscallArgs {
                registers: [T::zero(); NR_REGS],
                extra_data: Some(alloc as *mut _ as *mut u8),
            },
            max: alloc.len(),
            ..Default::default()
        }
    }

    pub fn encode_with<Item: SyscallArguments<BITS, NR_REGS, RegisterType = T>, R>(
        item: Item,
        f: impl FnOnce(SyscallArgs<T, NR_REGS>) -> R,
    ) -> R {
        let size = core::mem::size_of::<Item>();
        alloca::with_alloca(size, |alloc| {
            let mut encoder = Self::new(alloc);
            encoder.size_hint(size);
            item.encode(&mut encoder);
            let args = encoder.finish();
            let res = f(args);
            res
        })
    }

    pub fn size_hint(&self, _size: usize) {}

    pub fn finish(self) -> SyscallArgs<T, NR_REGS> {
        self.args
    }

    pub const fn bits(&self) -> usize {
        BITS
    }

    pub const fn nr_regs(&self) -> usize {
        NR_REGS
    }
}

pub struct SyscallDecoder<T: SyscallRegister, const BITS: usize, const NR_REGS: usize> {
    args: SyscallArgs<T, NR_REGS>,
    idx: usize,
    used: usize,
    _pd: core::marker::PhantomData<T>,
}

impl<T: SyscallRegister, const BITS: usize, const NR_REGS: usize> SyscallDecoder<T, BITS, NR_REGS> {
    pub fn new(args: SyscallArgs<T, NR_REGS>) -> Self {
        Self {
            args,
            idx: 0,
            used: 0,
            _pd: std::marker::PhantomData,
        }
    }

    fn extract_primitive<Item: TryFrom<T>>(&mut self) -> Result<Item, DecodeError>
    where
        T: Copy,
    {
        let reg = if self.idx == NR_REGS - 1 {
            // Grab from the stack

            let stack = self
                .args
                .extra_data
                .expect("tried to push register to stack, but no stack space was allocated");
            let reg_size = core::mem::size_of::<T>();
            let s = unsafe {
                // TODO: bounds checking
                core::slice::from_raw_parts(stack.add(self.used), reg_size)
            };
            let reg = T::from_stack_bytes(s);
            self.used += core::mem::size_of::<T>();
            reg
        } else {
            let reg = self.args.registers[self.idx];
            self.idx += 1;
            reg
        };

        reg.try_into().map_err(|_| DecodeError::InvalidData)
    }
}

/*
impl<const NR_REGS: usize> SyscallArguments<64, NR_REGS> for u32 {
    type RegisterType = u64;

    fn encode(&self, encoder: &mut SyscallEncoder<Self::RegisterType, 64, NR_REGS>) {
        encoder.push_primitive(*self)
    }

    fn decode(
        decoder: &mut SyscallDecoder<Self::RegisterType, 64, NR_REGS>,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        decoder.extract_primitive()
    }
}

impl<const NR_REGS: usize> SyscallArguments<64, NR_REGS> for u64 {
    type RegisterType = u64;

    fn encode(&self, encoder: &mut SyscallEncoder<Self::RegisterType, 64, NR_REGS>) {
        encoder.push_primitive(*self)
    }

    fn decode(
        decoder: &mut SyscallDecoder<Self::RegisterType, 64, NR_REGS>,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        decoder.extract_primitive()
    }
}
*/

trait ShouldAuto {}

impl ShouldAuto for u128 {}
impl ShouldAuto for u64 {}
impl ShouldAuto for u32 {}
impl ShouldAuto for u16 {}
impl ShouldAuto for u8 {}

impl<T: Copy, const BITS: usize, const NR_REGS: usize> SyscallArguments<BITS, NR_REGS> for T
where
    T: Into<u64>,
    T: TryFrom<u64>,
    T: ShouldAuto,
{
    type RegisterType = u64;

    fn encode(&self, encoder: &mut SyscallEncoder<Self::RegisterType, BITS, NR_REGS>) {
        encoder.push_primitive(*self)
    }

    fn decode(
        decoder: &mut SyscallDecoder<Self::RegisterType, BITS, NR_REGS>,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        decoder.extract_primitive()
    }
}

impl<'a, T, const BITS: usize, const NR_REGS: usize> SyscallArguments<BITS, NR_REGS>
    for UserPointer<'a, T>
{
    type RegisterType = u64;

    fn encode(&self, encoder: &mut SyscallEncoder<Self::RegisterType, BITS, NR_REGS>) {
        let x: Self::RegisterType = self.0 as Self::RegisterType;
        encoder.push_primitive(x)
    }

    fn decode(
        decoder: &mut SyscallDecoder<Self::RegisterType, BITS, NR_REGS>,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let x: Self::RegisterType = decoder.extract_primitive()?;
        Ok(Self(x as *mut u8, PhantomData))
    }
}

impl<const BITS: usize, const NR_REGS: usize> SyscallArguments<BITS, NR_REGS> for bool {
    type RegisterType = u64;

    fn encode(&self, encoder: &mut SyscallEncoder<Self::RegisterType, BITS, NR_REGS>) {
        let item: u8 = (*self).into();
        encoder.push_primitive(item)
    }

    fn decode(
        decoder: &mut SyscallDecoder<Self::RegisterType, BITS, NR_REGS>,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let item = u8::decode(decoder)?;
        match item {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::InvalidData),
        }
    }
}

impl<T, const BITS: usize, const NR_REGS: usize> SyscallArguments<BITS, NR_REGS> for Option<T>
where
    T: SyscallArguments<BITS, NR_REGS, RegisterType = u64>,
{
    type RegisterType = u64;

    fn encode(&self, encoder: &mut SyscallEncoder<Self::RegisterType, BITS, NR_REGS>) {
        if let Some(t) = self {
            encoder.push_primitive(true);
            t.encode(encoder);
        } else {
            encoder.push_primitive(false);
        }
    }

    fn decode(
        decoder: &mut SyscallDecoder<Self::RegisterType, BITS, NR_REGS>,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let flag = bool::decode(decoder)?;
        if flag {
            let t = T::decode(decoder)?;
            Ok(Some(t))
        } else {
            Ok(None)
        }
    }
}
