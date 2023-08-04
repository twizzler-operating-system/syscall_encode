use std::marker::PhantomData;

#[derive(Debug)]
pub struct SyscallArgs<T: SyscallRegister, const NR_REGS: usize> {
    pub registers: [T; NR_REGS],
    pub extra_data: Option<*mut u8>,
}

pub trait SyscallRegister {
    const BITS: usize;
    type Ty;
    fn zero() -> Self;
}

impl SyscallRegister for u64 {
    const BITS: usize = 64;
    type Ty = Self;
    fn zero() -> Self {
        0
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
}

#[derive(Debug)]
pub enum DecodeError {
    InvalidData,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
#[repr(transparent)]
pub struct UserPointer<'a, T>(*mut u8, PhantomData<&'a T>);

impl<'a, T> From<&'a T> for UserPointer<'a, T> {
    fn from(value: &'a T) -> Self {
        Self(value as *const _ as *const u8 as *mut u8, PhantomData)
    }
}

impl<T: Default + SyscallRegister + Copy, const BITS: usize, const NR_REGS: usize> Default
    for SyscallEncoder<T, BITS, NR_REGS>
{
    fn default() -> Self {
        Self {
            regs: [T::default(); NR_REGS],
            idx: Default::default(),
            _pd: Default::default(),
        }
    }
}

pub struct SyscallEncoder<T: SyscallRegister, const BITS: usize, const NR_REGS: usize> {
    regs: [T; NR_REGS],
    idx: usize,
    _pd: core::marker::PhantomData<T>,
}

impl<T: SyscallRegister, const BITS: usize, const NR_REGS: usize> SyscallEncoder<T, BITS, NR_REGS> {
    fn push_primitive(&mut self, item: impl Into<T>) {
        self.regs[self.idx] = item.into();
        self.idx += 1;
    }

    pub fn finish(self) -> SyscallArgs<T, NR_REGS> {
        SyscallArgs {
            registers: self.regs,
            extra_data: None,
        }
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
    _pd: core::marker::PhantomData<T>,
}

impl<T: SyscallRegister, const BITS: usize, const NR_REGS: usize> SyscallDecoder<T, BITS, NR_REGS> {
    pub fn new(args: SyscallArgs<T, NR_REGS>) -> Self {
        Self {
            args,
            idx: 0,
            _pd: std::marker::PhantomData,
        }
    }

    fn extract_primitive<Item: TryFrom<T>>(&mut self) -> Result<Item, DecodeError>
    where
        T: Copy,
    {
        let reg = self.args.registers[self.idx];
        self.idx += 1;
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
