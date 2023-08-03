use std::{convert::Infallible, num::TryFromIntError};

#[derive(Debug)]
pub struct SyscallArgs<T: SyscallRegister, const NR_REGS: usize> {
    pub registers: [T; NR_REGS],
    pub extra_data: Option<*mut u8>,
}

pub trait SyscallRegister {
    fn zero() -> Self;
}

impl SyscallRegister for u64 {
    fn zero() -> Self {
        Self::default()
    }
}

pub trait SyscallArguments<const BITS: usize, const NR_REGS: usize> {
    type RegisterType: SyscallRegister;
    fn encode(&self, encoder: &mut SyscallEncoder<Self::RegisterType, BITS, NR_REGS>);
    fn decode(
        decoder: &mut SyscallDecoder<Self::RegisterType, BITS, NR_REGS>,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized;
}

#[derive(Debug)]
pub enum DecodeError {
    Infallible,
    TryFromIntError(core::num::TryFromIntError),
}

impl From<TryFromIntError> for DecodeError {
    fn from(value: TryFromIntError) -> Self {
        Self::TryFromIntError(value)
    }
}

impl From<Infallible> for DecodeError {
    fn from(_: Infallible) -> Self {
        Self::Infallible
    }
}

#[derive(Debug)]
pub struct UserPointer(*mut u8);

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
        <Item as TryFrom<T>>::Error: Into<DecodeError>,
    {
        let reg = self.args.registers[self.idx];
        self.idx += 1;
        reg.try_into().map_err(|e: Item::Error| e.into())
    }
}

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
