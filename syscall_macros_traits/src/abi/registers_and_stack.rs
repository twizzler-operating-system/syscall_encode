use std::marker::PhantomData;

use crate::{
    api::SyscallEncodable,
    encoder::{DecodeError, EncodeError, EncodePrimitive, SyscallEncoder},
    error::SyscallError,
};

use super::{Allocation, SyscallAbi};

pub struct RegistersAndStackEncoder<
    'a,
    Abi: SyscallAbi,
    RegisterType: Copy + Default,
    const NR_REGS: usize,
> {
    abi: &'a Abi,
    idx: usize,
    regs: RegisterAndStackData<RegisterType, NR_REGS>,
}

impl<'a, Abi: SyscallAbi, RegisterType: Copy + Default, const NR_REGS: usize>
    SyscallEncoder<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>>
    for RegistersAndStackEncoder<'a, Abi, RegisterType, NR_REGS>
where
    RegisterType: From<u8>,
    RegisterType: TryInto<u8>,
{
    fn new(abi: &'a Abi, data: Option<RegisterAndStackData<RegisterType, NR_REGS>>) -> Self {
        Self {
            abi,
            regs: data.unwrap_or_default(),
            idx: 0,
        }
    }

    fn encode<
        Source: SyscallEncodable<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, Self>,
    >(
        &mut self,
        item: &Source,
        alloc: &Allocation,
    ) -> Result<(), EncodeError> {
        item.encode(self, alloc)
    }

    fn finish(self) -> RegisterAndStackData<RegisterType, NR_REGS> {
        self.regs
    }

    fn decode<
        Target: SyscallEncodable<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, Self>,
    >(
        &mut self,
    ) -> Result<Target, crate::encoder::DecodeError>
    where
        Self: Sized,
    {
        Target::decode(self)
    }

    fn encode_u8(&mut self, item: u8, alloc: &Allocation) -> Result<(), EncodeError>
    where
        Self: Sized,
    {
        self.regs.regs[self.idx] = item.into();
        self.idx += 1;
        Ok(())
    }

    fn decode_u8(&mut self) -> Result<u8, DecodeError>
    where
        Self: Sized,
    {
        let p = self.regs.regs[self.idx]
            .try_into()
            .map_err(|_| DecodeError::InvalidData)?;
        self.idx += 1;
        Ok(p)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RegisterAndStackData<RegisterType: Copy + Default, const NR_REGS: usize> {
    regs: [RegisterType; NR_REGS],
}

impl<R: Copy + Default, const NR_REGS: usize> Default for RegisterAndStackData<R, NR_REGS> {
    fn default() -> Self {
        Self {
            regs: [R::default(); NR_REGS],
        }
    }
}

impl<'a, Abi: SyscallAbi, RegisterType: Copy + Default, const NR_REGS: usize, Primitive: Copy>
    EncodePrimitive<'a, Abi, RegisterAndStackData<RegisterType, NR_REGS>, Primitive>
    for RegistersAndStackEncoder<'a, Abi, RegisterType, NR_REGS>
where
    Primitive: TryInto<RegisterType>,
    Primitive: TryFrom<RegisterType>,
    RegisterType: From<u8>,
    RegisterType: TryInto<u8>,
{
    fn encode_primitive(&mut self, item: Primitive, alloc: &Allocation) -> Result<(), EncodeError> {
        self.regs.regs[self.idx] = item.try_into().map_err(|_| EncodeError::PrimitiveError)?;
        self.idx += 1;
        Ok(())
    }

    fn decode_primitive(&mut self) -> Result<Primitive, crate::encoder::DecodeError> {
        let p = <Primitive as TryFrom<RegisterType>>::try_from(self.regs.regs[self.idx]);
        let p: Primitive = p.map_err(|_| DecodeError::InvalidData)?;
        self.idx += 1;
        Ok(p)
    }
}
