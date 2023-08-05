use std::marker::PhantomData;

use crate::{
    decoder::{DecodeError, SyscallDecoder},
    encoder::{EncodeError, EncodePrimitive, SyscallEncoder},
};

use super::{Allocation, SyscallAbi};

pub struct RegistersAndStackEncoder<'a, Abi: SyscallAbi, const NR_REGS: usize> {
    abi: &'a Abi,
    idx: usize,
    regs: RegisterAndStackData<Abi::Primitive, NR_REGS>,
}

impl<'a, Abi: SyscallAbi, const NR_REGS: usize> RegistersAndStackEncoder<'a, Abi, NR_REGS> {}

impl<'a, Abi: SyscallAbi, const NR_REGS: usize>
    SyscallEncoder<'a, Abi, RegisterAndStackData<Abi::Primitive, NR_REGS>>
    for RegistersAndStackEncoder<'a, Abi, NR_REGS>
{
    fn new(abi: &'a Abi) -> Self {
        Self {
            abi,
            regs: RegisterAndStackData::default(),
            idx: 0,
        }
    }

    fn encode<
        Source: crate::api::SyscallEncodable<Abi, RegisterAndStackData<Abi::Primitive, NR_REGS>>,
    >(
        &mut self,
        item: Source,
        alloc: &Allocation,
    ) -> Result<(), EncodeError> {
        item.encode(self, alloc)
    }

    fn encode_primitive<Item: TryInto<Abi::Primitive>>(
        &mut self,
        item: Item,
        alloc: &Allocation,
    ) -> Result<(), EncodeError> {
        self.regs.regs[self.idx] = item.try_into().map_err(|_| EncodeError::PrimitiveError)?;
        self.idx += 1;
        Ok(())
    }

    fn finish(self) -> RegisterAndStackData<Abi::Primitive, NR_REGS> {
        self.regs
    }
}

pub struct RegistersAndStackDecoder<'a, Abi: SyscallAbi, const NR_REGS: usize> {
    abi: &'a Abi,
    encoded: RegisterAndStackData<Abi::Primitive, NR_REGS>,
    idx: usize,
}

impl<'a, Abi: SyscallAbi, const NR_REGS: usize>
    SyscallDecoder<'a, Abi, RegisterAndStackData<Abi::Primitive, NR_REGS>>
    for RegistersAndStackDecoder<'a, Abi, NR_REGS>
{
    fn new(abi: &'a Abi, data: RegisterAndStackData<Abi::Primitive, NR_REGS>) -> Self {
        Self {
            abi,
            encoded: data,
            idx: 0,
        }
    }

    fn decode<
        Target: crate::api::SyscallEncodable<Abi, RegisterAndStackData<Abi::Primitive, NR_REGS>>,
    >(
        &mut self,
        item: RegisterAndStackData<Abi::Primitive, NR_REGS>,
    ) -> Result<Target, crate::decoder::DecodeError> {
        Target::decode(self)
    }

    fn decode_primitive<Item: Copy + TryFrom<<Abi as SyscallAbi>::Primitive>>(
        &mut self,
    ) -> Result<Item, crate::decoder::DecodeError> {
        let data = self.encoded.regs[self.idx];
        self.idx += 1;
        data.try_into().map_err(|_| DecodeError::InvalidData)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RegisterAndStackData<RegisterType: Copy + Default, const NR_REGS: usize> {
    regs: [RegisterType; NR_REGS],
}

impl<'a, RegisterType: Copy + Default, const NR_REGS: usize>
    RegisterAndStackData<RegisterType, NR_REGS>
{
    pub fn encode_primitive<Abi: SyscallAbi, Item: Into<RegisterType>>(
        &mut self,
        encoder: &mut RegistersAndStackEncoder<'a, Abi, NR_REGS>,
        item: Item,
        alloc: &Allocation,
    ) -> Result<(), EncodeError> {
        todo!()
        // self.regs[encoder.idx] = item.into();
        // encoder.idx += 1;
        // Ok(())
    }
}

impl<R: Copy + Default, const NR_REGS: usize> Default for RegisterAndStackData<R, NR_REGS> {
    fn default() -> Self {
        Self {
            regs: [R::default(); NR_REGS],
        }
    }
}
