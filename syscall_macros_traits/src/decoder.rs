use crate::{
    abi::{AllocationError, SyscallAbi},
    api::SyscallEncodable,
};

pub trait SyscallDecoder<'a, Abi: SyscallAbi, EncodedType: Copy> {
    fn new(abi: &'a Abi, data: EncodedType) -> Self;
    fn decode<Target: SyscallEncodable<Abi, EncodedType>>(
        &mut self,
        item: EncodedType,
    ) -> Result<Target, DecodeError>;

    fn decode_primitive<Item: Copy + TryFrom<Abi::Primitive>>(
        &mut self,
    ) -> Result<Item, DecodeError>;
}

pub enum DecodeError {
    InvalidData,
    InvalidNum,
}
