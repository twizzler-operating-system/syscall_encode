use crate::{
    abi::{Allocation, SyscallAbi},
    api::SyscallEncodable,
};

pub trait SyscallEncoder<'a, Abi: SyscallAbi + ?Sized, EncodedType: Copy> {
    fn new_decode(abi: &'a Abi, decode_data: EncodedType) -> Self;
    fn new_encode(abi: &'a Abi, allocation: Allocation) -> Self;
    fn size_hint(&mut self, _size: usize) {}
    fn encode<Source: SyscallEncodable<'a, Abi, EncodedType, Self>>(
        &mut self,
        item: &Source,
    ) -> Result<(), EncodeError>
    where
        Self: Sized;
    fn decode<Target: SyscallEncodable<'a, Abi, EncodedType, Self>>(
        &mut self,
    ) -> Result<Target, DecodeError>
    where
        Self: Sized;

    fn encode_u8(&mut self, item: u8) -> Result<(), EncodeError>
    where
        Self: Sized;

    fn decode_u8(&mut self) -> Result<u8, DecodeError>
    where
        Self: Sized;

    fn finish(self) -> EncodedType;
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub enum EncodeError {
    AllocationError,
    PrimitiveError,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub enum DecodeError {
    InvalidData,
    InvalidNum,
}

pub trait EncodePrimitive<'a, Abi: SyscallAbi, EncodedType: Copy, Primitive: Copy>:
    SyscallEncoder<'a, Abi, EncodedType>
{
    fn encode_primitive(&mut self, item: Primitive) -> Result<(), EncodeError>;

    fn decode_primitive(&mut self) -> Result<Primitive, DecodeError>;
}
