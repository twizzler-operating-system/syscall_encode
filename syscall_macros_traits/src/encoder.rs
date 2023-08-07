use crate::{
    abi::{Allocation, SyscallAbi},
    api::SyscallEncodable,
};

pub trait SyscallEncoder<'a, Abi: SyscallAbi + ?Sized, EncodedType: Copy> {
    fn new(abi: &'a Abi, decode_data: Option<EncodedType>) -> Self;
    fn encode<Source: SyscallEncodable<'a, Abi, EncodedType, Self>>(
        &mut self,
        item: &Source,
        alloc: &Allocation,
    ) -> Result<(), EncodeError>
    where
        Self: Sized;
    fn decode<Target: SyscallEncodable<'a, Abi, EncodedType, Self>>(
        &mut self,
    ) -> Result<Target, DecodeError>
    where
        Self: Sized;

    fn encode_u8(&mut self, item: u8, alloc: &Allocation) -> Result<(), EncodeError>
    where
        Self: Sized;

    fn decode_u8(&mut self) -> Result<u8, DecodeError>
    where
        Self: Sized;

    fn finish(self) -> EncodedType;
}

pub enum EncodeError {
    AllocationError,
    PrimitiveError,
}

pub enum DecodeError {
    InvalidData,
    InvalidNum,
}

pub trait EncodePrimitive<'a, Abi: SyscallAbi, EncodedType: Copy, Primitive: Copy>:
    SyscallEncoder<'a, Abi, EncodedType>
{
    fn encode_primitive(&mut self, item: Primitive, alloc: &Allocation) -> Result<(), EncodeError>;

    fn decode_primitive(&mut self) -> Result<Primitive, DecodeError>;
}
