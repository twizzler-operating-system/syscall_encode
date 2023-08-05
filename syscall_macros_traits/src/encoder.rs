use crate::{
    abi::{Allocation, SyscallAbi},
    api::SyscallEncodable,
};

pub trait SyscallEncoder<'a, Abi: SyscallAbi + ?Sized, EncodedType: Copy> {
    fn new(abi: &'a Abi) -> Self;
    fn encode<Source: SyscallEncodable<Abi, EncodedType>>(
        &mut self,
        item: Source,
        alloc: &Allocation,
    ) -> Result<(), EncodeError>;
    fn encode_primitive<Item: Copy + TryInto<Abi::Primitive>>(
        &mut self,
        item: Item,
        alloc: &Allocation,
    ) -> Result<(), EncodeError>;
    fn finish(self) -> EncodedType;
}

pub trait EncodePrimitive<'a, Abi: SyscallAbi, EncodedType: Copy, PrimitiveElement: Copy> {}

pub enum EncodeError {
    AllocationError,
    PrimitiveError,
}
