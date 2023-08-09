use crate::{
    abi::{Allocation, SyscallAbi},
    api::SyscallEncodable,
};

/// Defines how an encoder works.
pub trait SyscallEncoder<'a, Abi: SyscallAbi + ?Sized, EncodedType: Copy> {
    /// Make a new encoder for decoding data.
    fn new_decode(abi: &'a Abi, decode_data: EncodedType) -> Self;
    /// Make a new encoder given this allocation.
    fn new_encode(abi: &'a Abi, allocation: Allocation) -> Self;
    /// Called by SyscallEncodable when derived.
    fn size_hint(&mut self, _size: usize) {}
    /// Encode an item.
    fn encode<Source: SyscallEncodable<'a, Abi, EncodedType, Self>>(
        &mut self,
        item: &Source,
    ) -> Result<(), EncodeError>
    where
        Self: Sized;
    /// Decode an item.
    fn decode<Target: SyscallEncodable<'a, Abi, EncodedType, Self>>(
        &mut self,
    ) -> Result<Target, DecodeError>
    where
        Self: Sized;

    /// Encode a u8.
    fn encode_u8(&mut self, item: u8) -> Result<(), EncodeError>
    where
        Self: Sized;

    /// Decode a u8.
    fn decode_u8(&mut self) -> Result<u8, DecodeError>
    where
        Self: Sized;

    /// Finish encoding and return the EncodedType.
    fn finish(self) -> EncodedType;
}

/// Errors that occur during encoding.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub enum EncodeError {
    /// Failed to allocate enough memory for this type.
    AllocationError,
    /// Failed to encode a value.
    PrimitiveError,
}

/// Errors that occur during decoding.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub enum DecodeError {
    /// Data was impossible to decode into the supplied type.
    InvalidData,
    /// The number of the syscall was not recognized, or a discriminant was invalid.
    InvalidNum,
}
