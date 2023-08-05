use crate::abi::{Allocation, SyscallAbi};

use super::SyscallEncodable;

impl<Abi: SyscallAbi, EncodedType: Copy> SyscallEncodable<Abi, EncodedType> for u32
where
    Abi::Primitive: From<u32>,
    Abi::Primitive: TryInto<u32>,
    u32: TryFrom<<Abi as SyscallAbi>::Primitive>,
{
    fn encode<'a, Encoder: crate::encoder::SyscallEncoder<'a, Abi, EncodedType>>(
        &self,
        encoder: &mut Encoder,
        alloc: &Allocation,
    ) -> Result<(), crate::encoder::EncodeError> {
        encoder.encode_primitive(*self, alloc)
    }

    fn decode<'a, Decoder: crate::decoder::SyscallDecoder<'a, Abi, EncodedType>>(
        decoder: &mut Decoder,
    ) -> Result<Self, crate::decoder::DecodeError>
    where
        Self: Sized,
    {
        decoder.decode_primitive()
    }
}
