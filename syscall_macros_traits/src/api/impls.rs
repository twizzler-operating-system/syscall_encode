use std::fmt::Display;

use crate::{
    abi::{Allocation, SyscallAbi},
    encoder::{DecodeError, EncodePrimitive, SyscallEncoder},
};

use super::SyscallEncodable;

impl<'a, Abi: SyscallAbi, EncodedType: Copy, Encoder>
    SyscallEncodable<'a, Abi, EncodedType, Encoder> for u32
where
    Encoder: EncodePrimitive<'a, Abi, EncodedType, Self>,
{
    fn encode(
        &self,
        encoder: &mut Encoder,
        alloc: &Allocation,
    ) -> Result<(), crate::encoder::EncodeError> {
        encoder.encode_primitive(*self, alloc)
    }

    fn decode(decoder: &mut Encoder) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        decoder.decode_primitive()
    }
}

impl<'a, T, E, Abi: SyscallAbi, EncodedType: Copy, Encoder>
    SyscallEncodable<'a, Abi, EncodedType, Encoder> for Result<T, E>
where
    T: SyscallEncodable<'a, Abi, EncodedType, Encoder> + Copy,
    E: SyscallEncodable<'a, Abi, EncodedType, Encoder> + Copy,
    Encoder: SyscallEncoder<'a, Abi, EncodedType>,
{
    fn encode(
        &self,
        encoder: &mut Encoder,
        alloc: &Allocation,
    ) -> Result<(), crate::encoder::EncodeError> {
        match self {
            Ok(o) => {
                encoder.encode_u8(0, alloc)?;
                o.encode(encoder, alloc)
            }
            Err(e) => {
                encoder.encode_u8(1, alloc)?;
                e.encode(encoder, alloc)
            }
        }
    }

    fn decode(decoder: &mut Encoder) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let dis = decoder.decode_u8()?;
        Ok(match dis {
            0 => Ok(T::decode(decoder)?),
            1 => Err(E::decode(decoder)?),
            _ => return Err(DecodeError::InvalidData),
        })
    }
}
