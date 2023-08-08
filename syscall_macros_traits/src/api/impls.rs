use crate::{
    abi::SyscallAbi,
    encoder::{DecodeError, SyscallEncoder},
};

use super::SyscallEncodable;
macro_rules! impl_prim {
    ($ty:ty) => {
        impl<'a, Abi: SyscallAbi, EncodedType: Copy, Encoder>
            SyscallEncodable<'a, Abi, EncodedType, Encoder> for $ty
        where
            Encoder: SyscallEncoder<'a, Abi, EncodedType>,
        {
            fn encode(&self, encoder: &mut Encoder) -> Result<(), crate::encoder::EncodeError> {
                let bytes = self.to_ne_bytes();
                for b in bytes {
                    encoder.encode_u8(b)?
                }
                Ok(())
            }

            fn decode(decoder: &mut Encoder) -> Result<Self, DecodeError>
            where
                Self: Sized,
            {
                let len = <$ty>::default().to_ne_bytes().len();
                let mut bytes = [0u8; 16];
                for i in 0..len {
                    bytes[i] = decoder.decode_u8()?;
                }
                Ok(<$ty>::from_ne_bytes(core::array::from_fn(|i| bytes[i])))
            }
        }
    };
}

impl_prim!(u16);
impl_prim!(u32);
impl_prim!(u64);
impl_prim!(u128);
impl_prim!(i8);
impl_prim!(i16);
impl_prim!(i32);
impl_prim!(i64);
impl_prim!(i128);

impl<'a, Abi: SyscallAbi, EncodedType: Copy, Encoder>
    SyscallEncodable<'a, Abi, EncodedType, Encoder> for u8
where
    Encoder: SyscallEncoder<'a, Abi, EncodedType>,
{
    fn encode(&self, encoder: &mut Encoder) -> Result<(), crate::encoder::EncodeError> {
        encoder.encode_u8(*self)
    }

    fn decode(decoder: &mut Encoder) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        decoder.decode_u8()
    }
}

impl<'a, Abi: SyscallAbi, EncodedType: Copy, Encoder>
    SyscallEncodable<'a, Abi, EncodedType, Encoder> for bool
where
    Encoder: SyscallEncoder<'a, Abi, EncodedType>,
{
    fn encode(&self, encoder: &mut Encoder) -> Result<(), crate::encoder::EncodeError> {
        encoder.encode_u8(*self as u8)
    }

    fn decode(decoder: &mut Encoder) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        match decoder.decode_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::InvalidData),
        }
    }
}

impl<'a, Abi: SyscallAbi, EncodedType: Copy, Encoder>
    SyscallEncodable<'a, Abi, EncodedType, Encoder> for ()
where
    Encoder: SyscallEncoder<'a, Abi, EncodedType>,
{
    fn encode(&self, _encoder: &mut Encoder) -> Result<(), crate::encoder::EncodeError> {
        Ok(())
    }

    fn decode(_decoder: &mut Encoder) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        Ok(())
    }
}
impl<'a, T, E, Abi: SyscallAbi, EncodedType: Copy, Encoder>
    SyscallEncodable<'a, Abi, EncodedType, Encoder> for Result<T, E>
where
    T: SyscallEncodable<'a, Abi, EncodedType, Encoder> + Copy,
    E: SyscallEncodable<'a, Abi, EncodedType, Encoder> + Copy,
    Encoder: SyscallEncoder<'a, Abi, EncodedType>,
{
    fn encode(&self, encoder: &mut Encoder) -> Result<(), crate::encoder::EncodeError> {
        match self {
            Ok(o) => {
                encoder.encode_u8(0)?;
                o.encode(encoder)
            }
            Err(e) => {
                encoder.encode_u8(1)?;
                e.encode(encoder)
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

impl<'a, T, Abi: SyscallAbi, EncodedType: Copy, Encoder>
    SyscallEncodable<'a, Abi, EncodedType, Encoder> for Option<T>
where
    T: SyscallEncodable<'a, Abi, EncodedType, Encoder> + Copy,
    Encoder: SyscallEncoder<'a, Abi, EncodedType>,
{
    fn encode(&self, encoder: &mut Encoder) -> Result<(), crate::encoder::EncodeError> {
        match self {
            Some(o) => {
                encoder.encode_u8(1)?;
                o.encode(encoder)
            }
            None => encoder.encode_u8(0),
        }
    }

    fn decode(decoder: &mut Encoder) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let dis = decoder.decode_u8()?;
        Ok(match dis {
            0 => None,
            1 => Some(T::decode(decoder)?),
            _ => return Err(DecodeError::InvalidData),
        })
    }
}

pub trait EncodeAllPrimitives<'a, Abi: SyscallAbi, EncodedType: Copy, Encoder>
where
    Encoder: SyscallEncoder<'a, Abi, EncodedType>,
    u8: SyscallEncodable<'a, Abi, EncodedType, Encoder>,
    u16: SyscallEncodable<'a, Abi, EncodedType, Encoder>,
    u32: SyscallEncodable<'a, Abi, EncodedType, Encoder>,
    u64: SyscallEncodable<'a, Abi, EncodedType, Encoder>,
    u128: SyscallEncodable<'a, Abi, EncodedType, Encoder>,
    i8: SyscallEncodable<'a, Abi, EncodedType, Encoder>,
    i16: SyscallEncodable<'a, Abi, EncodedType, Encoder>,
    i32: SyscallEncodable<'a, Abi, EncodedType, Encoder>,
    i64: SyscallEncodable<'a, Abi, EncodedType, Encoder>,
    i128: SyscallEncodable<'a, Abi, EncodedType, Encoder>,
{
}
