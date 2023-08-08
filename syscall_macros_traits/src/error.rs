use crate::{
    abi::SyscallAbi,
    api::SyscallEncodable,
    encoder::{DecodeError, EncodeError, SyscallEncoder},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyscallError<Err: Copy> {
    InvalidData,
    InvalidNum,
    AllocationError,
    SyscallError(Err),
}

impl<Err: Copy> From<EncodeError> for SyscallError<Err> {
    fn from(value: EncodeError) -> Self {
        match value {
            EncodeError::AllocationError => Self::AllocationError,
            EncodeError::PrimitiveError => Self::InvalidData,
        }
    }
}

impl<Err: Copy> From<DecodeError> for SyscallError<Err> {
    fn from(value: DecodeError) -> Self {
        match value {
            DecodeError::InvalidData => Self::InvalidData,
            DecodeError::InvalidNum => Self::InvalidNum,
        }
    }
}

impl<
        'a,
        Err: SyscallEncodable<'a, Abi, EncodedType, Abi::RetEncoder<'a>>,
        Abi: SyscallAbi,
        EncodedType: Copy,
    > SyscallEncodable<'a, Abi, EncodedType, Abi::RetEncoder<'a>> for SyscallError<Err>
where
    <Abi as SyscallAbi>::RetEncoder<'a>: SyscallEncoder<'a, Abi, EncodedType>,
{
    fn encode(&self, encoder: &mut Abi::RetEncoder<'a>) -> Result<(), EncodeError> {
        match *self {
            SyscallError::InvalidData => encoder.encode(&0u8),
            SyscallError::InvalidNum => encoder.encode(&1u8),
            SyscallError::AllocationError => encoder.encode(&2u8),
            SyscallError::SyscallError(e) => {
                encoder.encode(&3u8)?;
                encoder.encode(&e)
            }
        }
    }

    fn decode(decoder: &mut Abi::RetEncoder<'a>) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let dis = decoder.decode_u8()?;
        Ok(match dis {
            0 => SyscallError::InvalidData,
            1 => SyscallError::InvalidNum,
            2 => SyscallError::AllocationError,
            3 => SyscallError::SyscallError(decoder.decode()?),
            _ => SyscallError::InvalidData,
        })
    }
}
