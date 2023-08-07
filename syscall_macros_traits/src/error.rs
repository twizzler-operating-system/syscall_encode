use crate::{
    abi::SyscallAbi,
    api::SyscallEncodable,
    encoder::{DecodeError, EncodeError, EncodePrimitive, SyscallEncoder},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
    <Abi as SyscallAbi>::RetEncoder<'a>: EncodePrimitive<'a, Abi, EncodedType, u32>,
{
    fn encode(&self, encoder: &mut Abi::RetEncoder<'a>) -> Result<(), EncodeError> {
        match *self {
            SyscallError::InvalidData => encoder.encode(&0u32),
            SyscallError::InvalidNum => encoder.encode(&1u32),
            SyscallError::AllocationError => encoder.encode(&2u32),
            SyscallError::SyscallError(e) => {
                encoder.encode(&3u32)?;
                encoder.encode(&e)
            }
        }
    }

    fn decode(decoder: &mut Abi::RetEncoder<'a>) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        todo!()
    }
}
