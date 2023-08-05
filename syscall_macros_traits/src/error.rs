use crate::{decoder::DecodeError, encoder::EncodeError};

#[derive(Debug, Clone, Copy)]
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
