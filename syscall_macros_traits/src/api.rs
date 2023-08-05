use std::alloc::Layout;

use crate::{
    abi::{Allocation, SyscallAbi},
    decoder::{DecodeError, SyscallDecoder},
    encoder::{EncodeError, SyscallEncoder},
    error::SyscallError,
};

pub mod impls;

pub trait SyscallApi<Abi: SyscallAbi>: SyscallEncodable<Abi, Abi::SyscallArgType> {
    type ReturnType: SyscallEncodable<Abi, Abi::SyscallRetType>;
    const NUM: Abi::SyscallNumType;
    type ErrorType: Copy;

    fn perform_call(&self, abi: &Abi) -> Result<Self::ReturnType, SyscallError<Self::ErrorType>> {
        let layout = Layout::new::<Self>();
        abi.with_alloc(layout, |abi: &Abi, alloc| {
            let mut encoder = abi.create_sender_encoder();
            encoder
                .encode(*self, &alloc)
                .map_err(|e| SyscallError::<Self::ErrorType>::from(e))?;
            let args = encoder.finish();

            let result = abi.syscall_impl(Self::NUM, args);

            let mut decoder = abi.create_sender_decoder(result);
            let result = decoder
                .decode(result)
                .map_err(|e| SyscallError::<Self::ErrorType>::from(e))?;
            Ok(result)
        })
        .map_err(|e| e.into())
    }

    unsafe fn with<
        F: FnOnce(Abi::SyscallNumType, Self) -> Result<Self::ReturnType, Self::ErrorType>,
    >(
        abi: &Abi,
        num: Abi::SyscallNumType,
        args: Abi::SyscallArgType,
        call: F,
    ) -> Result<Self::ReturnType, SyscallError<Self::ErrorType>>
    where
        Self: Sized,
    {
        let (mut decoder, mut encoder) = abi.create_receiver_pair(args);
        let me = Self::decode(&mut decoder)?;
        let res = (call)(num, me);
        res.map_err(|e| SyscallError::SyscallError(e))
    }
}

pub trait SyscallEncodable<Abi: SyscallAbi + ?Sized, EncodedType: Copy>: Copy {
    fn encode<'a, Encoder: SyscallEncoder<'a, Abi, EncodedType>>(
        &self,
        encoder: &mut Encoder,
        alloc: &Allocation,
    ) -> Result<(), EncodeError>;
    fn decode<'a, Decoder: SyscallDecoder<'a, Abi, EncodedType>>(
        decoder: &mut Decoder,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized;
}
