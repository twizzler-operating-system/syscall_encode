use std::alloc::Layout;

use crate::{
    abi::SyscallAbi,
    encoder::{DecodeError, EncodeError, SyscallEncoder},
    error::SyscallError,
};

pub mod impls;

pub trait SyscallApi<'a, Abi: SyscallAbi + 'a>:
    SyscallEncodable<'a, Abi, Abi::SyscallArgType, Abi::ArgEncoder<'a>>
{
    type ReturnType: SyscallEncodable<'a, Abi, Abi::SyscallRetType, Abi::RetEncoder<'a>>;
    const NUM: Abi::SyscallNumType;
    type ErrorType: SyscallEncodable<'a, Abi, Abi::SyscallRetType, Abi::RetEncoder<'a>>;

    fn perform_call(
        &self,
        abi: &'a Abi,
    ) -> Result<Self::ReturnType, SyscallError<Self::ErrorType>> {
        let layout = Layout::new::<Self>();
        abi.with_alloc(layout, |alloc| {
            let mut encoder = abi.arg_encoder(alloc);
            encoder
                .encode(self)
                .map_err(|e| SyscallError::<Self::ErrorType>::from(e))?;
            let args = encoder.finish();

            let result = unsafe { abi.syscall_impl(Self::NUM, args) };

            let mut decoder = abi.ret_decoder(result);
            let result: Result<Self::ReturnType, Self::ErrorType> = decoder
                .decode()
                .map_err(|e| SyscallError::<Self::ErrorType>::from(e))?;
            result.map_err(|e| SyscallError::SyscallError(e))
        })
        .map_err(move |e| e.into())
    }

    unsafe fn with<
        F: FnOnce(Abi::SyscallNumType, Self) -> Result<Self::ReturnType, Self::ErrorType>,
    >(
        abi: &'a Abi,
        num: Abi::SyscallNumType,
        args: Abi::SyscallArgType,
        call: F,
    ) -> Result<Self::ReturnType, SyscallError<Self::ErrorType>>
    where
        Self: Sized,
    {
        let mut arg_decoder = abi.arg_decoder(args);
        let me = Self::decode(&mut arg_decoder)?;
        let res = (call)(num, me);
        res.map_err(|e| SyscallError::SyscallError(e))
    }
}

pub trait SyscallEncodable<
    'a,
    Abi: SyscallAbi + ?Sized,
    EncodedType: Copy,
    Encoder: SyscallEncoder<'a, Abi, EncodedType>,
>: Copy
{
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError>;
    fn decode(decoder: &mut Encoder) -> Result<Self, DecodeError>
    where
        Self: Sized;
}
