use std::alloc::Layout;

use crate::{
    abi::SyscallAbi,
    encoder::{DecodeError, EncodeError, SyscallEncoder},
    error::SyscallError,
};

pub mod impls;

/// Use this encodable type as a front-facing Syscall API. It will have
/// a defined number, return, and error type. Once implemented, one may
/// call the auto implemented perform_call function on a value of the type
/// implementing this trait.
pub trait SyscallApi<'a, Abi: SyscallAbi + 'a>:
    SyscallEncodable<'a, Abi, Abi::SyscallArgType, Abi::ArgEncoder<'a>>
{
    /// The number of the syscall. Must be unique.
    const NUM: Abi::SyscallNumType;
    /// The type returned by this call on success.
    type ReturnType: SyscallEncodable<'a, Abi, Abi::SyscallRetType, Abi::RetEncoder<'a>>;
    /// The type returned by this call on error.
    type ErrorType: SyscallEncodable<'a, Abi, Abi::SyscallRetType, Abi::RetEncoder<'a>>;

    /// Perform the syscall with the given ABI.
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

    /// Used by the table API. You probably don't want to call this directly.
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

/// Indicates that a type may be encoded using an encoder, and implements the method for encoding.
/// May be derived.
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

/// For syscalls that need high performance, implement a much faster, but more limited and less ergonomic, encoding method
/// that allows per-type optimizations for encoding. The perform_call executes the syscall for a value of the type implementing this trait.
pub trait SyscallFastApi<'a, Abi: SyscallAbi + 'a>:
    Into<Abi::SyscallArgType> + From<Abi::SyscallArgType>
{
    const NUM: Abi::SyscallNumType;
    type ReturnType: From<Abi::SyscallRetType> + Into<Abi::SyscallRetType>;

    fn perform_call(self, abi: &'a Abi) -> Self::ReturnType {
        let args: Abi::SyscallArgType = self.into();
        let ret = unsafe { abi.syscall_impl(Self::NUM, args) };
        ret.into()
    }
}
