use crate::{DecodeError, SyscallArgs, SyscallArguments, SyscallEncoder, SyscallRegister};

pub trait SyscallApi<
    T: SyscallRegister,
    R: SyscallReturn<T>,
    const BITS: usize,
    const NR_REGS: usize,
>: Copy + SyscallArguments<BITS, NR_REGS, RegisterType = T>
{
    const NUM: T;
    type ReturnType: SyscallReturnType;
    type ReturnErrorType: SyscallErrorType;

    fn perform_call(
        &self,
        syscall: impl FnOnce(T, SyscallArgs<T, NR_REGS>) -> R,
    ) -> Result<Self::ReturnType, SyscallError<Self::ReturnErrorType>> {
        let res = SyscallEncoder::encode_with(*self, |args| {
            let raw_return = syscall(Self::NUM, args);
            unsafe { raw_return.decode() }
        });
        res
    }
}

pub trait SyscallReturn<T: SyscallRegister> {
    unsafe fn decode<Target: SyscallReturnType, Error: SyscallErrorType>(
        &self,
    ) -> Result<Target, SyscallError<Error>>;

    unsafe fn encode<Target: SyscallReturnType, Error: SyscallErrorType>(
        input: Result<Target, SyscallError<Error>>,
    ) -> Self
    where
        Self: Sized;
}

pub trait SyscallErrorType: Copy {}
pub trait SyscallReturnType: Copy {}

impl SyscallErrorType for u64 {}
impl SyscallReturnType for u64 {}

pub enum SyscallError<Error: SyscallErrorType> {
    Decode(DecodeError),
    CallError(Error),
}
