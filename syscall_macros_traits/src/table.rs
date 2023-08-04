#[macro_export]
macro_rules! syscall_api {
    ($in_num:expr, $args:expr, $bits:expr, $nr_regs:expr, $reg:ty, $ret_type:ty, $(($type:ty, $call:expr)),*) => {
        {
        let res = match $in_num {
            $(
                <$type as ::syscall_macros_traits::api::SyscallApi<$reg, $ret_type, $bits, $nr_regs>>::NUM => {
                    <$type as ::syscall_macros_traits::SyscallArguments<$bits, $nr_regs>>::with($in_num, $args, $call)
                },
            )*
            _ => Err(::syscall_macros_traits::DecodeError::InvalidNum)
        };
        match res {
            Err(e) => Err(::syscall_macros_traits::api::SyscallError::Decode(e)),
            Ok(Err(e)) => Err(::syscall_macros_traits::api::SyscallError::CallError(e)),
            Ok(Ok(ok)) => Ok(ok),
        }
    }
    };
}
